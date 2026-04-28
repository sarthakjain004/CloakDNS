"""
update_blocklists.py — fetch, parse, merge, deduplicate, and normalize
third-party DNS blocklists into a single `merged.txt` file plus a
`manifest.json` recording provenance.

Stdlib-only so this runs on any Python 3.11+ without pip.

Usage:
  python update_blocklists.py --out blocklists/merged.txt
  python update_blocklists.py --local tests/fixtures/blocklists --out /tmp/m.txt
  python update_blocklists.py --sources tools/blocklist_sources.toml
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import pathlib
import re
import sys
import tomllib
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Iterable


# ---- Source definitions ----------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Source:
    name: str
    url: str
    format: str          # "hosts" | "adblock" | "plain"
    optional: bool = False


DEFAULT_SOURCES: tuple[Source, ...] = (
    Source("stevenblack",
           "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
           "hosts"),
    Source("oisd",
           "https://big.oisd.nl/",
           "hosts"),
    Source("easyprivacy",
           "https://easylist.to/easylist/easyprivacy.txt",
           "adblock"),
    Source("easylist",
           "https://easylist.to/easylist/easylist.txt",
           "adblock"),
    Source("peter_lowe",
           "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
           "hosts"),
    Source("nextdns_cname",
           "https://raw.githubusercontent.com/nextdns/cname-cloaking-blocklist/master/domains",
           "plain"),
)


# ---- Parsers ---------------------------------------------------------------


# Hardcoded never-block list — domains that some upstream blocklist
# sources erroneously include but blocking would obviously break user
# workflow. Filtered out at merge time so they never reach merged.txt.
# CloakDNS uses suffix matching, so listing `google.com` here drops
# only the exact apex; `*.google.com` rules from upstream still apply
# (the priority tiers cover the actual tracker subdomains by hand).
#
# Conservative on purpose: only domains where blocking is clearly
# wrong, not anything debatable. Add to this list when you find a new
# false-positive — don't paper over via the runtime allowlist.
NEVER_BLOCK: frozenset[str] = frozenset({
    # Google end-user services
    "google.com", "www.google.com", "accounts.google.com",
    "mail.google.com", "drive.google.com", "docs.google.com",
    "calendar.google.com", "photos.google.com", "play.google.com",
    "translate.google.com", "maps.google.com", "news.google.com",
    "clients2.google.com", "clients4.google.com", "clients5.google.com",
    "googleapis.com", "content-autofill.googleapis.com",
    "oauthaccountmanager.googleapis.com", "ckintersect-pa.googleapis.com",
    "optimizationguide-pa.googleapis.com", "update.googleapis.com",
    "safebrowsing.googleapis.com", "safebrowsing.google.com",
    "gstatic.com", "www.gstatic.com",
    "googleusercontent.com",          # Drive / Photos / Sites content
    "ggpht.com",                      # YouTube avatars / Google CDN
    "gvt1.com", "gvt2.com",           # Google Update Service
    # YouTube — apex blocks break video playback (CDN is googlevideo.com)
    "youtube.com", "www.youtube.com", "m.youtube.com",
    "accounts.youtube.com", "studio.youtube.com",
    "ytimg.com", "i.ytimg.com",
    "googlevideo.com",                # YouTube video CDN — breaks YT
    "youtube-nocookie.com",           # privacy-mode embeds
    # Code / collaboration
    "github.com", "api.github.com", "www.github.com",
    "githubusercontent.com", "raw.githubusercontent.com",
    "gitlab.com", "bitbucket.org", "stackoverflow.com",
    "stackexchange.com",
    # Messaging / chat
    "whatsapp.com", "web.whatsapp.com", "www.whatsapp.com",
    "telegram.org", "web.telegram.org",
    "signal.org",
    "slack.com", "discord.com", "discordapp.com",
    "zoom.us",
    # OS / app distribution + updates
    "microsoft.com", "www.microsoft.com",
    "live.com", "outlook.com", "office.com", "office365.com",
    "teams.microsoft.com", "microsoftonline.com",
    "onedrive.live.com", "sharepoint.com",
    "xbox.com",
    "visualstudio.com", "marketplace.visualstudio.com",
    "dev.azure.com", "azure.com",
    "azureedge.net",                  # Azure Front Door / Microsoft CDN
    "azurewebsites.net",              # Azure App Service apps
    "azurefd.net",                    # Azure Front Door custom domains
    "trafficmanager.net",             # Azure Traffic Manager DNS LB
    "cloudapp.net",                   # Azure VMs / cloud services
    "msn.com", "www.msn.com",         # Edge new-tab default
    "hotmail.com", "windows.net",
    "nuget.org", "www.nuget.org",     # .NET package registry
    "apple.com", "www.apple.com",
    "icloud.com", "www.icloud.com",
    "mzstatic.com",                   # Apple CDN
    "ubuntu.com", "archlinux.org", "kernel.org",
    "code.visualstudio.com", "update.code.visualstudio.com",
    # Cloud / CDN apexes — bare-apex blocks suffix-match half the web
    "cloudflare.com", "www.cloudflare.com",
    "amazon.com", "www.amazon.com", "aws.amazon.com",
    "amazonaws.com", "s3.amazonaws.com",
    "cloudfront.net", "akamaized.net", "akamai.net", "akamaihd.net",
    "fastly.net", "fastlylb.net",
    # Search engines (other than Google)
    "bing.com", "www.bing.com",
    "duckduckgo.com", "www.duckduckgo.com",
    # Social — tracking subdomains stay blocked via specific entries,
    # but bare apexes are user destinations
    "twitter.com", "x.com", "t.co",
    "reddit.com", "www.reddit.com",
    "facebook.com", "www.facebook.com", "fbcdn.net", "fbsbx.com",
    "instagram.com", "www.instagram.com", "cdninstagram.com",
    "linkedin.com", "www.linkedin.com",
    "tiktok.com", "www.tiktok.com",
    "pinterest.com", "tumblr.com",
    "twitch.tv",
    "wikipedia.org", "en.wikipedia.org",
    # Streaming
    "netflix.com", "www.netflix.com",
    "spotify.com", "www.spotify.com",
    # Payments
    "paypal.com", "www.paypal.com",
    "stripe.com", "checkout.stripe.com",
    # Dev workflows
    "npmjs.com", "registry.npmjs.org", "pypi.org", "files.pythonhosted.org",
    "docker.com", "hub.docker.com",
    "adobe.com", "www.adobe.com",
    # Content / publishing
    "medium.com", "substack.com",
    # Backend-as-a-Service / app platforms — every customer is a
    # subdomain of these apexes, so wildcard-blocking the apex breaks
    # countless third-party apps the user relies on.
    "supabase.co", "supabase.com",
    "firebaseio.com", "appspot.com",
    "vercel.app", "netlify.app", "netlify.com",
    "herokuapp.com", "heroku.com", "fly.dev", "render.com",
    "railway.app", "deno.dev", "deno.com",
    "pages.dev", "workers.dev",
    "azurestaticapps.net",
    "web.app", "firebaseapp.com",
    "shopify.com", "wordpress.com",
    # Public CDNs — wildcard-blocking these breaks third-party scripts
    # on a huge fraction of the web (jQuery, Bootstrap, Tailwind, etc).
    "jsdelivr.net", "unpkg.com",
    # Banking / payments — essential user services
    "americanexpress.com", "bankofamerica.com", "citi.com",
    "visa.com", "wellsfargo.com", "revolut.com", "binance.com",
    # Major retail
    "alibaba.com", "aliexpress.com", "ebay.com", "etsy.com",
    "kroger.com", "nike.com", "target.com", "temu.com",
    "walmart.com", "walmart.ca",
    # News
    "bloomberg.com", "nytimes.com", "wsj.com",
    # Travel
    "booking.com", "expedia.com", "hotels.com",
    # Streaming / media
    "deezer.com", "hulu.com", "pandora.com", "soundcloud.com",
    "opera.com",
    # Social / community
    "gofundme.com", "imgur.com", "kickstarter.com",
    "patreon.com", "quora.com", "messenger.com",
    # Storage / productivity
    "airtable.com", "box.com", "canva.com", "dropbox.com",
    "fastmail.com", "figma.com",
    # Asian platforms (consumer end-user)
    "baidu.com", "naver.com", "naver.net", "qq.com",
    "taobao.com", "weibo.com", "weibo.cn",
    # Dev / SaaS / corporate
    "adobe.io", "akamai.com", "behance.net", "cisco.com",
    "codecademy.com", "coursera.org", "dribbble.com",
    "github.dev", "grafana.net", "honeycomb.io",
    "kaggle.com", "newrelic.com", "sumologic.com",
    "udemy.com", "unsplash.com",
    # Apps / logistics
    "dhl.com", "ups.com", "lyft.com", "uber.com", "ubereats.com",
    # Stock / images
    "pexels.com", "shutterstock.com",
    # Mail
    "aol.com", "yahoo.com", "yahoo.net",
})


_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$")


def _valid_domain(s: str) -> bool:
    return bool(_DOMAIN_RE.match(s)) and len(s) <= 253


def _punycode(domain: str) -> str | None:
    """Lowercase + IDNA-encode. Returns None on malformed input."""
    try:
        out = domain.strip().lower().encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return None
    return out if _valid_domain(out) else None


def parse_hosts(text: str) -> Iterable[str]:
    """StevenBlack / OISD / hosts-file format: `0.0.0.0 domain.tld` lines."""
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        for tok in parts[1:]:
            if d := _punycode(tok):
                if d not in ("0.0.0.0", "127.0.0.1", "localhost"):
                    yield d


def parse_adblock(text: str) -> Iterable[str]:
    """EasyList format. We only pick up `||domain^` network-filter rules;
    element-hiding selectors, regex rules, and exceptions are ignored.

    DNS-blocking can only enforce whole-domain rules. Two classes of
    adblock rule must be **dropped**, not coerced into apex matches:

    1. **Path-restricted rules** (`||twitter.com/i/jot$third-party`).
       The original intent is "block /i/jot only"; reducing to apex
       blocks the entire site. This is how `twitter.com`, `reddit.com`,
       and similar consumer sites slipped into prior merged.txt
       outputs.
    2. **Wildcard-prefixed rules** (`||*.google.com^`, `||.x.com^`).
       Adblock semantics require at least one subdomain label; the
       apex itself shouldn't match. Stripping the `*` / `.` produced a
       bare apex rule, and CloakDNS's suffix matcher then matched the
       apex too — turning subdomain-only rules into whole-site blocks.
       This is how `google.com` ended up in merged.txt.

    Domain-only rules (`||doubleclick.net^`) and option-restricted
    rules without paths (`||doubleclick.net^$third-party`) are kept,
    since their intent maps cleanly to DNS-level blocking.
    """
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("!", "[", "#")):
            continue
        if line.startswith("@@"):      # exception — drop
            continue
        if not line.startswith("||"):  # only simple domain rules
            continue
        # Strip leading "||"
        body = line[2:]
        # Find the host-pattern terminator: ^ (host separator), $ (start
        # of options), or / (start of path). If `/` comes first, the
        # rule is path-restricted and must be dropped — DNS can't
        # enforce paths and reducing to apex would block the whole
        # site.
        end_idx = len(body)
        first_delim = None
        for ch in "^$/":
            i = body.find(ch)
            if i >= 0 and i < end_idx:
                end_idx = i
                first_delim = ch
        if first_delim == "/":
            continue
        # If the host ends at `^`, anything after `^` other than `$options`
        # is a path filter (e.g. `||twitter.com^*/log.json` blocks only
        # log.json under any path). Drop these too.
        if first_delim == "^":
            tail = body[end_idx + 1:]
            if tail and not tail.startswith("$"):
                continue
        candidate = body[:end_idx]
        # Reject wildcard-prefix rules; an adblock `*` represents at
        # least one label and the apex itself should not match.
        if "*" in candidate or candidate.startswith("."):
            continue
        candidate = candidate.rstrip(".")
        if not candidate:
            continue
        if d := _punycode(candidate):
            yield d


def parse_plain(text: str) -> Iterable[str]:
    """One domain per line, # comments."""
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if d := _punycode(line):
            yield d


_PARSERS = {
    "hosts":   parse_hosts,
    "adblock": parse_adblock,
    "plain":   parse_plain,
}


# ---- Fetching --------------------------------------------------------------


@dataclasses.dataclass
class Fetch:
    name: str
    url: str
    text: str
    etag: str | None = None
    last_modified: str | None = None
    error: str | None = None
    not_modified: bool = False   # 304 response; reuse prior body


def fetch_remote(src: Source, timeout: float = 20.0,
                 prior_etag: str | None = None,
                 prior_last_modified: str | None = None,
                 conditional: bool = True) -> Fetch:
    """Fetch a source over HTTP. If `prior_etag` / `prior_last_modified`
    are provided AND `conditional` is True, send If-None-Match /
    If-Modified-Since and return a `not_modified` Fetch when the
    upstream answers 304. Callers should reuse the prior body in that
    case (see merge())."""
    headers = {"User-Agent": "CloakDNS/0.1"}
    if conditional and prior_etag:
        headers["If-None-Match"] = prior_etag
    if conditional and prior_last_modified:
        headers["If-Modified-Since"] = prior_last_modified
    req = urllib.request.Request(src.url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return Fetch(
                name=src.name,
                url=src.url,
                text=body,
                etag=resp.headers.get("ETag"),
                last_modified=resp.headers.get("Last-Modified"),
            )
    except urllib.error.HTTPError as e:
        if e.code == 304:
            # Server says nothing changed since the prior fetch.
            return Fetch(
                name=src.name, url=src.url, text="",
                etag=prior_etag, last_modified=prior_last_modified,
                not_modified=True,
            )
        return Fetch(src.name, src.url, text="", error=str(e))
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return Fetch(src.name, src.url, text="", error=str(e))


def fetch_local(src: Source, local_dir: pathlib.Path) -> Fetch:
    path = local_dir / f"{src.name}.txt"
    try:
        text = path.read_text(encoding="utf-8")
        return Fetch(src.name, src.url, text=text)
    except OSError as e:
        return Fetch(src.name, src.url, text="", error=str(e))


# ---- Merge + manifest ------------------------------------------------------


def merge(fetches: list[Fetch], sources: list[Source],
          prior: dict | None = None) -> tuple[list[str], dict]:
    """Merge domain sets across all fetches. Returns (sorted domains, manifest).

    If `prior` is provided, sources whose Fetch is `not_modified` reuse the
    prior manifest entry's domain count and provenance metadata so 304
    responses don't blank out the merged output."""
    domains: set[str] = set()
    by_source: list[dict] = []
    errors: list[str] = []
    prior_by_name = {s["name"]: s for s in (prior or {}).get("sources", [])}

    for src, f in zip(sources, fetches):
        if f.error:
            errors.append(f"{src.name}: {f.error}")
            by_source.append({
                "name": src.name, "url": src.url, "format": src.format,
                "error": f.error, "domains": 0,
            })
            continue

        if f.not_modified and not f.text:
            # 304 with no body cache available — we cannot contribute
            # domains; record metadata so the manifest stays honest.
            cached = prior_by_name.get(src.name, {})
            by_source.append({
                "name": src.name,
                "url": src.url,
                "format": src.format,
                "bytes": cached.get("bytes", 0),
                "sha256": cached.get("sha256"),
                "last_modified": f.last_modified,
                "etag": f.etag,
                "not_modified": True,
                "new_domains": 0,
            })
            continue

        parser = _PARSERS[src.format]
        count_before = len(domains)
        for d in parser(f.text):
            if d in NEVER_BLOCK:
                continue
            domains.add(d)
        added = len(domains) - count_before
        by_source.append({
            "name": src.name,
            "url": src.url,
            "format": src.format,
            "bytes": len(f.text),
            "sha256": hashlib.sha256(f.text.encode("utf-8")).hexdigest(),
            "last_modified": f.last_modified,
            "etag": f.etag,
            "not_modified": f.not_modified,    # True when served from body cache
            "new_domains": added,
        })

    manifest = {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "domain_count": len(domains),
        "sources": by_source,
        "errors": errors,
    }
    return sorted(domains), manifest


def write_merged(domains: list[str], out_path: pathlib.Path,
                 manifest: dict) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        f.write(f"# CloakDNS merged blocklist — {manifest['generated_at']}\n")
        f.write(f"# {len(domains)} unique domains from {len(manifest['sources'])} sources\n")
        for name in (s["name"] for s in manifest["sources"]):
            f.write(f"# source: {name}\n")
        f.write("\n")
        for d in domains:
            f.write(f"0.0.0.0 {d}\n")


def write_manifest(manifest: dict, path: pathlib.Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


# ---- Sources file ----------------------------------------------------------


def load_sources(path: pathlib.Path) -> list[Source]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    out: list[Source] = []
    for entry in data.get("source", []):
        out.append(Source(
            name=entry["name"],
            url=entry["url"],
            format=entry["format"],
            optional=bool(entry.get("optional", False)),
        ))
    if not out:
        raise ValueError(f"no sources defined in {path}")
    return out


# ---- CLI -------------------------------------------------------------------


def load_prior_manifest(path: pathlib.Path) -> dict:
    """Read a manifest from a previous run. Returns {} if missing or
    unreadable so the caller can fall back to a full fetch."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def index_prior(manifest: dict) -> dict[str, dict]:
    """Index prior manifest sources by name for O(1) lookup. Used both
    for conditional-fetch headers (etag/last_modified) and for reusing
    cached metadata when a source returns 304."""
    return {s["name"]: s for s in manifest.get("sources", []) if s.get("name")}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--sources", type=pathlib.Path,
                    help="TOML file listing sources; defaults to built-in list")
    ap.add_argument("--local", type=pathlib.Path,
                    help="Directory with pre-saved <name>.txt files; skips HTTP")
    ap.add_argument("--out", type=pathlib.Path,
                    default=pathlib.Path("blocklists/merged.txt"),
                    help="Output merged blocklist path")
    ap.add_argument("--manifest", type=pathlib.Path,
                    default=None,
                    help="Output manifest path (default: <out>.manifest.json)")
    ap.add_argument("--no-conditional", action="store_true",
                    help="Disable If-Modified-Since / If-None-Match")
    args = ap.parse_args(argv)

    sources = list(load_sources(args.sources)) if args.sources else list(DEFAULT_SOURCES)
    manifest_path = args.manifest or args.out.with_suffix(args.out.suffix + ".manifest.json")
    prior = {} if args.no_conditional else load_prior_manifest(manifest_path)
    prior_by_name = index_prior(prior)

    # Per-source body cache so a 304 response can be honoured without
    # silently dropping that source from the merged output (security
    # review M13/#6). Lives next to the manifest.
    body_cache_dir = manifest_path.parent / ".body-cache"
    body_cache_dir.mkdir(parents=True, exist_ok=True)

    fetches: list[Fetch] = []
    for src in sources:
        if args.local:
            fetches.append(fetch_local(src, args.local))
            continue
        cached = prior_by_name.get(src.name, {})
        body_path = body_cache_dir / f"{src.name}.txt"
        # Only send conditional headers if we have the body to fall back
        # on. Without a body cache, a 304 would erode the merged output.
        send_conditional = (not args.no_conditional) and body_path.is_file()
        f = fetch_remote(
            src,
            prior_etag=cached.get("etag"),
            prior_last_modified=cached.get("last_modified"),
            conditional=send_conditional,
        )
        if f.not_modified and body_path.is_file():
            try:
                f.text = body_path.read_text(encoding="utf-8")
                # We have a body — fall through to the normal parse
                # path. The "not_modified" flag stays so the manifest
                # can advertise the cache hit, but merge() also
                # re-parses to keep the domain set populated.
            except OSError as e:
                f.error = f"reading body cache: {e}"
                f.text = ""
                f.not_modified = False
        elif not f.error and f.text:
            try:
                body_path.write_text(f.text, encoding="utf-8")
            except OSError:
                pass   # cache miss is non-fatal
        fetches.append(f)

    skipped = sum(1 for f in fetches if f.not_modified)

    domains, manifest = merge(fetches, sources, prior=prior)
    write_merged(domains, args.out, manifest)
    write_manifest(manifest, manifest_path)

    print(f"wrote {len(domains)} domains to {args.out}")
    if skipped:
        print(f"  ({skipped} source(s) returned 304 Not Modified)")
    print(f"manifest: {manifest_path}")
    if manifest["errors"]:
        print(f"warnings: {len(manifest['errors'])} source error(s)", file=sys.stderr)
        for e in manifest["errors"]:
            print(f"  - {e}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
