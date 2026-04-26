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
    element-hiding selectors, regex rules, and exceptions are ignored."""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("!", "[", "#")):
            continue
        if line.startswith("@@"):      # exception — drop
            continue
        if not line.startswith("||"):  # only simple domain rules
            continue
        # Strip leading "||" and trailing options "^$third-party,..."
        body = line[2:]
        m = re.match(r"^([a-z0-9.\-_*]+)", body, re.IGNORECASE)
        if not m:
            continue
        candidate = m.group(1).rstrip(".").replace("*", "").lstrip(".")
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
