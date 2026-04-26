"""
analyze_india.py — additional India-specific analysis on top of
analyze.py's output.

Answers:
  1. Which intercepting rules appear in our run that are NOT in the
     CLAUDE.md tier1/2 list (blocklists/tier1.txt) — i.e. trackers
     caught only because we added the new priority tiers
     (cname_cloaking, data_brokers, cookie_syncing, email_tracking,
     server_side_apis, fingerprinting). These are the "wins" from
     the gap-fill pass.

  2. Per-category behavior: govt sites broken vs. ok, banking ditto,
     streaming ditto. The corpus comments group sites by category;
     we re-derive the grouping by looking at the corpus_india.txt
     header structure.

  3. Indian-origin domain detection: trackers whose apex domain is
     .in / .co.in or which match a curated list of known
     Indian-origin ad-tech (Paytm, Sharechat, Hotstar, Inmobi).
     These are candidates for a future `priority_tiers/india_adtech.txt`.

Usage:
  python tools/e2e/analyze_india.py --run results/E2E/india-top100 \
      --query-log cloakdns-queries.jsonl \
      --corpus tools/e2e/corpus_india.txt \
      --tier-dir tools/priority_tiers \
      --out results/E2E_india_top100_extras.md
"""

from __future__ import annotations

import argparse
import collections
import datetime
import json
import pathlib
import re
import sys


# --- Inputs -----------------------------------------------------------------


def load_jsonl(path: pathlib.Path) -> list[dict]:
    out: list[dict] = []
    if not path.is_file():
        return out
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def parse_iso(ts: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))


def load_tier_domains(tier_dir: pathlib.Path) -> dict[str, set[str]]:
    """Return {tier_name: {domain, ...}} by reading every *.txt under
    tier_dir plus blocklists/tier1.txt one level up."""
    out: dict[str, set[str]] = {}
    paths = list(tier_dir.glob("*.txt"))
    repo_root = tier_dir.parent.parent
    extra = repo_root / "blocklists" / "tier1.txt"
    if extra.is_file():
        paths.append(extra)
    for p in paths:
        domains: set[str] = set()
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            tokens = line.split()
            for tok in tokens[1:] if len(tokens) > 1 else []:
                domains.add(tok.lower())
        out[p.name] = domains
    return out


def parse_corpus_categories(corpus: pathlib.Path) -> dict[str, str]:
    """Walk corpus_india.txt and assign each domain to the category
    name from its preceding `# --- <category> (N) ---` header."""
    out: dict[str, str] = {}
    current = "uncategorized"
    header_re = re.compile(r"^#\s*---\s*(.+?)\s*\(\d+\)\s*---")
    for raw in corpus.read_text(encoding="utf-8").splitlines():
        m = header_re.match(raw.strip())
        if m:
            current = m.group(1)
            continue
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out[line] = current
    return out


# --- Window partitioning (mirrors analyze.py) -------------------------------


def attribute(visits: list[dict],
              queries: list[dict]) -> dict[str, list[dict]]:
    windows = sorted(
        ((parse_iso(v["start"]), parse_iso(v["end"]), v["site"]) for v in visits),
        key=lambda x: x[0],
    )
    by_site: dict[str, list[dict]] = {v["site"]: [] for v in visits}
    sorted_q = sorted(queries, key=lambda q: parse_iso(q["ts"]))
    wi = 0
    for q in sorted_q:
        ts = parse_iso(q["ts"])
        while wi < len(windows) and windows[wi][1] < ts:
            wi += 1
        if wi >= len(windows):
            continue
        start, end, site = windows[wi]
        if start <= ts <= end:
            by_site[site].append(q)
    return by_site


# --- Indian-origin heuristics ----------------------------------------------


_INDIAN_ADTECH = {
    "inmobi.com",
    "inmobicdn.net",
    "vserv.com",
    "pubmatic.com",   # IN HQ but global presence
    "komli.com",
    "tyroo.com",
    "affle.com",
    "mediasmart.io",
    "advangelists.com",
    "adsindia.com",
    "paytm.com",
    "paytm-blog.com",
    "phonepe.com",
    "sharechat.com",
    "hotstar.com",
    "hotstarext.com",
    "jio.com",
    "jiocdn.com",
    "jiocinema.com",
}

_INDIAN_TLD = re.compile(r"\.(?:in|co\.in|net\.in|org\.in|gov\.in)$",
                         re.IGNORECASE)


def looks_indian(domain: str) -> bool:
    if not domain:
        return False
    domain = domain.lower()
    if domain in _INDIAN_ADTECH:
        return True
    if _INDIAN_TLD.search(domain):
        return True
    return False


# --- Reporting --------------------------------------------------------------


def render(visits: list[dict], by_site: dict[str, list[dict]],
           tiers: dict[str, set[str]],
           categories: dict[str, str],
           run_id: str) -> str:

    rule_to_tiers: dict[str, list[str]] = collections.defaultdict(list)
    all_tier_domains: set[str] = set()
    for tier_name, domains in tiers.items():
        for d in domains:
            all_tier_domains.add(d)
    for tier_name, domains in tiers.items():
        for d in domains:
            rule_to_tiers[d].append(tier_name)

    rule_counts: collections.Counter = collections.Counter()
    for site, qs in by_site.items():
        for q in qs:
            if q.get("action") in ("block", "uncloak") and q.get("rule"):
                rule_counts[q["rule"]] += 1

    # --- Section 1: which tiers are pulling weight ---
    tier_hits: collections.Counter = collections.Counter()
    only_in_added_tiers: collections.Counter = collections.Counter()
    tier1_domains = tiers.get("tier1.txt", set())
    for rule, n in rule_counts.items():
        rule_l = rule.lower()
        for t in rule_to_tiers.get(rule_l, ["unknown"]):
            tier_hits[t] += n
        if rule_l in all_tier_domains and rule_l not in tier1_domains:
            only_in_added_tiers[rule] += n

    # --- Section 2: category breakdown ---
    cat_status: dict[str, dict[str, int]] = collections.defaultdict(
        lambda: collections.defaultdict(int))
    cat_blocks: dict[str, int] = collections.defaultdict(int)
    for v in visits:
        cat = categories.get(v["site"], "uncategorized")
        status = v.get("status", "unknown")
        cat_status[cat][status] += 1
        cat_blocks[cat] += sum(
            1 for q in by_site.get(v["site"], [])
            if q.get("action") in ("block", "uncloak"))

    # --- Section 3: Indian-origin tracker discovery ---
    indian_blocked: collections.Counter = collections.Counter()
    indian_not_blocked: collections.Counter = collections.Counter()
    for site, qs in by_site.items():
        for q in qs:
            qname = (q.get("qname") or "").lower()
            if not looks_indian(qname):
                continue
            if q.get("action") in ("block", "uncloak"):
                indian_blocked[qname] += 1
            elif q.get("action") in ("allow", "cached"):
                indian_not_blocked[qname] += 1

    out: list[str] = []
    out.append(f"# India top-100 — extras (delta vs. CLAUDE.md tier1/2)\n")
    out.append(f"_Generated {datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')}_\n")
    out.append(f"_Companion to results/E2E_{run_id}.md_\n")

    # 1. Tier weight
    out.append("## Block hits by priority tier\n")
    out.append("Each block can be attributed to one or more tiers (a "
               "domain may live in multiple files). Counts are query "
               "hits, not unique domains.\n")
    out.append("| tier | hits |")
    out.append("|------|------|")
    for tier_name, hits in tier_hits.most_common():
        out.append(f"| `{tier_name}` | {hits} |")
    out.append("")

    # 2. New-tier wins
    if only_in_added_tiers:
        out.append("## Trackers caught only by the new priority tiers\n")
        out.append("These rules are NOT in the original `blocklists/tier1.txt` "
                   "(CLAUDE.md tier 1+2). They were added in the M13 gap-fill "
                   "pass. Each row is a tracker the hand-curated tier files "
                   "caught that a CLAUDE.md-only deployment would have missed.\n")
        out.append("| rule | hits | tier(s) |")
        out.append("|------|------|---------|")
        for rule, n in only_in_added_tiers.most_common(40):
            tiers_for = ", ".join(t for t in rule_to_tiers.get(rule.lower(), [])
                                  if t != "tier1.txt")
            out.append(f"| `{rule}` | {n} | {tiers_for} |")
        out.append("")

    # 3. Category behavior
    out.append("## Per-category outcomes\n")
    out.append("| category | sites | ok | timeout | net_error | http_error | blocks |")
    out.append("|----------|-------|----|---------|-----------|------------|--------|")
    for cat in sorted(cat_status.keys()):
        s = cat_status[cat]
        total = sum(s.values())
        out.append(f"| {cat} | {total} | {s.get('ok', 0)} "
                   f"| {s.get('timeout', 0)} | {s.get('net_error', 0)} "
                   f"| {s.get('http_error', 0)} | {cat_blocks[cat]} |")
    out.append("")

    # 4. Indian-origin tracker findings
    if indian_blocked or indian_not_blocked:
        out.append("## Indian-origin tracker domains observed\n")
        out.append("Heuristic: domain is in our small Indian-adtech list "
                   "(InMobi, PubMatic India, Paytm, Sharechat, Hotstar, "
                   "Jio family, etc.) OR matches a `.in / .co.in / .gov.in` "
                   "TLD.\n")
        if indian_blocked:
            out.append("### Already blocked\n")
            out.append("| domain | hits |")
            out.append("|--------|------|")
            for d, n in indian_blocked.most_common(30):
                out.append(f"| `{d}` | {n} |")
            out.append("")
        if indian_not_blocked:
            out.append("### Forwarded (candidates for "
                       "`priority_tiers/india_adtech.txt`)\n")
            out.append("Apex-only — judgement needed before adding (some are "
                       "first-party content domains, not trackers). Dedup "
                       "by exact qname; subdomains of a forwarded apex are "
                       "rolled up.\n")
            apex_counts: collections.Counter = collections.Counter()
            for d, n in indian_not_blocked.items():
                # Roll up to the registrable apex (last 2 labels for .com,
                # last 3 for .co.in / .gov.in / etc.)
                parts = d.split(".")
                if len(parts) >= 3 and parts[-2] in ("co", "gov", "net", "org"):
                    apex = ".".join(parts[-3:])
                else:
                    apex = ".".join(parts[-2:])
                apex_counts[apex] += n
            out.append("| apex | hits |")
            out.append("|------|------|")
            for apex, n in apex_counts.most_common(40):
                out.append(f"| `{apex}` | {n} |")
            out.append("")

    return "\n".join(out)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True, type=pathlib.Path)
    ap.add_argument("--query-log", type=pathlib.Path,
                    default=pathlib.Path("cloakdns-queries.jsonl"))
    ap.add_argument("--corpus", type=pathlib.Path,
                    default=pathlib.Path("tools/e2e/corpus_india.txt"))
    ap.add_argument("--tier-dir", type=pathlib.Path,
                    default=pathlib.Path("tools/priority_tiers"))
    ap.add_argument("--out", type=pathlib.Path, required=True)
    args = ap.parse_args(argv)

    visits = load_jsonl(args.run / "visits.jsonl")
    queries = load_jsonl(args.query_log)
    if not visits:
        print(f"no visits at {args.run}/visits.jsonl", file=sys.stderr)
        return 2

    by_site = attribute(visits, queries)
    tiers = load_tier_domains(args.tier_dir)
    categories = parse_corpus_categories(args.corpus)
    report = render(visits, by_site, tiers, categories, args.run.name)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(report, encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
