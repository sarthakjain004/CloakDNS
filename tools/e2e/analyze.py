"""
analyze.py — read cloakdns query log + visits log from a run directory,
attribute queries to sites by time window, and emit a markdown report.

Usage:
  python tools/e2e/analyze.py --run results/E2E/<run_id> \
      [--query-log <path>] [--out results/E2E_<run_id>.md]
"""

from __future__ import annotations

import argparse
import collections
import datetime
import json
import pathlib
import statistics
import sys


# --- I/O --------------------------------------------------------------------


def load_jsonl(path: pathlib.Path) -> list[dict]:
    out: list[dict] = []
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
    # Both producers emit timezone-aware ISO 8601.
    return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))


# --- Window partitioning ----------------------------------------------------


def attribute(visits: list[dict], queries: list[dict]) -> dict[str, list[dict]]:
    """Return {site: [query_records]} by matching query timestamps to
    visit windows. Queries outside any window go into key "_outside_"."""
    windows = sorted(
        ((parse_iso(v["start"]), parse_iso(v["end"]), v["site"]) for v in visits),
        key=lambda x: x[0],
    )
    by_site: dict[str, list[dict]] = {v["site"]: [] for v in visits}
    by_site["_outside_"] = []

    sorted_queries = sorted(queries, key=lambda q: parse_iso(q["ts"]))
    wi = 0
    for q in sorted_queries:
        ts = parse_iso(q["ts"])
        while wi < len(windows) and windows[wi][1] < ts:
            wi += 1
        if wi >= len(windows):
            by_site["_outside_"].append(q)
            continue
        start, end, site = windows[wi]
        if start <= ts <= end:
            by_site[site].append(q)
        else:
            by_site["_outside_"].append(q)
    return by_site


# --- Per-site metrics -------------------------------------------------------


TRACKER_ACTIONS = {"block", "uncloak"}


def site_metrics(visit: dict, qs: list[dict]) -> dict:
    blocks = [q for q in qs if q.get("action") == "block"]
    uncloaks = [q for q in qs if q.get("action") == "uncloak"]
    cached = [q for q in qs if q.get("action") == "cached"]
    allows = [q for q in qs if q.get("action") == "allow"]
    servfails = [q for q in qs if q.get("action") == "servfail"]

    tracker_q = blocks + uncloaks
    unique_tracker_qnames = {q.get("qname") for q in tracker_q}

    rule_counts: collections.Counter = collections.Counter()
    for q in tracker_q:
        if q.get("rule"):
            rule_counts[q["rule"]] += 1

    forward_latencies = [
        q["latency_ms"] for q in (allows + cached)
        if isinstance(q.get("latency_ms"), (int, float))
    ]
    forward_latencies.sort()

    def pct(p: float) -> float | None:
        if not forward_latencies:
            return None
        idx = min(len(forward_latencies) - 1,
                  int(p * len(forward_latencies)))
        return forward_latencies[idx]

    cname_uncloak_hits = []
    for q in uncloaks:
        chain = q.get("cname_chain") or []
        cname_uncloak_hits.append({
            "qname": q.get("qname"),
            "chain": chain,
            "rule":  q.get("rule"),
        })

    return {
        "site":                 visit["site"],
        "status":               visit.get("status"),
        "main_frame_loaded":    visit.get("main_frame_loaded"),
        "http_status":          visit.get("http_status"),
        "host_count":           visit.get("host_count", 0),
        "queried":              visit.get("queried", 0),
        "tracker_queries":      len(tracker_q),
        "blocks":               len(blocks),
        "uncloaks":             len(uncloaks),
        "cached":               len(cached),
        "allows":               len(allows),
        "servfails":            len(servfails),
        "unique_trackers":      len(unique_tracker_qnames),
        "top_rules":            rule_counts.most_common(5),
        "p50_latency_ms":       pct(0.50),
        "p95_latency_ms":       pct(0.95),
        "cname_uncloak_hits":   cname_uncloak_hits,
        "console_errors":       visit.get("console_errors", []),
        "failed_subresources":  visit.get("failed_subresources", []),
    }


def is_broken(metrics: dict) -> bool:
    if metrics["status"] == "timeout":          return True
    if metrics["status"] == "net_error":        return True
    if metrics["status"] == "harness_error":    return True
    if not metrics["main_frame_loaded"]:        return True
    if metrics["http_status"] >= 400:           return True
    if any("ERR_NAME_NOT_RESOLVED" in e or
           "ERR_BLOCKED_BY_CLIENT" in e
           for e in metrics["console_errors"]): return True
    return False


def fp_candidates(metrics: dict, blocked_qnames: list[str]) -> list[dict]:
    """For broken sites, propose allowlist candidates from blocks/uncloaks
    inside the visit. Score: domain in console errors, etc. (heuristic)."""
    suggestions = []
    error_text = " ".join(metrics["console_errors"]).lower()
    for qname in blocked_qnames:
        score = 0
        if qname.lower() in error_text:
            score += 3
        if qname.endswith("." + metrics["site"]) or qname == metrics["site"]:
            score += 2
        suggestions.append({"qname": qname, "score": score})
    suggestions.sort(key=lambda x: (-x["score"], x["qname"]))
    return suggestions[:3]


# --- Report -----------------------------------------------------------------


def fmt(v) -> str:
    if v is None: return "—"
    if isinstance(v, float): return f"{v:.2f}"
    return str(v)


def md_safe(s: str | None) -> str:
    """Make a string safe to drop into a markdown table cell. RFC 1035
    qnames are LDH only, but a hostile authoritative server can return
    arbitrary octets in CNAME RDATA — strip backticks and pipes that
    would break our table rendering."""
    if s is None:
        return ""
    return s.replace("`", "").replace("|", "│")


def render(run_id: str, run_dir: pathlib.Path,
           visits: list[dict], by_site: dict[str, list[dict]]) -> str:
    metrics = []
    for v in visits:
        qs = by_site.get(v["site"], [])
        metrics.append(site_metrics(v, qs))

    total_q = sum(len(by_site[s["site"]]) for s in visits)
    total_blocks = sum(m["blocks"] for m in metrics)
    total_uncloaks = sum(m["uncloaks"] for m in metrics)
    total_unique_trackers = sum(m["unique_trackers"] for m in metrics)
    sites_with_uncloak = sum(1 for m in metrics if m["uncloaks"] > 0)
    broken = [m for m in metrics if is_broken(m)]

    all_latencies: list[float] = []
    for s in visits:
        for q in by_site.get(s["site"], []):
            if q.get("action") in ("allow", "cached") and \
                isinstance(q.get("latency_ms"), (int, float)):
                all_latencies.append(q["latency_ms"])
    all_latencies.sort()

    def pct(p: float) -> str:
        if not all_latencies:
            return "—"
        return f"{all_latencies[min(len(all_latencies)-1, int(p*len(all_latencies)))]:.2f}"

    global_rules: collections.Counter = collections.Counter()
    for m in metrics:
        for rule, n in m["top_rules"]:
            global_rules[rule] += n

    out = []
    out.append(f"# CloakDNS E2E run — {run_id}\n")
    out.append(f"_Generated {datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')}_\n")

    out.append("## Headline\n")
    out.append(f"- **Sites crawled**: {len(visits)}")
    out.append(f"- **Sites broken under cloakdns**: {len(broken)}"
               + (f" — {', '.join(m['site'] for m in broken)}" if broken else ""))
    out.append(f"- **Total DNS queries logged**: {total_q}")
    out.append(f"- **Tracker queries (block + uncloak)**: "
               f"{total_blocks + total_uncloaks} "
               f"(blocks {total_blocks}, uncloaks {total_uncloaks})")
    out.append(f"- **Unique tracker domains intercepted**: {total_unique_trackers}")
    out.append(f"- **Sites with ≥1 CNAME uncloak hit**: {sites_with_uncloak}")
    out.append(f"- **Latency (forward + cached path)**: p50 {pct(0.5)} ms, "
               f"p95 {pct(0.95)} ms, p99 {pct(0.99)} ms (n={len(all_latencies)})")
    out.append("")

    out.append("## Per-site results\n")
    out.append("| site | status | hosts | block | uncloak | cached | allow | servfail | p50 ms | p95 ms |")
    out.append("|------|--------|-------|-------|---------|--------|-------|----------|--------|--------|")
    for m in metrics:
        out.append(
            f"| {m['site']} | {m['status']} | {m['host_count']} "
            f"| {m['blocks']} | {m['uncloaks']} | {m['cached']} "
            f"| {m['allows']} | {m['servfails']} "
            f"| {fmt(m['p50_latency_ms'])} | {fmt(m['p95_latency_ms'])} |")
    out.append("")

    if global_rules:
        out.append("## Top intercepting blocklist rules\n")
        out.append("| rule | hits |")
        out.append("|------|------|")
        for rule, n in global_rules.most_common(30):
            out.append(f"| `{md_safe(rule)}` | {n} |")
        out.append("")

    uncloak_hits_global = []
    for m in metrics:
        for h in m["cname_uncloak_hits"]:
            uncloak_hits_global.append((m["site"], h))
    if uncloak_hits_global:
        out.append("## CNAME uncloak findings\n")
        out.append("| site | qname | rule | chain |")
        out.append("|------|-------|------|-------|")
        for site, h in uncloak_hits_global[:50]:
            chain_str = " → ".join(md_safe(c) for c in h["chain"])
            out.append(f"| {md_safe(site)} | `{md_safe(h['qname'])}` "
                       f"| `{md_safe(h['rule'])}` | {chain_str} |")
        out.append("")

    if broken:
        out.append("## Broken sites — allowlist candidates\n")
        for m in broken:
            site_qs = by_site.get(m["site"], [])
            blocked_qnames = sorted({
                q.get("qname")
                for q in site_qs
                if q.get("action") in TRACKER_ACTIONS
            })
            cands = fp_candidates(m, blocked_qnames)
            out.append(f"### {m['site']}\n")
            out.append(f"- status: `{m['status']}`, "
                       f"http={m['http_status']}, "
                       f"main_frame_loaded={m['main_frame_loaded']}")
            if m["console_errors"]:
                out.append(f"- top console errors:")
                for e in m["console_errors"][:5]:
                    out.append(f"  - `{e}`")
            if cands:
                out.append(f"- top allowlist candidates "
                           f"(paste into `[allowlist] sources` file):")
                for c in cands:
                    out.append(f"  - `0.0.0.0 {c['qname']}` (score={c['score']})")
            else:
                out.append("- no blocked queries observed inside this visit window.")
            out.append("")

    n_outside = len(by_site.get("_outside_", []))
    if n_outside:
        out.append(f"_{n_outside} cloakdns log line(s) fell outside any "
                   f"visit window (background traffic / boot)._\n")

    return "\n".join(out)


# --- CLI --------------------------------------------------------------------


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True, type=pathlib.Path,
                    help="results/E2E/<run_id>")
    ap.add_argument("--query-log", type=pathlib.Path,
                    help="cloakdns query log JSONL (default: cloakdns-queries.jsonl in CWD)")
    ap.add_argument("--out", type=pathlib.Path)
    args = ap.parse_args(argv)

    run_id = args.run.name
    visits = load_jsonl(args.run / "visits.jsonl")
    if not visits:
        print(f"no visits found in {args.run}/visits.jsonl", file=sys.stderr)
        return 2

    qlog = args.query_log or pathlib.Path("cloakdns-queries.jsonl")
    queries = load_jsonl(qlog) if qlog.exists() else []
    if not queries:
        print(f"warning: query log {qlog} is empty or missing", file=sys.stderr)

    by_site = attribute(visits, queries)
    report = render(run_id, args.run, visits, by_site)

    out = args.out or pathlib.Path(f"results/E2E_{run_id}.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report, encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
