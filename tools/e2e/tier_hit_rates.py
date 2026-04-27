"""
Tier hit-rate miner — for every priority blocklist tier, counts how many
of its rules actually showed up as hostnames in the existing E2E
captures, and how many observed hostnames each tier caught.

This converts each tier from "list with research justification" to
"list with measured catch rate against real browsing", which is the
gap noted in `docs/09-verification.md`.

Usage (from project root):
    python tools/e2e/tier_hit_rates.py

Reads:
    blocklists/tier1.txt
    tools/priority_tiers/*.txt
    results/E2E/*/visits.jsonl

Prints a per-tier summary and a per-dataset summary to stdout.
"""
import json, pathlib, re

ROOT = pathlib.Path(__file__).resolve().parents[2]

def parse_tier_file(path: pathlib.Path) -> set[str]:
    """Return the set of suffix rules from a hosts-format or bare-domain file."""
    rules = set()
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if (hash_at := raw.find("#")) >= 0:
            raw = raw[:hash_at]
        toks = raw.split()
        if not toks: continue
        # /etc/hosts format: first token is IP — skip.
        first = toks[0]
        if re.match(r"^[0-9.:]+$", first):
            for t in toks[1:]:
                rules.add(t.lower().rstrip("."))
        else:
            for t in toks:
                rules.add(t.lower().rstrip("."))
    return rules

def host_matches_rule(host: str, rule: str) -> bool:
    """Suffix match (rule is a domain suffix like CloakDNS does)."""
    h = host.lower().rstrip(".")
    r = rule.lower().rstrip(".")
    return h == r or h.endswith("." + r)

def load_observed_hosts(jsonl: pathlib.Path) -> set[str]:
    hosts = set()
    for line in jsonl.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip(): continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        for h in rec.get("hosts", []):
            hosts.add(h.lower())
    return hosts

# ----- Load every tier file -----
tier_files = [ROOT / "blocklists" / "tier1.txt"] + sorted(
    (ROOT / "tools" / "priority_tiers").glob("*.txt"))
tiers = {p.name: parse_tier_file(p) for p in tier_files}
total_rules = {n: len(rs) for n, rs in tiers.items()}

# ----- Load every E2E visits.jsonl -----
datasets: dict[str, set[str]] = {}
for vfile in (ROOT / "results" / "E2E").glob("*/visits.jsonl"):
    datasets[vfile.parent.name] = load_observed_hosts(vfile)

# ----- For each (tier, dataset), count rule-hits and host-hits -----
print(f"{'tier':30s} {'rules':>6s}  {'dataset':16s} {'hosts':>6s} "
      f"{'rules_matched':>14s} {'hosts_matched':>14s} {'rule_hit_%':>10s}")
print("-" * 100)

for tname in sorted(tiers):
    tier = tiers[tname]
    for dname in sorted(datasets):
        observed = datasets[dname]
        rules_matched = set()
        hosts_matched = set()
        for rule in tier:
            for host in observed:
                if host_matches_rule(host, rule):
                    rules_matched.add(rule)
                    hosts_matched.add(host)
        rate = (len(rules_matched) / len(tier) * 100) if tier else 0
        print(f"{tname:30s} {len(tier):>6d}  {dname:16s} {len(observed):>6d} "
              f"{len(rules_matched):>14d} {len(hosts_matched):>14d} {rate:>9.1f}%")

print()
# Aggregate: union of all observed hosts.
union = set().union(*datasets.values())
print(f"=== aggregate: union of all {len(datasets)} datasets, {len(union)} unique hosts observed ===")
print(f"{'tier':30s} {'rules':>6s} {'rules_caught':>14s} {'hosts_caught':>14s} {'rule_hit_%':>10s}")
print("-" * 90)
for tname in sorted(tiers):
    tier = tiers[tname]
    rules_matched = set()
    hosts_matched = set()
    for rule in tier:
        for host in union:
            if host_matches_rule(host, rule):
                rules_matched.add(rule)
                hosts_matched.add(host)
    rate = (len(rules_matched) / len(tier) * 100) if tier else 0
    print(f"{tname:30s} {len(tier):>6d} {len(rules_matched):>14d} {len(hosts_matched):>14d} {rate:>9.1f}%")

# Also: which sites in the corpus had the highest catch counts?
print()
print("=== top 10 sites by total tier-domain queries (any tier) ===")
all_rules = set().union(*tiers.values())
site_counts: dict[str, int] = {}
for vfile in (ROOT / "results" / "E2E").glob("*/visits.jsonl"):
    for line in vfile.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip(): continue
        try: rec = json.loads(line)
        except: continue
        n = sum(1 for h in rec.get("hosts", [])
                if any(host_matches_rule(h, r) for r in all_rules))
        if n > 0:
            site_counts[rec["site"]] = max(site_counts.get(rec["site"], 0), n)
for site, n in sorted(site_counts.items(), key=lambda x: -x[1])[:10]:
    print(f"  {n:3d}  {site}")
