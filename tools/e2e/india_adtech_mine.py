"""
India-adtech candidate miner.

Walks results/E2E/india-top100/visits.jsonl and surfaces hostnames that
appear on multiple Indian sites and are NOT already covered by any
existing CloakDNS tier (tier1, priority_tiers, allowlist). The output
is a ranked candidate list for human review; nothing is auto-blocked.

Heuristics tuned for Indian-adtech detection:
  * cross-site presence — appears on >= MIN_SITES distinct sites
  * eTLD+1 popularity — common parent domains hint at vendor identity
  * domain-shape filters — drop obvious CDN / first-party patterns

Usage (from project root):
    python tools/e2e/india_adtech_mine.py
"""
import collections, json, pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
VISITS = ROOT / "results" / "E2E" / "india-top100" / "visits.jsonl"

# Show only candidates that appeared on at least this many distinct
# Indian sites — enough to suggest cross-site adtech presence rather
# than a one-off subresource.
MIN_SITES = 3

# Already-blocked domains across every tier we ship.
def parse_tier_file(path):
    rules = set()
    for raw in path.read_text(errors="ignore").splitlines():
        if (h := raw.find("#")) >= 0: raw = raw[:h]
        toks = raw.split()
        if not toks: continue
        first = toks[0]
        if re.match(r"^[0-9.:]+$", first):
            for t in toks[1:]: rules.add(t.lower())
        else:
            for t in toks: rules.add(t.lower())
    return rules

existing = set()
for p in [ROOT / "blocklists" / "tier1.txt"] + sorted(
        (ROOT / "tools" / "priority_tiers").glob("*.txt")):
    existing |= parse_tier_file(p)

def already_blocked(host: str) -> bool:
    h = host.lower().rstrip(".")
    while h:
        if h in existing: return True
        if "." not in h: return False
        h = h.split(".", 1)[1]
    return False

# Accept-list domain-shape filters. CDN / hosting / first-party patterns
# don't belong in an adtech tier — drop them at mining time so the
# manual review queue is shorter.
SKIP_SUFFIXES = (
    "akamaihd.net", "akamaized.net", "akamai.net", "edgekey.net",
    "edgesuite.net", "cloudfront.net", "amazonaws.com", "azureedge.net",
    "azure.com", "windows.net", "googleapis.com", "googleusercontent.com",
    "gstatic.com", "ggpht.com", "google.com", "google.co.in",
    "youtube.com", "youtu.be", "ytimg.com", "fbcdn.net",
    "cloudflare.com", "cloudflare.net", "cloudflareinsights.com",
    "fastly.net", "jsdelivr.net", "unpkg.com", "bootstrapcdn.com",
    "cdnjs.cloudflare.com", "jquery.com", "wp.com", "wordpress.com",
    "github.io", "githubusercontent.com",
    "okta.com", "auth0.com", "stripe.com", "paypal.com",
)

def shape_skip(host: str) -> bool:
    h = host.lower()
    for s in SKIP_SUFFIXES:
        if h == s or h.endswith("." + s): return True
    return False

# Walk the corpus.
host_sites: dict[str, set[str]] = collections.defaultdict(set)
for line in VISITS.read_text(errors="ignore").splitlines():
    line = line.strip()
    if not line: continue
    try: rec = json.loads(line)
    except: continue
    site = rec.get("site")
    if not site: continue
    site_etld = site.lower()
    for h in rec.get("hosts", []):
        h = (h or "").lower()
        if not h or "." not in h: continue
        # Skip the site's own first-party — anything that ends with the site's eTLD+1.
        if h == site_etld or h.endswith("." + site_etld): continue
        if already_blocked(h): continue
        if shape_skip(h): continue
        host_sites[h].add(site_etld)

# eTLD+1 collapsing — group candidates by their parent so the human
# can see "this whole vendor showed up on N sites" not "12 subdomains
# of one vendor each on a few sites."
def etld_plus_one(host: str) -> str:
    parts = host.split(".")
    # Coarse heuristic: take last 2 labels. Works fine for *.com, *.in,
    # *.io etc. India .co.in / .net.in get a 3-label retain pass.
    if len(parts) >= 3 and parts[-2] in ("co", "net", "ac", "gov", "org") and parts[-1] == "in":
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

vendor_sites: dict[str, set[str]] = collections.defaultdict(set)
vendor_hosts: dict[str, set[str]] = collections.defaultdict(set)
for host, sites in host_sites.items():
    v = etld_plus_one(host)
    vendor_sites[v] |= sites
    vendor_hosts[v].add(host)

# Rank by site-count.
ranked = sorted(vendor_sites.items(), key=lambda kv: (-len(kv[1]), kv[0]))

print(f"India top-100 corpus: {len(host_sites)} candidate hostnames "
      f"(after dropping already-blocked + obvious CDN/first-party shapes)")
print(f"Showing vendors that appear on >= {MIN_SITES} distinct sites:\n")

print(f"{'sites':>5s}  {'hosts':>5s}  {'vendor':32s}  example hosts (up to 3)")
print("-" * 100)
for vendor, sites in ranked:
    if len(sites) < MIN_SITES: continue
    sample_hosts = sorted(vendor_hosts[vendor])[:3]
    print(f"{len(sites):>5d}  {len(vendor_hosts[vendor]):>5d}  {vendor:32s}  "
          f"{', '.join(sample_hosts)}")

print(f"\nTotal vendors above threshold: "
      f"{sum(1 for _,s in ranked if len(s) >= MIN_SITES)}")
