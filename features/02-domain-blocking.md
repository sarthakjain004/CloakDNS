# Domain blocking

Match the queried hostname against a curated list of tracker / ad /
malware domains; if it matches, return a synthesised "no answer"
response (`0.0.0.0` for A queries, `::` for AAAA queries, empty
NOERROR for anything else) without ever asking the upstream resolver.

This is what most people mean when they say "DNS sinkhole" or "Pi-hole
style blocking." It's the single feature that makes CloakDNS visibly
useful to a regular user.

---

## The problem

Imagine you visit `cnn.com`. While the article loads, your browser
silently fires off DNS lookups for **dozens** of third-party domains
the page embeds — ad networks, analytics, tracking pixels, beacons,
social-share widgets. A representative slice of what shows up in our
real captures (`results/E2E/`):

```
googletagmanager.com
googleadservices.com
doubleclick.net
google-analytics.com
scorecardresearch.com
adnxs.com
casalemedia.com
taboola.com
3lift.com
pubmatic.com
... (sometimes 50+ more)
```

Every one of those resolves to a real IP, and your browser then opens
TLS connections to them in the background. Each connection lets the
third party:

- See your IP and approximate location
- Set / read cookies (if not blocked)
- Run JavaScript that fingerprints your browser
- Stitch your visit to `cnn.com` together with your visits to every
  *other* site that loads the same tracker

You didn't ask for any of this; the publisher embedded it for revenue
or analytics.

**Domain blocking at the DNS layer cuts the chain at step zero.** If
`googletagmanager.com` never resolves to a real IP, the browser can't
open a connection to it, can't load its JS, can't set its cookies,
can't fingerprint anything. The whole tracking ecosystem on that
page is silently disarmed before the first byte of tracker JS hits
your machine.

### Concrete user-impact example

You browse 10 news articles a day. Without DNS blocking, your browser
talks to **600–1,000 third-party tracker hosts** in those 10 visits
(this is the average from our `results/E2E_smoke-20.md` and India
top-100 captures). Each tracker host is a separate TLS connection
that:

- Costs you battery and bandwidth (especially on mobile / metered
  data — research-grade estimates put trackers at 10–30% of total
  bytes loaded on news pages).
- Hands a third party your IP, fingerprint, and the URL referer
  showing which article you read.

With CloakDNS pointed at by your OS, the curated tier-1 + cookie-
syncing + fingerprinting tiers (and india-adtech if you're in India)
catch those domains at the resolver. The browser sees `0.0.0.0` /
`::`, gives up immediately, never opens the TLS connection, never
loads the tracker. The page still loads (the publisher's own
content); only the parasites are missing.

### Why this is hard for a *browser* to do alone

Browser ad-blockers (uBlock Origin, AdGuard browser extension, Brave
Shields) work above the DNS layer — they let the browser perform the
DNS lookup, then decide whether to make the TCP connection. Three
things they can't reach but a DNS-layer blocker can:

1. **Apps and devices that aren't browsers.** Smart TVs, IoT
   doorbells, native mobile apps — they don't load extensions.
2. **CNAME-cloaked tracking** (covered in its own feature doc).
3. **Bypass-resistance.** A browser extension can be disabled or
   removed by the user (or by malware); a DNS resolver above the OS
   can't.

---

## See it live

This walkthrough was run end-to-end on **2026-04-28**. Output blocks
below are verbatim from that run.

### 1. Use the same UDP config as feature #1

```toml
# cloakdns-feat-udp.toml
[server]
listen_addr = "127.0.0.1"
listen_port = 5354

[upstream]
protocol     = "udp"
servers      = ["1.1.1.1:53"]
timeout_ms   = 3000

[blocklist]
sources = ["blocklists/tier1.txt"]

[cache]
max_entries = 100

[logging]
path  = "cloakdns-feat-udp.jsonl"
async = false
```

`blocklists/tier1.txt` ships with the project; the daemon's startup
log will print `loaded 22 block rule(s) from 1 source(s)`. The 22
rules are the highest-impact tracker hubs (DoubleClick, Google
Analytics, Facebook tracking, AppNexus, ScoreCardResearch, etc.).
Bigger lists are available via `tools/priority_tiers/*.txt` and the
auto-updater.

### 2. Start the daemon, then run four queries

```
$ ./build-msvc/Release/cloakdns.exe cloakdns-feat-udp.toml
loaded 22 block rule(s) from 1 source(s)
cloakdns listening on 127.0.0.1:5354
upstream: 1.1.1.1:53  (timeout 3000ms)
cname uncloaking: max depth 8
cache: 100 entries, jitter 0-5ms on hit, sweep 30s
padding: 128-byte blocks
logging: cloakdns-feat-udp.jsonl (sync)
```

#### A. blocked domain (in tier1) — A query

```
$ dig @127.0.0.1 -p 5354 doubleclick.net +noall +question +answer +stats

;doubleclick.net.               IN      A
doubleclick.net.        300     IN      A       0.0.0.0
;; Query time: 0 msec
;; SERVER: 127.0.0.1#5354(127.0.0.1) (UDP)
;; WHEN: Tue Apr 28 00:26:20 India Standard Time 2026
;; MSG SIZE  rcvd: 49
```

Three things to read off this:

- The answer is **`0.0.0.0`** — a synthesised non-routable address.
  Any program that follows the standard "use the IP I got from DNS"
  flow tries to connect to `0.0.0.0`, fails immediately, gives up.
- **`Query time: 0 msec`** — CloakDNS never went upstream. The block
  decision happened in microseconds in the local hash/suffix-trie.
  No `1.1.1.1` traffic was generated; the upstream resolver doesn't
  even know you tried to look up DoubleClick.
- TTL of **300** — the synthesised response carries a 5-minute TTL
  so OS-level resolver caches don't keep trying.

#### B. blocked domain — AAAA (IPv6) query

```
$ dig @127.0.0.1 -p 5354 doubleclick.net AAAA +noall +question +answer +stats

;doubleclick.net.               IN      AAAA
doubleclick.net.        300     IN      AAAA    ::
;; Query time: 0 msec
;; SERVER: 127.0.0.1#5354(127.0.0.1) (UDP)
;; WHEN: Tue Apr 28 00:26:20 India Standard Time 2026
;; MSG SIZE  rcvd: 61
```

Same block, IPv6-shaped. `::` is the IPv6 unspecified address — the
v6 equivalent of `0.0.0.0`. CloakDNS picks the answer shape based on
the qtype so a dual-stack OS doesn't fall back to IPv4 in search of
a real answer.

#### C. clean domain forwards normally

```
$ dig @127.0.0.1 -p 5354 example.com +noall +answer +stats

example.com.            7       IN      A       172.66.147.243
example.com.            7       IN      A       104.20.23.154
;; Query time: 6 msec
;; SERVER: 127.0.0.1#5354(127.0.0.1) (UDP)
```

`example.com` isn't in the blocklist; CloakDNS forwarded to
`1.1.1.1`, got the real answer, returned it. 6 ms total round-trip.
This confirms blocking is **opt-in per name** — it doesn't change
the default for unblocked names.

#### D. subdomain blocked via suffix match

```
$ dig @127.0.0.1 -p 5354 ad.googleads.g.doubleclick.net +short
0.0.0.0
```

The blocklist contains `doubleclick.net`, not
`ad.googleads.g.doubleclick.net`. But the matcher walks the qname
backwards through every `.` boundary and finds `doubleclick.net` as a
suffix → blocks. This is how 22 curated rules end up catching
hundreds of distinct subdomain hosts in real traffic (the tier-hit
mining showed 87 distinct hosts matching the 22 tier-1 rules across
the existing E2E corpus).

### 3. Daemon log of the four queries

Captured from the daemon's stdout:

```
block   doubleclick.net  via doubleclick.net  qtype=1
block   doubleclick.net  via doubleclick.net  qtype=28
forward example.com
block   ad.googleads.g.doubleclick.net  via doubleclick.net  qtype=1
```

Each blocked query prints which **rule** triggered the block (the
shortest matching suffix), letting you see at a glance "this got
caught because we have `doubleclick.net` in the list" — even when
the qname was a 4-label subdomain.

### 4. Per-query JSONL records

```json
{"v":2,"ts":"2026-04-27T18:56:20.101Z","qname":"doubleclick.net","qtype":"A","action":"block","rule":"doubleclick.net","cname_chain":[],"upstream":null,"latency_ms":0.124,"client":"127.0.0.1:52152"}
{"v":2,"ts":"2026-04-27T18:56:20.173Z","qname":"doubleclick.net","qtype":"AAAA","action":"block","rule":"doubleclick.net","cname_chain":[],"upstream":null,"latency_ms":0.094,"client":"127.0.0.1:52153"}
{"v":2,"ts":"2026-04-27T18:56:20.228Z","qname":"example.com","qtype":"A","action":"allow","rule":null,"cname_chain":["example.com"],"upstream":"1.1.1.1:53","latency_ms":6.055,"client":"127.0.0.1:52154"}
{"v":2,"ts":"2026-04-27T18:56:20.295Z","qname":"ad.googleads.g.doubleclick.net","qtype":"A","action":"block","rule":"doubleclick.net","cname_chain":[],"upstream":null,"latency_ms":0.242,"client":"127.0.0.1:52156"}
```

Read structure:

- **Blocked queries** have `"action":"block"`, the matching rule
  string, no upstream (because none was contacted), and a tiny
  `latency_ms` (sub-millisecond — pure local hash lookup).
- **The clean forward** has `"action":"allow"`, no rule, the
  upstream that answered, and a larger latency (real network RTT).
- The fourth record's `qname` is the full 4-label subdomain but the
  `rule` field is just `doubleclick.net` — that's the suffix match
  in action, recorded for forensic clarity.

---

## How it works in code

Three pieces.

### 1. The matcher (`src/blocklist.cpp`)

Each rule is added to one of three structures based on its shape:

- **Exact set** — `unordered_set<string> exact_` for plain hostnames.
- **Suffix set** — `unordered_set<string> suffix_` for suffix-matched
  hostnames (the common case for DNS blocking, where a rule like
  `doubleclick.net` should also catch any subdomain).
- **Regex list** — `vector<pair<string, regex>> regex_` for
  pattern-based rules.

Plus equivalents for the *allow*list (`allow_exact_`,
`allow_suffix_`).

The match function tries them in order — exact, suffix, regex — and
returns on the first hit:

```cpp
// src/blocklist.cpp:139
MatchResult Blocklist::match(std::string_view qname) const {
    if (qname.empty()) return {};

    // Allowlist wins over any block rule.
    if (allowed(qname)) return {};

    if (auto it = exact_.find(std::string{qname}); it != exact_.end()) {
        return {true, *it, MatchKind::Exact};
    }

    if (auto it = find_suffix_match(suffix_, qname); it != suffix_.end()) {
        return {true, *it, MatchKind::Suffix};
    }

    for (const auto& [pattern, rx] : regex_) {
        if (std::regex_search(std::string{qname}, rx)) {
            return {true, pattern, MatchKind::Regex};
        }
    }

    return {};
}
```

Two design choices here matter:

1. **Allow always wins.** Even if a name is in three different block
   tiers, a single allowlist entry overrides all of them. Lets a user
   rescue a domain like `doubleclick.net` if some legit service they
   care about happens to share the parent.

2. **Exact before suffix before regex.** Fast paths first. Hash-set
   exact lookup is `O(1)`; suffix walk is bounded by label count
   (typically ≤10 hops); regex is `O(rules × name_len)` and runs only
   when neither hit.

### 2. The suffix walk (`src/blocklist.cpp` ~line 117)

For a rule `doubleclick.net` to match `ad.googleads.g.doubleclick.net`,
the matcher walks the qname's tails:

```cpp
// src/blocklist.cpp:117
template <class Set>
auto find_suffix_match(const Set& set, std::string_view qname) {
    size_t pos = 0;
    while (pos <= qname.size()) {
        if (auto it = set.find(std::string{qname.substr(pos)}); it != set.end())
            return it;
        const auto dot = qname.find('.', pos);
        if (dot == std::string_view::npos) break;
        pos = dot + 1;
    }
    return set.end();
}
```

For `ad.googleads.g.doubleclick.net` it tries (in order):

```
ad.googleads.g.doubleclick.net   ← pos=0
googleads.g.doubleclick.net      ← pos after first '.'
g.doubleclick.net                ← pos after second '.'
doubleclick.net                  ← MATCH; return this iterator
```

The matcher returns the **shortest** matching suffix (the rule itself,
not the queried name) so logs and dashboards can group hits by rule.

### 3. The block-response synthesis (`src/main.cpp` ~line 154)

When `bl.match(qname)` returns a hit, `handle()` builds a synthesised
DNS response — never touching the upstream:

```cpp
// src/main.cpp:154
const auto hit = bl.match(qname);
if (hit.blocked) {
    std::vector<std::byte> response;
    switch (qtype) {
      case kTypeA:
        response = cloak::build_block_a_response(query, msg); break;
      case kTypeAAAA:
        response = cloak::build_block_aaaa_response(query, msg); break;
      default:
        response = cloak::build_block_nodata_response(query, msg); break;
    }
    std::cout << "block   " << qname << "  via " << hit.rule
              << "  qtype=" << qtype << std::endl;
    log_record(cloak::LogAction::Block, qname, qtype, hit.rule);
    co_await sock.async_send_to(
        asio::buffer(response), from, use_awaitable);
    co_return;
}
```

`build_block_a_response` (in `src/dns_writer.cpp`) reuses the client's
question section, sets `qr=1` (response), `rcode=0` (NOERROR), and
appends a single A record with `rdata = 0.0.0.0` and `ttl = 300`.
Symmetrically, `build_block_aaaa_response` produces an AAAA `::`.
Anything else (TXT, SRV, MX, qtype 65 HTTPS, etc.) gets an empty
NOERROR — the "this name exists but has no record of that type"
shape, which is what most clients gracefully degrade to.

### What the dataflow looks like end-to-end

For a blocked A query the path is:

```
client UDP packet arrives  ──→  parse DNS message
                           ──→  is_forwardable_qtype? yes
                           ──→  bl.match("doubleclick.net") → hit
                           ──→  build_block_a_response with 0.0.0.0
                           ──→  async_send_to client
                           ──→  log_record(Block)
                           ──→  co_return
```

Total time on the daemon side: ~0.1 ms (the JSONL `latency_ms` field).
No upstream packet is ever sent.

### What you can verify yourself

- Add your own rule: edit `blocklists/tier1.txt`, add `0.0.0.0
  yoursite.example`, hot-reload with the SIGHUP/SIGBREAK feature, and
  watch `dig yoursite.example` return `0.0.0.0`.
- Watch the JSONL: `tail -f cloakdns-feat-udp.jsonl` while you
  browse — you'll see `"action":"block"` records light up
  whenever a blocked tracker tries to load.
- See what tier1 catches: `python tools/e2e/tier_hit_rates.py` will
  count how many tier-1 rules fire across the existing E2E corpus
  and which hosts they catch.

---

## References

- **Curated tier files:** `blocklists/tier1.txt` and
  `tools/priority_tiers/*.txt`. Each tier file's header comment cites
  the research papers behind its rules.
- **Englehardt & Narayanan, OpenWPM 1M Census** (CCS 2016) — the
  empirical study behind tier 1's choices.
- **Roesner et al., Detecting and Defending Against Third-Party
  Tracking** (NSDI 2012) — the tracker-behaviour taxonomy that
  motivates blocking parents to kill children.
- **Source files:** [`src/blocklist.cpp`](../src/blocklist.cpp),
  [`src/main.cpp`](../src/main.cpp),
  [`src/dns_writer.cpp`](../src/dns_writer.cpp).
- Related features: allowlist passthrough, wildcard / regex matching,
  hot-reload, structured query log, CNAME uncloaking.
