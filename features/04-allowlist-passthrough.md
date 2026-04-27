# Allowlist passthrough

If a domain is in the blocklist (any tier) AND in the allowlist, the
allowlist wins. The query is forwarded to the upstream resolver and
the real answer is returned — exactly as if the blocklist had no
matching rule.

This is the "no, I actually need this domain" override for users
whose legitimate apps share infrastructure with trackers.

---

## The problem

Blocklists are imperfect. A list curated for high recall (catch as
much tracking as possible) inevitably catches some domain that you,
specifically, depend on. A few real examples:

- **You work at Google.** Your corporate single-sign-on flows go
  through `accounts.google.com`, but `googleadservices.com` is in
  every privacy-tier blocklist. If your work tooling pulls anything
  through Google Ad Manager, the blocklist breaks it.
- **You're a developer using Google Analytics on your own site.**
  The `google-analytics.com` script is in tier 1; you can't view your
  own dashboard while CloakDNS is on.
- **A site you trust embeds a tracker you don't.** You want
  `cnn.com` to load, including the news content fronted by Akamai's
  `edgekey.net`. But `edgekey.net` is also used by other tracker
  CDNs you'd block. CNAME uncloaking will drop the whole page.
- **You explicitly opted into a tracker.** Some products (Plausible,
  Fathom) are tracker-shaped from a DNS perspective but you've chosen
  to support them on your own site.

Without an allowlist override, the only way to fix any of these is
to **edit the blocklist** itself — which is brittle (your edit is
overwritten on the next federated update) and global (you can't say
"allow this on my work laptop but block it on the family TV").

The allowlist gives you a per-installation override that:

- **Always wins** — whatever rule a tier file claims, allow trumps it.
- **Survives blocklist updates** — your allowlist is a separate file
  the auto-updater never touches.
- **Suffix-matches like the blocklist** — one entry catches the
  parent domain plus all subdomains.

### Concrete user-impact example

Default config blocks `doubleclick.net` (it's in `tier1.txt`). You
work in adtech and need to fetch tag-manager files from there.

- Without allowlist: every dig / curl / browser load of `doubleclick.net`
  returns `0.0.0.0`. Your work workflow is dead.
- With `0.0.0.0 doubleclick.net` in your allowlist: the same dig
  returns the real Google IP. The blocklist still catches every
  *other* tracker — `google-analytics.com`, `facebook.net`,
  `scorecardresearch.com`, etc. — only `doubleclick.net` got
  rescued.

You didn't have to remove the rule from `tier1.txt`. The next
federated blocklist update can refresh tier 1 freely; your override
stays.

---

## See it live

Run end-to-end on **2026-04-28**.

### Config

```toml
# cloakdns-feat-allow.toml
[server]
listen_addr = "127.0.0.1"
listen_port = 5354

[upstream]
protocol     = "udp"
servers      = ["1.1.1.1:53"]
timeout_ms   = 3000

[blocklist]
sources = ["blocklists/tier1.txt"]

[allowlist]
sources = ["allowlist-feat-demo.txt"]

[cache]
max_entries = 100

[logging]
path  = "cloakdns-feat-allow.jsonl"
async = false
```

`allowlist-feat-demo.txt` (one line, hosts-file format):

```
0.0.0.0 doubleclick.net
```

The `/etc/hosts` shape — `<IP> <hostname>` — is required. The first
whitespace-delimited token is treated as the IP and skipped; the
second token is the rule. (See the gotcha in
`learnings/demo-doh-dot-ech.md` if you accidentally put a bare
hostname on the line.)

### Start the daemon

```
$ ./build-msvc/Release/cloakdns.exe cloakdns-feat-allow.toml
loaded 22 block rule(s) from 1 source(s), 1 allow rule(s) from 1 source(s)
cloakdns listening on 127.0.0.1:5354
upstream: 1.1.1.1:53  (timeout 3000ms)
cname uncloaking: max depth 8
cache: 100 entries, jitter 0-5ms on hit, sweep 30s
padding: 128-byte blocks
logging: cloakdns-feat-allow.jsonl (sync)
```

The new line is `loaded 22 block rule(s) from 1 source(s), 1 allow
rule(s) from 1 source(s)` — confirmation the allowlist file was read.

### Three queries

#### A. `doubleclick.net` — in tier1 AND allowlist

```
$ dig @127.0.0.1 -p 5354 doubleclick.net +noall +answer +stats

doubleclick.net.        300     IN      A       142.250.67.46
;; Query time: 36 msec
;; SERVER: 127.0.0.1#5354(127.0.0.1) (UDP)
```

The allowlist won. CloakDNS forwarded to `1.1.1.1`, got the real
Google IP `142.250.67.46`, returned it. The 36 ms latency confirms
the upstream was actually contacted (vs the 0 ms of a synthesised
block).

#### B. `google-analytics.com` — in tier1 only (control case)

```
$ dig @127.0.0.1 -p 5354 google-analytics.com +noall +answer +stats

google-analytics.com.   300     IN      A       0.0.0.0
;; Query time: 0 msec
;; SERVER: 127.0.0.1#5354(127.0.0.1) (UDP)
```

Other tier1 rules still fire normally. The allowlist only spares the
specific names you put in it — everything else gets the same block
treatment as before. The 0 ms confirms no upstream contact for the
blocked case.

#### C. `ad.googleads.g.doubleclick.net` — subdomain of allowed parent

```
$ dig @127.0.0.1 -p 5354 ad.googleads.g.doubleclick.net +noall +answer +stats

;; Query time: 43 msec
;; SERVER: 127.0.0.1#5354(127.0.0.1) (UDP)
;; MSG SIZE  rcvd: 48
```

The dig answer section is empty — that's because the upstream
returned NOERROR with no A record for this specific subdomain (it's
an internal Google name that doesn't have a public A record). What
matters for *this* feature is what CloakDNS did:

- It did NOT block. The upstream got asked, the upstream's "no
  record" answer was relayed.
- The 43 ms latency confirms the upstream was contacted — i.e. the
  allowlist suffix-matched and let the query through.
- Without the allowlist entry on the parent, this name would have
  been blocked at qname-match time (suffix `doubleclick.net`) and
  returned `0.0.0.0` immediately.

So allowlist suffix-matching mirrors blocklist suffix-matching: one
parent-domain entry rescues all subdomains.

### Daemon log

```
forward doubleclick.net
block   google-analytics.com  via google-analytics.com  qtype=1
forward ad.googleads.g.doubleclick.net
```

`forward` for the two allowed names; `block` for the control case.

### JSONL records

```json
{"v":2,"ts":"2026-04-27T19:05:40.607Z","qname":"doubleclick.net","qtype":"A","action":"allow","rule":null,"cname_chain":["doubleclick.net"],"upstream":"1.1.1.1:53","latency_ms":36.164,"client":"127.0.0.1:57000"}
{"v":2,"ts":"2026-04-27T19:05:40.726Z","qname":"google-analytics.com","qtype":"A","action":"block","rule":"google-analytics.com","cname_chain":[],"upstream":null,"latency_ms":0.109,"client":"127.0.0.1:57002"}
{"v":2,"ts":"2026-04-27T19:05:40.832Z","qname":"ad.googleads.g.doubleclick.net","qtype":"A","action":"allow","rule":null,"cname_chain":["ad.googleads.g.doubleclick.net"],"upstream":"1.1.1.1:53","latency_ms":42.833,"client":"127.0.0.1:57003"}
```

Read structure:

- Allowlisted-and-otherwise-blocked queries get `"action":"allow"`,
  `"rule":null`, and a real `upstream`. The fact that the rule field
  is null means *the allowlist override is silent* — the log doesn't
  shout "rescued by allowlist", it just looks like a normal forward.
  (If you want explicit allow-trail in the log, that's a roadmap
  item, not yet shipped.)
- The blocked control case still has `"action":"block"` with the
  matching rule.

---

## How it works in code

Two pieces.

### 1. The match function — allow always tested first

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

The very first non-trivial line is the allowlist check. If `allowed`
returns true, `match` returns `{}` — an empty `MatchResult` with
`blocked = false`. Every downstream caller (qname-level block,
CNAME-uncloaker hop check) treats that as "not in any blocklist" and
forwards normally.

### 2. The allowlist itself uses the same suffix walker

```cpp
// src/blocklist.cpp:132
bool Blocklist::allowed(std::string_view qname) const {
    if (qname.empty()) return false;
    if (allow_exact_.find(std::string{qname}) != allow_exact_.end())
        return true;
    return find_suffix_match(allow_suffix_, qname) != allow_suffix_.end();
}
```

Same logic as the blocklist's match: exact set first, suffix walk
second. The `find_suffix_match` template is shared between block and
allow — there's literally one implementation of "walk every
label-aligned suffix" used by both.

The structures themselves:

```cpp
// include/cloakdns/blocklist.hpp (interface)
std::unordered_set<std::string> exact_;
std::unordered_set<std::string> suffix_;
std::vector<std::pair<std::string, std::regex>> regex_;

std::unordered_set<std::string> allow_exact_;
std::unordered_set<std::string> allow_suffix_;
```

Mirrored sets. The blocklist file loader populates `suffix_`; the
allowlist file loader populates `allow_suffix_`. (No regex on the
allowlist side — there's been no use case for it yet.)

### 3. CNAME uncloaking respects the allowlist too

When `CnameUncloaker::uncloak` walks a CNAME chain (see
`03-cname-uncloaking.md`) and calls `blocklist_.match(hop)` for
each hop, that match also goes through the same allowlist-first
gate. So an allowlisted parent rescues both:

- direct queries for that parent / its subdomains, AND
- queries that pass through the parent in a CNAME chain.

This matters for the "I want this CDN's content" case — adding
`edgekey.net` to your allowlist lets every Akamai-fronted site
through even if some other rule (or another tier) would have caught
the edgekey hop.

### What the daemon prints at startup

```
loaded 22 block rule(s) from 1 source(s), 1 allow rule(s) from 1 source(s)
```

The two counts are independent. If your TOML has no `[allowlist]`
section the second clause just doesn't print.

### What you can verify yourself

- Toggle: comment out the allowlist rule, restart, query the same
  name — should now be blocked.
- Edit your allowlist file while the daemon is running, then send the
  hot-reload signal (see `08-hot-reload.md`); the new override takes
  effect without restart.
- Mix tiers: stack `tools/priority_tiers/cookie_syncing.txt` plus an
  allowlist that rescues one specific syncing hub you actually use
  — the rest of cookie-syncing tier still blocks normally.

---

## References

- **Source files:** [`src/blocklist.cpp`](../src/blocklist.cpp),
  [`include/cloakdns/blocklist.hpp`](../include/cloakdns/blocklist.hpp).
- **Config schema:** [`include/cloakdns/config.hpp`](../include/cloakdns/config.hpp).
- Related features: domain blocking, CNAME uncloaking, hot-reload,
  structured query log.
