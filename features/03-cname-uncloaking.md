# CNAME uncloaking

When a name resolves through a CNAME chain (one or more aliases
before the final A/AAAA record), CloakDNS walks every hop in the
chain and re-checks each hop against the blocklist. If **any** hop
matches a rule, the whole query is blocked — even if the name the
client originally asked for looks first-party.

This is the single feature that makes CloakDNS more powerful than
classic Pi-hole-style blockers, and it closes a tracking technique
that browser ad-blockers on Chrome can no longer touch.

---

## The problem

A CNAME record in DNS is an alias: "this name is just another name
for that name." The client follows the chain until it reaches a real
A or AAAA address.

Trackers exploit this. Suppose a publisher wants to load a
third-party tracker like `ad-tracker.criteo.net` on every page, but
they know browser blocklists will catch that hostname. So they ask
their DNS provider to set up:

```
trkr.publisher-site.com   →  CNAME →  customer-1234.tracker.example
                                            ↓
                                            CNAME → ad-tracker.criteo.net → A
```

Now the publisher's site loads `https://trkr.publisher-site.com/...`
which:

- Looks first-party to the browser (same parent domain → same-origin
  rules → cookies flow).
- Looks first-party to old-school blocklists that match on the
  hostname literal — `trkr.publisher-site.com` isn't on any list.
- But the CNAME chain ultimately points to a known tracker. The
  tracker is just hidden behind one alias.

This is **CNAME cloaking** and it's actively used by Criteo, Adobe,
Eulerian, AT Internet, and dozens of smaller adtech vendors. Dao et
al. (IEEE TNSM 2021) catalogued thousands of cloaked tracking
deployments in the wild; Vekaria et al. SoK 2025 lists it as one of
the open evasion techniques the browser ecosystem hasn't fixed.

### What the browsers do (or don't)

- **Chrome** — has no defence. Chrome's built-in DNS lookup never
  surfaces the CNAME chain to the JS / extension layer, and
  Manifest V3 removed the API uBlock Origin used to fetch it
  manually. As of 2026 there is **no in-browser CNAME defence
  shipping in Chrome.**
- **Firefox + uBlock Origin** — does CNAME uncloaking via
  `browser.dns.resolve`. Works only in Firefox.
- **Safari ITP** — partial: applies a 7-day cookie cap to anything
  whose CNAME chain points to a known tracker, but doesn't block
  the load.

So for the ~65% of the browser market that uses Chrome, CNAME-cloaked
trackers run unimpeded *unless something at the DNS layer catches
them*. CloakDNS is exactly that something.

### Concrete user-impact example

You read an article on `cnn.com`. Among the third-party domains it
loads, one is `trkr.cnn.com` — a subdomain of CNN itself. (Hypothetical
example; the principle is real.)

- Without CNAME uncloaking: the browser asks "what IP is
  `trkr.cnn.com`?", the OS forwards to your resolver, which forwards
  upstream, which returns a chain ending at a Criteo tracker IP. The
  browser opens TLS to that IP. From the browser's perspective the
  connection is to `trkr.cnn.com` — same-origin with the publisher.
  Cookies flow. Fingerprinting runs.
- With CNAME uncloaking: CloakDNS receives the same query, forwards
  upstream, gets the same chain back, then walks the chain hop by
  hop. It sees `customer-1234.tracker.example` (or whatever) is a
  known tracker. CloakDNS returns `0.0.0.0` to the browser. The TLS
  connection never opens. The tracker never loads.

The user doesn't see anything change visually — the article still
loads; only the parasite is missing.

---

## See it live

This walkthrough was run end-to-end on **2026-04-28**. We use
`www.washingtonpost.com` because it has a real, observable CNAME
chain through Akamai's edge-key infrastructure — a clean example
even though it's not actually used for tracking. (For demo purposes
the chain shape is what matters; the principle is identical for any
real cloaked tracker.)

The real chain it returns from `1.1.1.1`:

```
www.washingtonpost.com  →  CNAME  →  50992.edgekey.net
                                            ↓
                                     CNAME  →  e9631.j.akamaiedge.net
                                                    ↓
                                                A     104.114.86.163
```

We'll do two runs:

1. With **no rule** matching the chain → CloakDNS forwards normally
   but logs the chain and flags it as `suspicious` (Safari-ITP-style
   soft signal because the chain crossed registrable-domain
   boundaries).
2. With `edgekey.net` added to the blocklist → CloakDNS walks the
   chain, hits the rule on hop 2, returns `0.0.0.0`. This is the
   uncloak block.

### Config

```toml
# cloakdns-feat-cname.toml
[server]
listen_addr = "127.0.0.1"
listen_port = 5354

[upstream]
protocol     = "udp"
servers      = ["1.1.1.1:53"]
timeout_ms   = 3000

[blocklist]
sources = ["blocklist-cname-demo.txt"]

[cache]
max_entries = 100

[logging]
path  = "cloakdns-feat-cname.jsonl"
async = false
```

### Run 1 — no rule for the chain

`blocklist-cname-demo.txt`:

```
0.0.0.0 doubleclick.net
```

(deliberately *not* matching anything in the chain, so the chain is
followed all the way to the A record.)

```
$ ./build-msvc/Release/cloakdns.exe cloakdns-feat-cname.toml &
$ dig @127.0.0.1 -p 5354 www.washingtonpost.com +noall +answer +stats

www.washingtonpost.com.    21115  IN  CNAME  50992.edgekey.net.
50992.edgekey.net.         20979  IN  CNAME  e9631.j.akamaiedge.net.
e9631.j.akamaiedge.net.    20     IN  A      104.114.86.163
;; Query time: 36 msec
;; SERVER: 127.0.0.1#5354(127.0.0.1) (UDP)
```

Daemon log:

```
suspect www.washingtonpost.com  -> edgekey.net (chain: www.washingtonpost.com 50992.edgekey.net e9631.j.akamaiedge.net)
```

JSONL record:

```json
{
  "v": 2,
  "ts": "2026-04-27T19:01:55.330Z",
  "qname": "www.washingtonpost.com",
  "qtype": "A",
  "action": "suspicious",
  "rule": "etldp1-cross:edgekey.net",
  "cname_chain": [
    "www.washingtonpost.com",
    "50992.edgekey.net",
    "e9631.j.akamaiedge.net"
  ],
  "upstream": "1.1.1.1:53",
  "latency_ms": 35.827,
  "client": "127.0.0.1:63847"
}
```

Read structure:

- The full chain — three hops — is recorded in `cname_chain`.
- `action: "suspicious"` — the chain crossed eTLD+1 boundaries
  (washingtonpost.com → edgekey.net → akamaiedge.net) and CloakDNS
  flagged it. This is a *soft* signal modelled on Safari ITP: the
  query still got the real answer (`104.114.86.163`), but the
  cross-domain hop is logged so a human can review whether to add
  a rule. See `learnings/safari-cname-defense-and-our-adaptation.md`
  for the rationale.

### Run 2 — `edgekey.net` blocked

Update `blocklist-cname-demo.txt`:

```
0.0.0.0 doubleclick.net
0.0.0.0 edgekey.net
```

Restart the daemon and re-run the same query:

```
$ dig @127.0.0.1 -p 5354 www.washingtonpost.com +noall +answer +stats

www.washingtonpost.com.    300  IN  A  0.0.0.0
;; Query time: 44 msec
;; SERVER: 127.0.0.1#5354(127.0.0.1) (UDP)
```

```
$ dig @127.0.0.1 -p 5354 www.washingtonpost.com AAAA +noall +answer +stats

www.washingtonpost.com.    300  IN  AAAA  ::
;; Query time: 36 msec
;; SERVER: 127.0.0.1#5354(127.0.0.1) (UDP)
```

Daemon log (both A and AAAA queries):

```
uncloak www.washingtonpost.com  via edgekey.net (chain: www.washingtonpost.com 50992.edgekey.net)
uncloak www.washingtonpost.com  via edgekey.net (chain: www.washingtonpost.com 50992.edgekey.net)
```

JSONL records:

```json
{"v":2,"ts":"2026-04-27T19:02:20.428Z","qname":"www.washingtonpost.com","qtype":"A","action":"uncloak","rule":"edgekey.net","cname_chain":["www.washingtonpost.com","50992.edgekey.net"],"upstream":"1.1.1.1:53","latency_ms":44.830,"client":"127.0.0.1:61467"}
{"v":2,"ts":"2026-04-27T19:02:20.541Z","qname":"www.washingtonpost.com","qtype":"AAAA","action":"uncloak","rule":"edgekey.net","cname_chain":["www.washingtonpost.com","50992.edgekey.net"],"upstream":"1.1.1.1:53","latency_ms":35.916,"client":"127.0.0.1:61469"}
```

Read structure:

- `action: "uncloak"` (not `"block"`) — distinct log action so
  dashboards can count "trackers caught only because we walked the
  chain" separately from "trackers caught at the qname level".
- `rule: "edgekey.net"` — the matching suffix; this is also what
  the rule file says.
- `cname_chain` stops at the matching hop. The walker exits the
  moment it finds a rule hit; it never bothers continuing to
  `akamaiedge.net` once `edgekey.net` (the eTLD+1 of
  `50992.edgekey.net`) caught it.
- The synthesised answer is `0.0.0.0` for A and `::` for AAAA —
  same shape as a normal block.

### Why the latency is unchanged

`latency_ms: 44.8` for the blocked query is roughly the same as the
unblocked query (`35.8`). That's because uncloaking still **forwards
the upstream lookup once** (it has to, to get the chain in the first
place). The block decision happens after the upstream replies; the
saved cost is the *connection* the browser would otherwise have made
to the tracker — which is much bigger than one DNS round trip.

---

## How it works in code

Three pieces wire this together.

### 1. The decision to uncloak (`src/main.cpp`)

After the qname-level blocklist check passes (i.e. the queried name
itself isn't in any tier), `handle()` calls into the uncloaker only
for **address qtypes** (A and AAAA — the qtypes that follow CNAME
chains):

```cpp
// src/main.cpp ~line 208
if (is_address_qtype(qtype)) {
    auto result = co_await uncloaker.uncloak(qname, upstream_resp);
    switch (result.status) {
    case cloak::UncloakStatus::Blocked:
        response = qtype == kTypeAAAA
            ? cloak::build_block_aaaa_response(query, msg)
            : cloak::build_block_a_response(query, msg);
        std::cout << "uncloak " << qname << "  via " << result.hit.rule;
        log_chain(std::cout, result.chain);
        // ... write log + send response ...
```

For non-address qtypes (TXT, SRV, etc.), CloakDNS forwards the
upstream answer as-is — those qtypes don't follow CNAME chains in
the same way and the qname-level blocklist already covers tracker
queries on them.

### 2. The chain walk (`src/uncloaker.cpp`)

`CnameUncloaker::uncloak` (line 68) walks the upstream's response
hop by hop, re-checking each new hop against the blocklist:

```cpp
// src/uncloaker.cpp ~line 84 onwards
while (true) {
    DnsMessage msg;
    try { msg = parse(current); }
    catch (const ParseError&) {
        result.status = UncloakStatus::Aborted;
        result.abort_reason = "parse error in upstream response";
        co_return result;
    }

    WalkOutput walk;
    try { walk = walk_answers(msg, current, result.chain.back()); }
    catch (const ParseError&) {
        result.status = UncloakStatus::Aborted;
        result.abort_reason = "malformed CNAME target";
        co_return result;
    }

    for (auto& hop : walk.new_hops) {
        if (!seen.insert(hop).second) {
            result.status = UncloakStatus::Aborted;
            result.abort_reason = "CNAME loop";
            co_return result;
        }
        if (static_cast<int>(result.chain.size()) >= cfg_.max_depth) {
            result.status = UncloakStatus::Aborted;
            result.abort_reason = "depth limit reached";
            co_return result;
        }
        result.chain.push_back(hop);

        // Soft eTLD+1 cross signal — recorded but doesn't change status.
        if (!result.crossed_etldp1 && !original_etldp1.empty()) {
            std::string hop_etldp1 = etld_plus_one(hop);
            if (!hop_etldp1.empty() && hop_etldp1 != original_etldp1) {
                result.crossed_etldp1 = true;
                result.crossed_to = std::move(hop_etldp1);
            }
        }

        auto m = blocklist_.match(hop);
        if (m.blocked) {
            result.status = UncloakStatus::Blocked;
            result.hit = std::move(m);
            co_return result;
        }
    }
    // ... continue with more re-queries if chain isn't terminated yet ...
}
```

Three safety checks before any rule lookup:

- **Loop detection**. Some misconfigured authoritative servers will
  return a CNAME chain that revisits a name. Without `seen.insert`
  we'd burn forever.
- **Depth limit**. `cfg_.max_depth` defaults to 8 (RFC 1034 §3.6.2
  recommends a small bound; the daemon prints `cname uncloaking:
  max depth 8` on startup). Beyond that the walker aborts —
  pathological chains are an attack vector.
- **eTLD+1 cross signal**. Whenever a hop crosses to a different
  registrable domain (e.g. `washingtonpost.com → edgekey.net`),
  set `crossed_etldp1 = true` and remember the first crossing
  hop. This doesn't *block* by itself; it just gets recorded so
  unfamiliar cross-domain chains get logged as `suspicious`.

The walker re-queries upstream when the chain isn't terminated yet
in the response we have (some servers return only the next hop; we
have to ask again for that hop's name to continue the walk). Each
re-query goes through the same `forward_with_source` path used by
non-uncloaking queries.

### 3. The blocklist re-check is exactly the same matcher

The `blocklist_.match(hop)` call inside the walk is the **same
match function** documented in `02-domain-blocking.md`. The rule
that catches `50992.edgekey.net` via the suffix `edgekey.net` is the
same one that would catch `edgekey.net` if it were queried directly.

This is intentional. There's no separate "CNAME blocklist" — there's
one set of rules, and they apply at every step of the resolution
process. A user adds `edgekey.net` once and it catches:

- direct queries for `edgekey.net`
- direct queries for `50992.edgekey.net` (suffix match)
- CNAME-chained queries that pass through anything ending in
  `edgekey.net`

### What you can verify yourself

- Pick a CDN-fronted site and dig it through CloakDNS — most major
  sites have at least one CNAME hop. The `cname_chain` field in the
  log will show the chain.
- Add the CDN's apex to your blocklist and watch any site fronted by
  that CDN suddenly return `0.0.0.0` (this is also how you'd
  *over-block* — be careful).
- Look at `tools/priority_tiers/cname_cloaking.txt` for the curated
  list of known tracker-cloaking CNAME targets (sourced from Dao et
  al. + NextDNS's published list).

---

## References

- **Dao et al., CNAME Cloaking** (IEEE TNSM 2021) — characterisation
  of CNAME cloaking deployments.
- **Vekaria et al., SoK: Web Tracking** (2025) — open problems
  including CNAME cloaking.
- **WebKit blog: CNAME Cloaking and Bounce-Tracking Defense** —
  Safari ITP's approach.
- **`learnings/safari-cname-defense-and-our-adaptation.md`** — why
  CloakDNS chose the ITP-style soft signal for cross-domain hops.
- **NextDNS CNAME-cloaking blocklist** —
  <https://github.com/nextdns/cname-cloaking-blocklist>; one of the
  upstream sources for our `tools/priority_tiers/cname_cloaking.txt`.
- **Source files:** [`src/uncloaker.cpp`](../src/uncloaker.cpp),
  [`src/main.cpp`](../src/main.cpp).
- Related features: domain blocking, structured query log, hot-reload.
