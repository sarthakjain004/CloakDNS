# TTL-aware cache with timing jitter

CloakDNS keeps a local cache of upstream answers, keyed by qname +
qtype + class. Cache hits are served from memory in microseconds, the
TTL on the cached record is rewritten down as time passes, and an
optional small random delay (0 to N milliseconds) is added to each hit
so an attacker can't fingerprint your browsing from cache-hit timing.

LRU eviction keeps the cache bounded; a background sweeper periodically
clears out expired entries; both negative responses (NXDOMAIN) and
positive ones are cached per RFC 2308.

---

## The problem

There are three problems mixed together here.

### 1. Repeating the same upstream lookup is wasteful.

Open `cnn.com`. The page loads ~80 third-party hosts. Each host needs
a DNS lookup. If you stay on `cnn.com` for 5 minutes and click around
to other articles, the SAME hosts get looked up over and over —
every navigation triggers a fresh round of subresource loads. Without
a cache, every one of those round-trips upstream costs ~30–50 ms and
generates upstream traffic the resolver could see.

A local cache means: ask upstream once for `googletagmanager.com`,
keep the answer for the TTL the upstream said is valid (300 seconds is
typical), serve every subsequent request from RAM in microseconds.

### 2. The TTL the cache returns has to be honest.

DNS clients use the TTL to decide how long to trust the answer. If
CloakDNS caches a 300-second answer at t=0, and a client asks for it
at t=200, the client should see TTL=100 (the time remaining), not
TTL=300 (which would let it cache forever). Clients that re-cache at
TTL=300 wedge stale records.

So a real DNS cache has to **rewrite the TTL fields in every cached
response** to reflect time elapsed. CloakDNS does this on every cache
hit.

### 3. Cache-hit timing is a fingerprinting signal.

This is the privacy angle and the reason for the jitter knob. There's
a JS API called the **Performance Timing API** (`performance.getEntriesByType('resource')`)
that exposes `domainLookupStart` / `domainLookupEnd` to scripts on the
page. The difference between those two is how long the DNS lookup
took. The FP-Radar paper (PETS 2022) showed that:

- A **cached** lookup is sub-millisecond on a local resolver.
- An **uncached** lookup is tens of milliseconds (round-trip to
  upstream + maybe more for CNAME chains).

Trackers mine this signal. By measuring DNS-lookup time for a
specific carefully chosen set of hostnames, a script can fingerprint
which sites the user has visited recently (the cached ones answer
fast; the uncached ones answer slow). It's not a unique-ID
fingerprint, but it's stable enough to refine cohort identification.

The defence: add small random jitter (0–N ms) to every cache hit, so
the cached vs. uncached distinction is fuzzed. The price is added
local latency (mostly invisible — a few ms in the local resolver path
is negligible compared to the 30+ ms WAN hops needed for everything
else).

### Concrete user-impact example

You browse 30 sites in an hour. Each site has ~50 third-party hosts.
That's 1,500 DNS lookups, but only ~300 unique hostnames (the same
trackers show up on every site).

- Without a cache: 1,500 × 35 ms = ~52 seconds of cumulative DNS
  latency, and 1,500 queries to your upstream resolver — handing
  them a high-resolution browsing log even if you've encrypted the
  transport.
- With CloakDNS's cache: only 300 queries upstream. The other 1,200
  are served locally in <1 ms each. Total upstream traffic drops
  ~80%, your browsing-pattern signal to upstream drops with it, and
  the page-load latency you actually feel improves.

---

## See it live

Run end-to-end on **2026-04-28**. Two configurations, same domain.

### Config

```toml
# cloakdns-feat-cache.toml
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
max_entries   = 100
jitter_max_ms = 0     # change to 50 for the second run

[logging]
path  = "cloakdns-feat-cache.jsonl"
async = false
```

### Run 1 — `jitter_max_ms = 0`

Send the same query 5 times in a row:

```
$ for i in 1 2 3 4 5; do dig @127.0.0.1 -p 5354 example.org +noall +answer +stats | grep -E 'Query time|^example'; echo '---'; done

example.org.    300  IN  A  172.66.157.237
example.org.    300  IN  A  104.20.26.136
;; Query time: 37 msec
---
example.org.    300  IN  A  172.66.157.237
example.org.    300  IN  A  104.20.26.136
;; Query time: 0 msec
---
example.org.    300  IN  A  172.66.157.237
example.org.    300  IN  A  104.20.26.136
;; Query time: 0 msec
---
example.org.    300  IN  A  172.66.157.237
example.org.    300  IN  A  104.20.26.136
;; Query time: 0 msec
---
example.org.    300  IN  A  172.66.157.237
example.org.    300  IN  A  104.20.26.136
;; Query time: 0 msec
---
```

Read structure:

- **Query 1**: 37 ms — full upstream round-trip (CloakDNS → 1.1.1.1
  → CloakDNS → dig).
- **Queries 2–5**: 0 ms each — served from cache.
- All 5 return the same IPs (`172.66.157.237`, `104.20.26.136`).
- TTL stays at 300 in this output because the queries arrive within
  ~1 second of each other and dig only shows whole-second
  resolution.

Daemon log captures the action distinction:

```
forward example.org
cached  example.org
cached  example.org
cached  example.org
cached  example.org
```

JSONL records (4 of the 5 — one was dropped to keep this excerpt readable):

```json
{"v":2,"ts":"2026-04-27T19:08:21.438Z","qname":"example.org","qtype":"A","action":"allow","rule":null,"cname_chain":["example.org"],"upstream":"1.1.1.1:53","latency_ms":37.059,"client":"127.0.0.1:57955"}
{"v":2,"ts":"2026-04-27T19:08:21.564Z","qname":"example.org","qtype":"A","action":"cached","rule":null,"cname_chain":[],"upstream":null,"latency_ms":0.196,"client":"127.0.0.1:57957"}
{"v":2,"ts":"2026-04-27T19:08:21.643Z","qname":"example.org","qtype":"A","action":"cached","rule":null,"cname_chain":[],"upstream":null,"latency_ms":0.165,"client":"127.0.0.1:57958"}
{"v":2,"ts":"2026-04-27T19:08:21.724Z","qname":"example.org","qtype":"A","action":"cached","rule":null,"cname_chain":[],"upstream":null,"latency_ms":0.207,"client":"127.0.0.1:57960"}
```

Daemon-side latency for cache hits is **0.16–0.21 ms** (vs 37 ms on
the forward). That's the gap a tracker sees if it measures DNS
timing from JS — a thousandfold cleaner discrimination signal than
the WAN round-trip.

### Run 2 — `jitter_max_ms = 50`

Same config, only `jitter_max_ms` flipped to 50. Warm the cache with
a single query (not shown), then send 5 cache-hit queries:

```
$ for i in 1 2 3 4 5; do dig @127.0.0.1 -p 5354 example.org +noall +stats | grep "Query time"; done

;; Query time: 38 msec
;; Query time: 29 msec
;; Query time: 41 msec
;; Query time: 35 msec
;; Query time: 10 msec
```

Same five cache hits, but now the timings are spread between
**10 ms and 41 ms** rather than all sitting at 0. That's the
configured 0–50 ms additive jitter doing its job.

The shape is roughly uniform between 0 and `jitter_max_ms`. The
jitter test in `tools/e2e/jitter_test.py` runs 30 samples each at
jitter=0 and jitter=50 and shows the distribution explicitly:

```
jitter=0:  n=30 min=0  median=0  max=1   mean=0.2  stdev=0.4
jitter=50: n=30 min=9  median=36 max=61  mean=35.2 stdev=15.9
```

(Captured during the verification round in
`docs/09-verification.md`.)

The visible cost: each cache hit is now ~25 ms slower on average. In
exchange the cached/uncached signal is buried under noise — the
~25 ms of jitter is comparable to a typical un-cached round trip,
so a JS timer can't cleanly separate "this name was already cached"
from "this name was a fresh lookup."

---

## How it works in code

Six pieces.

### 1. The cache itself (`src/cache.cpp`)

A flat hash-map of `CacheKey` (qname + qtype + class) to a
`CacheEntry` containing the raw response bytes, the absolute expiry
timestamp, an LRU-list iterator, and the byte offsets of every TTL
field in the response (so we can rewrite them on hit).

```cpp
// include/cloakdns/cache.hpp (sketch)
struct CacheEntry {
    std::vector<std::byte> response;        // wire-format bytes
    std::chrono::steady_clock::time_point expires_at;
    std::vector<size_t> ttl_offsets;        // where TTL is in `response`
    std::list<CacheKey>::iterator lru_it;   // for O(1) LRU promotion
};
```

### 2. Lookup with TTL rewrite (`src/cache.cpp:217`)

```cpp
// src/cache.cpp:217
std::optional<std::vector<std::byte>>
DnsCache::lookup(const CacheKey& key, uint16_t client_id) {
    const auto now = std::chrono::steady_clock::now();
    std::vector<std::byte> copy;
    std::vector<size_t> offsets;
    std::chrono::seconds remaining{0};
    {
        std::unique_lock lk{mu_};
        const auto it = map_.find(key);
        if (it == map_.end()) {
            misses_.fetch_add(1, std::memory_order_relaxed);
            return std::nullopt;
        }
        if (it->second.expires_at <= now) {
            // Expired — drop now so the next miss isn't spent walking past it.
            lru_.erase(it->second.lru_it);
            map_.erase(it);
            misses_.fetch_add(1, std::memory_order_relaxed);
            return std::nullopt;
        }
        copy    = it->second.response;
        offsets = it->second.ttl_offsets;
        remaining = std::chrono::duration_cast<std::chrono::seconds>(
            it->second.expires_at - now);
        lru_.splice(lru_.end(), lru_, it->second.lru_it);  // promote to MRU
    }

    hits_.fetch_add(1, std::memory_order_relaxed);
    const auto ttl = static_cast<uint32_t>(
        std::min<int64_t>(remaining.count(),
                          std::numeric_limits<uint32_t>::max()));
    rewrite_ttls(std::span<std::byte>{copy}, offsets, ttl);

    if (copy.size() >= 2) {
        copy[0] = std::byte{static_cast<uint8_t>(client_id >> 8)};
        copy[1] = std::byte{static_cast<uint8_t>(client_id & 0xff)};
    }
    return copy;
}
```

Three things happening here:

1. **Lazy eviction on expiry**. If the map entry exists but
   `expires_at <= now`, we erase it then and there. This keeps the
   sweeper's job small.
2. **LRU promotion**. On every hit we splice the LRU-list node to
   the back (most-recently-used). When the cache is at capacity,
   eviction takes from the front (least-recently-used).
3. **TTL rewrite**. The bytes were stored with the original TTL.
   `rewrite_ttls` walks the recorded offsets and writes the
   `remaining` value as a 4-byte big-endian integer at each one.
   That's how a cached answer at t=200 returns TTL=100 to the
   client.

The transaction-ID swap at the end (`copy[0] = client_id >> 8`,
`copy[1] = client_id & 0xff`) reuses the same trick the upstream
forwarder uses — replace the cached response's stored ID with this
client's ID before returning.

### 3. Insert with computed TTL (`src/cache.cpp:181`)

After a successful upstream forward, `handle()` calls
`cache.insert(key, upstream_resp, parsed_msg, ttl)` to store. The
TTL passed in is computed by `compute_cache_ttl(parsed_msg)`
following RFC 2181 (positive TTL = min over the answer RRs) or
RFC 2308 (negative TTL = min over SOA + MINIMUM, capped). Empty
or RCODE-uncacheable responses are dropped — see line ~98 for the
RCODEs that "must never be cached regardless of TTL."

### 4. The jitter helper (`src/cache.cpp:151`)

```cpp
// src/cache.cpp:151
asio::awaitable<void> apply_jitter(std::chrono::milliseconds max_jitter) {
    if (max_jitter.count() <= 0) co_return;

    std::uniform_int_distribution<int> dist(
        0, static_cast<int>(max_jitter.count()));
    const auto delay = std::chrono::milliseconds{dist(jitter_rng)};
    if (delay.count() == 0) co_return;

    auto exec = co_await asio::this_coro::executor;
    asio::steady_timer timer{exec, delay};
    co_await timer.async_wait(asio::use_awaitable);
}
```

Pick a uniform-random delay between 0 and `max_jitter` (inclusive),
then `co_await` an Asio `steady_timer` for that duration. Because
this is a coroutine, the jitter wait is non-blocking — other queries
in flight on the same thread are unaffected.

The `thread_local` RNG (line 31) means contention-free random
numbers across the request handlers; no shared mutex on the RNG.

### 5. The handler glue (`src/server.cpp`)

```cpp
// src/server.cpp ~line 191
if (auto key = make_cache_key(msg)) {
    if (auto cached = cache.lookup(*key, msg.header.id)) {
        co_await apply_jitter(cache.jitter_max());
        co_await sock.async_send_to(
            asio::buffer(*cached), from, use_awaitable);
        std::cout << "cached  " << qname << std::endl;
        log_record(LogAction::Cached, qname, qtype);
        co_return;
    }
}
```

The order matters: jitter happens **after** the cache lookup but
**before** the response goes out. So the timer the JS code measures
includes the jitter. (If we jittered before the lookup, an attacker
could still distinguish "did we hit the cache" by the
hit-vs-miss-without-jitter delta.)

### 6. Background sweeper

`DnsCache`'s constructor starts a `sweeper_` thread that periodically
calls `sweep_expired()` (every 30 seconds — line 169). The sweeper
walks the map and drops every entry past its expiry. Lazy eviction
on lookup catches any miss in between sweeps; the sweeper exists to
keep the working-set memory bounded for cache entries that are
expired but never queried again.

### What you can verify yourself

- Run with `jitter_max_ms = 0`, dig the same name 10 times, watch
  every hit return 0 ms.
- Run `python tools/e2e/jitter_test.py` — it does the full
  jitter=0 vs jitter=50 measurement.
- Watch cache hit/miss counts via the `inserts/hits/misses`
  atomics — exposed by `DnsCache::stats()` (`src/cache.cpp:283`).

---

## References

- **FP-Radar** (PETS 2022) — the paper showing DNS-timing
  fingerprinting via Performance API.
- **RFC 1035 §3.2.1** — the TTL field shape we rewrite.
- **RFC 2181** — TTL aggregation rules for positive cached responses.
- **RFC 2308** — negative caching (NXDOMAIN, NODATA) — what min-SOA-
  TTL means for cache lifetime.
- **`docs/09-verification.md` §Cache TTL jitter** — the full
  measurement of jitter=0 vs jitter=50.
- **Source files:** [`src/cache.cpp`](../src/cache.cpp),
  [`include/cloakdns/cache.hpp`](../include/cloakdns/cache.hpp),
  [`src/main.cpp`](../src/main.cpp).
- Related features: UDP forwarding, structured query log, hot-reload.
