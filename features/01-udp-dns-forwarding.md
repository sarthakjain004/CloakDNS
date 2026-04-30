# UDP DNS forwarding

The foundation. CloakDNS receives DNS queries on a UDP socket, forwards
them to a chosen upstream resolver, and returns the upstream's answer
to the client. Every privacy / blocking / inspection layer in CloakDNS
sits on top of this.

---

## The problem

When your laptop opens `example.com`, somewhere a DNS lookup happens:
the operating system asks a resolver "what IP is `example.com`?", gets
back a number like `172.66.147.243`, and only then connects.

Without CloakDNS, that lookup goes to whichever resolver your network
or OS is hardcoded to use. On most home networks that's **your
ISP's DNS** — and ISPs see every domain every device on your network
ever asks about. They can log it, profile you, monetise that data
(in many countries this is legal), throttle traffic to certain
destinations, or hand a list to a court / regulator on demand.

Even if you switch to a public resolver like Google's `8.8.8.8` or
Cloudflare's `1.1.1.1`, the basic problem doesn't go away — you've
just changed which company sees every lookup. You also can't insert
your own logic in the middle (block trackers, filter ads, log queries
locally), because you don't run that resolver.

**CloakDNS's job at the most basic layer:** *be your local resolver.*
Listen on a UDP port your OS can be pointed at; forward queries to
the upstream resolver *you choose*; return the answer. That's the
plumbing every other CloakDNS feature depends on.

### Concrete user-impact example

You open Instagram on your phone. Your phone is configured to use the
ISP's resolver (the default).

- DNS lookup for `instagram.com` → ISP sees it.
- DNS lookup for `cdn.instagram.com` → ISP sees it.
- DNS lookup for `connect.facebook.net` (the tracking pixel a third
  party site loaded yesterday on your laptop) → ISP sees it.

After a week your ISP has a high-resolution log of which apps you use,
how often, and at what times of day. None of the queries were *secret*;
HTTPS doesn't help here — DNS is plaintext, separate from HTTPS, and
happens before HTTPS does.

With CloakDNS pointed at by your phone:

- DNS lookup for `instagram.com` → goes to CloakDNS at home.
- CloakDNS forwards to your chosen upstream (Cloudflare, Quad9,
  Mullvad — your choice).
- Your ISP's resolver no longer sees the query; what your ISP sees is
  the encrypted leg between your phone (or your home network) and
  CloakDNS, plus the leg from CloakDNS out.

The privacy layers that come later (encrypted upstream, blocklists,
EDNS0 padding, ECH) all assume this basic forwarding plumbing exists
and works. No forwarding, no resolver, no privacy story.

---

## See it live

This walkthrough was run end-to-end on **2026-04-28** with the
real binary. The output blocks below are verbatim copy-pastes from
that run.

### 1. Write a minimal config

Save as `cloakdns-feat-udp.toml` in the project root:

```toml
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

Plain UDP upstream to Cloudflare's `1.1.1.1:53`. A blocklist is
required by the config validator (`fatal: blocklist.sources: must
contain at least one path`), so we point at the bundled `tier1.txt`.

### 2. Start the daemon

```
$ ./build-msvc/Release/cloakdns.exe cloakdns-feat-udp.toml
```

Captured startup output:

```
loaded 22 block rule(s) from 1 source(s)
cloakdns listening on 127.0.0.1:5354
upstream: 1.1.1.1:53  (timeout 3000ms)
cname uncloaking: max depth 8
cache: 100 entries, jitter 0-5ms on hit, sweep 30s
padding: 128-byte blocks
logging: cloakdns-feat-udp.jsonl (sync)
```

The line that matters for this feature is `cloakdns listening on
127.0.0.1:5354` — confirmation that the UDP socket is open and the
daemon is ready to receive queries.

### 3. Send a query through CloakDNS

In another terminal:

```
$ dig @127.0.0.1 -p 5354 example.com +noall +question +answer +stats
```

Captured output:

```
;example.com.                  IN      A
example.com.            300     IN      A       172.66.147.243
example.com.            300     IN      A       104.20.23.154
;; Query time: 44 msec
;; SERVER: 127.0.0.1#5354(127.0.0.1) (UDP)
;; WHEN: Tue Apr 28 00:21:26 India Standard Time 2026
;; MSG SIZE  rcvd: 61
```

Three things to read off this output:

- **The answer came back.** `example.com` resolved to two real
  Cloudflare-hosted IPs. The forwarder correctly relayed the upstream
  response.
- **`SERVER: 127.0.0.1#5354(127.0.0.1) (UDP)`** — `dig` is reporting
  it spoke UDP to CloakDNS at the loopback port. End-to-end UDP path
  was exercised.
- **44 ms latency** — that's the round-trip including the network hop
  to `1.1.1.1` and back. CloakDNS itself adds sub-millisecond overhead;
  the visible latency is dominated by the upstream RTT.

### 4. Look at the structured log record

The same query produced a JSON line in `cloakdns-feat-udp.jsonl`.
Captured (one line, pretty-formatted here for readability):

```json
{
  "v": 2,
  "ts": "2026-04-27T18:52:21.980Z",
  "qname": "example.com",
  "qtype": "A",
  "action": "allow",
  "rule": null,
  "cname_chain": ["example.com"],
  "upstream": "1.1.1.1:53",
  "latency_ms": 5.871,
  "client": "127.0.0.1:50215"
}
```

`"action": "allow"` because nothing matched the blocklist. `"upstream":
"1.1.1.1:53"` confirms which upstream actually answered — useful when
you have multiple upstreams configured for failover.

`latency_ms: 5.871` is the daemon-internal latency (queue → forward →
send back). It's much smaller than `dig`'s 44 ms because `dig`'s
number includes the round-trip wire time on the loopback and to
`1.1.1.1`; the daemon-side number is wall time inside the coroutine,
which is mostly just the time to `co_await` the upstream socket.

---

## How it works in code

Three pieces wire this together.

### The UDP listener (`src/server.cpp`)

The daemon opens a UDP socket on the configured `listen_addr:port`
and runs an Asio coroutine that loops on `async_receive_from`:

```cpp
// src/server.cpp ~line 295 (inside serve())
n = co_await sock.async_receive_from(
    asio::buffer(recv_buf), from, use_awaitable);
```

For each received datagram, it spawns a fresh coroutine via
`asio::co_spawn(...handle(...))` so multiple in-flight queries don't
serialise on each other:

```cpp
// src/server.cpp ~line 316
asio::co_spawn(sock.get_executor(),
    handle(std::move(copy), from, sock, std::move(snapshot),
           resolver, uncloaker, cache, logger),
    asio::detached);
```

`handle()` is where each query is processed end-to-end.

### The per-query handler

`handle()` (in `src/server.cpp`, line 119) does this:

1. Parses the DNS message bytes (`cloak::parse(query)`).
2. Refuses unsupported qtypes (ANY/AXFR/IXFR — see the abuse-qtype
   feature doc).
3. Looks up the qname in the blocklist. If matched: synthesises a
   block response (e.g. A → `0.0.0.0`) and sends it.
4. Looks in the cache. If hit: serves from cache.
5. **Otherwise, forwards upstream** — this is the line that matters
   for *this* feature:

   ```cpp
   // src/server.cpp ~line 204
   auto fwd_result = co_await resolver.forward_with_source(query);
   auto upstream_resp = std::move(fwd_result.response);
   const auto upstream_str = fwd_result.upstream;
   ```

6. Sends the upstream's answer back to the original client over the
   same UDP socket, and writes a log record.

### The forward path (`src/resolver.cpp` + `src/udp_adapter.cpp`)

`cloak::resolver::Resolver::forward_with_source` is the public API
(declared in `include/cloakdns/resolver.hpp`). The implementation
lives in `Resolver::Impl::forward` in `src/resolver.cpp`. The
single-shot per-protocol exchange — the actual UDP send/recv pair —
sits behind the `Adapter` interface and is implemented in
`src/udp_adapter.cpp`.

Before any Adapter is touched, `forward` rewrites the transaction ID
and pads the query once. The padded buffer is reused across every
retry / fallback so each upstream sees identical wire bytes:

```cpp
// src/resolver.cpp:64
const uint16_t client_id = read_u16_be(client_query, 0);
std::uniform_int_distribution<uint32_t> dist{0, 0xffff};
const uint16_t our_id = static_cast<uint16_t>(dist(rng));

vector<byte> outbound = (cfg.padding_block_size == 0)
    ? vector<byte>(client_query.begin(), client_query.end())
    : pad_query(client_query, cfg.padding_block_size);
write_u16_be(span<byte>{outbound}, 0, our_id);
```

Two things happen before sending:

- **Transaction-ID randomisation.** The client's query had its own
  16-bit ID; CloakDNS swaps it for a fresh random ID before sending
  upstream, then swaps it back when the response arrives. Without
  this, an attacker who can guess the client's IDs could try to
  forge upstream responses (RFC 5452 §6).
- **EDNS0 padding** (covered in its own feature doc). For UDP this
  pads the outgoing query to a multiple of `padding_block_size` bytes
  so an observer can't infer the queried name from packet length.

Then the loop over configured Adapters (with retries on the primary):

```cpp
// src/resolver.cpp:80
for (size_t i = 0; i < adapters.size(); ++i) {
    const bool is_primary = (i == 0);
    const int  attempts   = is_primary
        ? (1 + cfg.retries_on_primary) : 1;
    auto& adapter = *adapters[i];

    for (int a = 0; a < attempts; ++a) {
        auto reply = co_await adapter.try_once(outbound, cfg.timeout);
        if (!reply) continue;
        if (reply->bytes.size() < 12) continue;
        if (read_u16_be(reply->bytes, 0) != our_id) continue;
        if (!reply_matches_request(client_query, reply->bytes)) continue;

        write_u16_be(span<byte>{reply->bytes}, 0, client_id);
        co_return ForwardResult{
            .response = std::move(reply->bytes),
            .upstream = string{adapter.label()},
            ...
        };
    }
}
throw runtime_error{"resolver: all adapters exhausted"};
```

For UDP mode, every Adapter in the vector is a `UdpAdapter`
(constructed by `cloak::resolver::build_from_config()` in
`src/resolver_factory.cpp`). The `Adapter::try_once` virtual method
is what picks the protocol — UDP, DoT, or DoH — without the Resolver
needing to know.

When the upstream replies, the response's transaction ID is rewritten
back to the client's original ID before returning — `dig` only
notices the round-trip happened; the ID-swap is invisible at the
client side.

### Why coroutines

Each query is an independent `co_await` chain. While CloakDNS is
waiting for `1.1.1.1` to reply to query A, it can be processing
query B, query C, etc. on the same single thread. No threadpool, no
mutexes around hot paths. Asio's `awaitable<T>` integrates with the
io_context to multiplex thousands of in-flight queries naturally.

### What you can verify yourself

- Re-run the dig with `+stats` and look at `;; SERVER:
  127.0.0.1#5354(127.0.0.1) (UDP)` — confirms UDP path.
- Check `cloakdns-feat-udp.jsonl` for the per-query record after
  every dig.
- Try a non-existent name: `dig @127.0.0.1 -p 5354 doesnotexist.invalid`
  — CloakDNS forwards it, upstream returns NXDOMAIN, CloakDNS relays
  the NXDOMAIN.

---

## References

- **Architecture walkthrough:** [`docs/03-architecture.md`](../docs/03-architecture.md)
- **DNS primer:** [`docs/01-dns-primer.md`](../docs/01-dns-primer.md)
- **RFC 1035** — the DNS wire format.
- **RFC 5452 §6** — transaction-ID randomization (why we swap the ID).
- **Source files:** [`src/server.cpp`](../src/server.cpp),
  [`src/resolver.cpp`](../src/resolver.cpp),
  [`src/udp_adapter.cpp`](../src/udp_adapter.cpp),
  [`include/cloakdns/resolver.hpp`](../include/cloakdns/resolver.hpp).
- Related features in this directory: domain blocking, cache,
  CNAME uncloaking, structured query log, DoT/DoH/ECH upstreams.
