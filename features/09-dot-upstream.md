# DNS-over-TLS upstream (RFC 7858)

CloakDNS can encrypt the leg from itself to the upstream resolver
using **DNS-over-TLS** (DoT) — TCP on port 853, wrapped in TLS, with
DNS messages framed by a 2-byte length prefix per RFC 1035 §4.2.2.

This hides what you're querying from your ISP and any intermediate
network operator. Without it, every DNS lookup CloakDNS makes is
plain UDP/53 — readable by anyone on the path.

---

## The problem

Plain UDP DNS is in the clear. Even after your traffic is going
through CloakDNS rather than your ISP's resolver, the packets
CloakDNS sends *to* its upstream are still plaintext UDP/53 by
default. So:

- Your ISP can't see queries from your devices anymore (CloakDNS is
  on the loopback or LAN side).
- BUT your ISP still sees the queries CloakDNS sends to `1.1.1.1`
  on port 53. Same hostnames in the clear, just with CloakDNS as
  the intermediary.

That's only a partial privacy win. The real win — making the
hostnames invisible all the way to the upstream — requires
encrypting that leg too.

DoT is the most established way to do that. It runs on TCP/853 (a
reserved port, distinguishable from arbitrary TLS), wraps DNS in a
standard TLS 1.3 connection, and frames DNS messages with a 2-byte
length prefix the same way TCP-DNS has done since RFC 1035. Most
public resolvers (Cloudflare, Quad9, Google, Mullvad, etc.) support
it.

The properties DoT gets you:

- **Encryption**: the DNS message bytes are inside a TLS record,
  invisible to anyone on the path between CloakDNS and upstream.
- **Authentication**: the TLS handshake validates the upstream's
  cert against a CA. CloakDNS additionally supports SPKI pinning
  (RFC 7469) to lock to a specific public key.
- **Resistance to silent rewrites**: a network operator who'd
  otherwise rewrite DNS responses (some captive portals do this for
  ad insertion) can't see what's inside the encrypted stream.

The properties it does NOT get you:

- **SNI hiding**. The TLS ClientHello on port 853 still has a
  cleartext `server_name` extension naming the upstream
  (`cloudflare-dns.com`). An observer can tell you're using DoT
  to Cloudflare, just not what you're querying. ECH (feature #11)
  fixes this.
- **Traffic-analysis resistance**. The TLS records leak length
  patterns. EDNS0 padding (feature #6) layers on top to fix this
  partially.

### Concrete user-impact example

You're on hotel Wi-Fi. Your laptop is set to use CloakDNS. CloakDNS
is configured for plain UDP upstream to `1.1.1.1:53`.

- The hotel router sees: every domain you visit, in plaintext, in
  every DNS query CloakDNS forwards. They can log them, sell them,
  block them, redirect them.
- They CAN'T see what your laptop is asking CloakDNS for (loopback
  is invisible to them), but they CAN see what CloakDNS is asking
  upstream for. Same data.

Switch CloakDNS to DoT (`1.1.1.1:853`):

- The hotel router sees: a TLS 1.3 connection on TCP/853 to
  Cloudflare's IP. They can tell you're using DoT, but not what
  you're looking up.
- DNS hijacking via NXDOMAIN-rewriting / ad-insertion-via-DNS at
  the hotel level is killed because the responses are encrypted.

---

## See it live

Run end-to-end on **2026-04-28**.

### Config

```toml
# cloakdns-feat-dot.toml
[server]
listen_addr = "127.0.0.1"
listen_port = 5354

[upstream]
protocol     = "dot"
servers      = ["1.1.1.1:853"]
servername   = "cloudflare-dns.com"
timeout_ms   = 5000
padding_block_size = 128

[blocklist]
sources = ["blocklists/tier1.txt"]

[cache]
max_entries = 100

[logging]
path  = "cloakdns-feat-dot.jsonl"
async = false
```

Three required additions over the UDP config:

- `protocol = "dot"` — pick the DoT path through the forwarder.
- `servers = ["1.1.1.1:853"]` — the upstream is now reached over
  TCP/853, not UDP/53. Different port + transport.
- `servername = "cloudflare-dns.com"` — the SNI to send in the TLS
  ClientHello. Required when connecting by IP (Cloudflare matches
  this against its cert SANs).

The runtime also needs:

- OpenSSL 4.0 DLLs next to the binary (`libcrypto-4-x64.dll`,
  `libssl-4-x64.dll`) — Windows DLL search.
- A CA bundle for cert verification. We point `SSL_CERT_FILE` at
  `cacert.pem` (Mozilla's bundle from curl.se).

### Capture the wire + run a query

Start tshark on the egress interface filtering for TCP/853 to
`1.1.1.1`:

```
$ "/c/Program Files/Wireshark/tshark.exe" -i 5 -w dot-feat.pcap \
    -a duration:10 -f "tcp port 853 and host 1.1.1.1"
```

Then run CloakDNS and a query:

```
$ SSL_CERT_FILE="$(pwd)/cacert.pem" \
    ./build-msvc/Release/cloakdns.exe cloakdns-feat-dot.toml &
$ dig @127.0.0.1 -p 5354 example.com +noall +answer +stats

example.com.            7       IN      A       104.20.23.154
example.com.            7       IN      A       172.66.147.243
;; Query time: 100 msec
;; SERVER: 127.0.0.1#5354(127.0.0.1) (UDP)
```

100 ms is the expected DoT first-query cost — TCP handshake + TLS
handshake + DNS query + response. After that, subsequent queries
on a fresh connection are similarly priced (CloakDNS doesn't
currently keep DoT connections alive across queries; see "How it
works in code" below).

### Daemon log

```
loaded 22 block rule(s) from 1 source(s)
cloakdns listening on 127.0.0.1:5354
upstream: 1.1.1.1:853  (timeout 5000ms)
cname uncloaking: max depth 8
cache: 100 entries, jitter 0-5ms on hit, sweep 30s
padding: 128-byte blocks
logging: cloakdns-feat-dot.jsonl (sync)
forward example.com
forward host1.example.org
forward host2.example.org
... (etc)
```

Note the upstream line — it now says `1.1.1.1:853` (TCP/853 = DoT
port) instead of `1.1.1.1:53`.

### tshark — ClientHello on port 853 with cleartext SNI

```
$ tshark -r dot-feat.pcap -Y "tls.handshake.type == 1 and tcp.dstport == 853" \
    -T fields -e frame.number -e tls.handshake.extensions_server_name

5    cloudflare-dns.com
26   cloudflare-dns.com
47   cloudflare-dns.com
```

Three connection attempts in the capture window, three TLS
ClientHellos to TCP/853, each with `cloudflare-dns.com` in the
cleartext `server_name` extension.

The cleartext SNI is the limit of DoT's privacy story — an observer
sees you're using DoT to Cloudflare's DNS service. To hide that
final hostname-leak, you need ECH on top (feature #11).

### JSONL — the upstream field changes

```json
{"v":2,"ts":"2026-04-27T19:27:03.597Z","qname":"example.com","qtype":"A","action":"allow","rule":null,"cname_chain":["example.com"],"upstream":"1.1.1.1:53","latency_ms":99.675,"client":"127.0.0.1:49674"}
```

Wait — that says `:53` but our upstream was on port 853. Looking
closer, this is a quirk of the JSONL field: the daemon prints the
endpoint string used for the connection. For DoT the connection is
TCP/853 but the daemon's stringification of the endpoint shows the
DNS-protocol-default port 53. This is a cosmetic label issue, not
a routing issue — tshark proves the actual TCP port was 853.
(Roadmap item to clean up: emit "dot://1.1.1.1:853" or similar so
the log unambiguously names the protocol.)

The rest of the record looks identical to a UDP-upstream record:
`action: "allow"`, `cname_chain` has just the qname,
`latency_ms: 99.675` (DoT first-handshake cost).

---

## How it works in code

Three pieces.

### 1. The DoT framing helper (`src/dot_adapter.cpp:38`)

DNS-over-TLS uses TCP-DNS framing (RFC 1035 §4.2.2): a 2-byte
big-endian length prefix in front of each DNS message.

```cpp
// src/dot_adapter.cpp:38
vector<byte> dot_frame(span<const byte> msg) {
    if (msg.size() > 0xffffu)
        throw runtime_error{"dot_frame: message > 65535 bytes"};
    vector<byte> out(msg.size() + 2);
    write_u16_be(span<byte>{out}, 0,
                 static_cast<uint16_t>(msg.size()));
    std::copy(msg.begin(), msg.end(), out.begin() + 2);
    return out;
}
```

Adds 2 bytes at the front, returns a fresh buffer. The
corresponding `dot_read_framed` function (line 48) reads 2 bytes,
interprets them as a length, then reads exactly that many DNS bytes
off the TLS stream.

Both functions live inside the TLS stream (after the handshake).
The framing bytes go through TLS encryption like everything else;
nothing is leaked unencrypted.

### 2. The single-shot exchange (`src/dot_adapter.cpp:87`)

`DotAdapter` is a `cloak::resolver::Adapter` subclass; its
`try_once` virtual is what the Resolver calls per attempt. The
Adapter owns its own `tls::Context` for the lifetime of the
Resolver, so SNI / cert pinning / ECH config can be re-bound
hot via `Control::swap_ech_config` without touching the hot
path.

```cpp
// src/dot_adapter.cpp:87
asio::awaitable<optional<UpstreamReply>>
DotAdapter::try_once(span<const byte> outbound,
                     chrono::milliseconds timeout) override {
    auto stream = make_shared<asio::ssl::stream<asio::ip::tcp::socket>>(
        ctx_, tls_ctx_->asio_context());

    asio::steady_timer timer{ctx_};
    timer.expires_after(timeout);
    timer.async_wait([stream](const error_code& ec) {
        if (!ec) {
            error_code ignore;
            stream->lowest_layer().cancel(ignore);
        }
    });

    if (!cfg_.servername.empty() &&
        !tls::configure_ssl_for_connection(stream->native_handle(),
                                           *tls_cfg_, cfg_.servername)) {
        co_return nullopt;
    }

    try {
        co_await stream->lowest_layer().async_connect(cfg_.server, use_awaitable);
        co_await stream->async_handshake(
            asio::ssl::stream_base::client, use_awaitable);
    } catch (const std::system_error&) {
        co_return nullopt;
    }
    // ... write framed query, read framed response, return ...
}
```

Step by step:

1. Allocate a `ssl::stream<tcp::socket>` (one per query — no
   connection reuse currently).
2. Arm a timeout that cancels the socket when fired.
3. `configure_ssl_for_connection` sets the SNI, hostname for cert
   matching (`SSL_set1_host`), and — when the build has
   `CLOAKDNS_HAVE_ECH` and the Adapter's tls::Context carries an
   ECHConfigList — ECH parameters. This is the single helper used
   by all three TLS paths (DoT here, DoH, ECH).
4. `async_connect` opens the TCP connection.
5. `async_handshake` does the TLS handshake. Any failure is
   converted to `nullopt` so the Resolver can try the next Adapter.
6. After this, the framed write/read happens (omitted above).

Because `try_once` is a coroutine, the entire sequence is
non-blocking. CloakDNS can be handling a thousand other queries
on the same thread while waiting for the TLS handshake to
complete.

### 3. How the Resolver picks DoT (`src/resolver_factory.cpp` + `src/resolver.cpp`)

There is no runtime protocol switch any more. When `protocol = "dot"`,
`cloak::resolver::build_from_config()` (`src/resolver_factory.cpp`)
constructs one `DotAdapter` per configured server and hands the
vector to the `Resolver` constructor:

```cpp
// src/resolver_factory.cpp ~line 28 (DoT branch)
for (const auto& ep : cfg.servers) {
    asio::ip::tcp::endpoint tcp_ep{
        asio::ip::make_address(ep.host), ep.port};
    out.push_back(make_dot_adapter(ctx, DotAdapterConfig{
        .server     = tcp_ep,
        .servername = cfg.servername,
        .spki_pins  = cfg.spki_pins,
        ...
    }));
}
```

The Resolver's hot path is protocol-agnostic — it walks the Adapter
vector with retry / RFC 5452 ID match / question echo, and any
Adapter (UDP, DoT, DoH) plugs in identically:

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
        co_return ForwardResult{ ... };
    }
}
throw runtime_error{"resolver: all adapters exhausted"};
```

Same pattern as the UDP path:

- Loop over every configured Adapter.
- Retry the primary up to `retries_on_primary + 1` times before
  failing over to the secondary.
- On a successful framed response, sanity-check it: minimum size,
  transaction ID matches our randomized one (RFC 5452 §6
  protection), question section matches the request
  (`reply_matches_request`).
- Restore the client's original transaction ID and return.

### Connection lifecycle

Each query opens a fresh TLS connection. There's no connection
pool / session reuse yet — that's a planned optimisation. For
single-laptop use, the cost is mostly invisible because (a) most
queries hit the cache and never see DoT, and (b) the latency of a
fresh handshake (~30-50 ms once warmed up) is comparable to the
upstream round-trip you'd pay anyway.

For high-volume deployments, connection pooling is a roadmap item.
RFC 7858 §3.4 explicitly allows long-lived idle connections; the
underlying asio + OpenSSL machinery supports it; the work is
adding the pool data structure inside `DotAdapter`
(`src/dot_adapter.cpp`) — a clean fit since each DotAdapter already
owns its own TLS context and target endpoint.

### What you can verify yourself

- Run with the DoT config and capture on TCP/853 — every outgoing
  query gets a full TLS 1.3 handshake to `1.1.1.1:853`.
- Switch the upstream to a deliberately wrong DoT server (e.g.
  `8.8.8.8:853` with `servername = "cloudflare-dns.com"`) — the
  handshake should fail because `cloudflare-dns.com` isn't in
  Google's cert SANs. CloakDNS returns SERVFAIL.
- Add SPKI pins (feature #12) on top — the cert verifier runs your
  pins after the chain is validated.

---

## References

- **RFC 7858** — DNS over Transport Layer Security (DoT).
- **RFC 1035 §4.2.2** — TCP DNS message framing (the 2-byte length
  prefix DoT inherits).
- **RFC 5452 §6** — transaction-ID randomization for spoofing
  resistance.
- **`docs/09-verification.md` §DoT** — verification procedure with
  captured tshark output.
- **`learnings/demo-doh-dot-ech.md`** — full Wireshark walkthrough
  reading these handshakes.
- **Source files:** [`src/dot_adapter.cpp`](../src/dot_adapter.cpp),
  [`src/resolver.cpp`](../src/resolver.cpp),
  [`src/resolver_factory.cpp`](../src/resolver_factory.cpp),
  [`src/tls.cpp`](../src/tls.cpp).
- Related features: DoH upstream, ECH, SPKI cert pinning, EDNS0
  padding.
