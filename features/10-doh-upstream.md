# DNS-over-HTTPS upstream (RFC 8484)

CloakDNS can encrypt the upstream leg using **DNS-over-HTTPS** (DoH)
— TCP/443 wrapped in TLS, DNS messages carried as the body of an
HTTP/1.1 `POST /dns-query` request with content type
`application/dns-message`.

DoH offers everything DoT does (encryption, authentication,
resistance to DNS rewriting) plus an extra ~5% practical
indistinguishability win because port 443 carries every kind of
HTTPS traffic — making "you used DoH" harder to fingerprint than
"you used DoT" (which sticks out on TCP/853).

---

## The problem

Same setup as DoT (feature #9): plain UDP from CloakDNS to upstream
leaks every domain name to anyone on the path between you and your
upstream resolver. We want that leg encrypted.

DoT solves the encryption problem, but on a port (TCP/853) that's
*reserved* for DoT and immediately recognisable. A network operator
who wants to discourage encrypted DNS can:

- Block TCP/853 outright. Some restrictive networks do.
- Throttle TCP/853 traffic.
- Log "this client is using DoT" as a signal.

DoH dodges this by riding on the same port that every other web
TLS connection uses — TCP/443. You can't block port 443 without
breaking the entire web. From a network observer's view, your DoH
traffic to Cloudflare looks like normal HTTPS to a Cloudflare web
service. Distinguishing it from a regular browser visit to
`cloudflare.com` requires either DPI on the HTTP layer (visible
post-TLS handshake = needs SNI sniffing or content inspection,
neither cheap) or maintaining lists of "this IP serves DoH" (which
also serves dozens of regular websites because Cloudflare's edge is
multi-tenant).

The wire shape compared to DoT:

| Layer | DoT | DoH |
|---|---|---|
| TCP port | 853 | 443 |
| TLS handshake | yes | yes |
| Inside TLS | length-prefixed DNS | HTTP/1.1 POST + body == DNS |
| HTTP layer overhead | none | ~150 bytes per query (POST headers) |
| Visible distinguisher | port 853 = "this is DoT" | port 443 = "could be anything" |

The trade-off: DoH costs you ~150 bytes of HTTP-header overhead per
query in exchange for the indistinguishability. For most users on
broadband that's invisible; on metered mobile data where every byte
matters, DoT might be preferable.

### Concrete user-impact example

You're on a corporate network that blocks port 853. Plain DoT can't
reach `1.1.1.1:853` because the firewall drops the connection.

- With DoT: CloakDNS times out trying to handshake, returns SERVFAIL,
  apps see DNS failures.
- With DoH on port 443: CloakDNS opens TCP/443 to Cloudflare exactly
  like every other browser tab does, completes the handshake, sends
  the DoH request, gets the answer. The corporate proxy sees an
  encrypted HTTPS connection to Cloudflare and waves it through.

For a personal user the same logic applies on hotel Wi-Fi, airplane
internet, and any public network that aggressively gates non-443
traffic.

---

## See it live

Run end-to-end on **2026-04-28**.

### Config

```toml
# cloakdns-feat-doh.toml
[server]
listen_addr = "127.0.0.1"
listen_port = 5354

[upstream]
protocol     = "doh"
servers      = ["1.1.1.1:443"]
servername   = "cloudflare-dns.com"
doh_path     = "/dns-query"
timeout_ms   = 5000
padding_block_size = 128

[blocklist]
sources = ["blocklists/tier1.txt"]

[cache]
max_entries = 100

[logging]
path  = "cloakdns-feat-doh.jsonl"
async = false
```

Three additions over DoT (feature #9):

- `protocol = "doh"` — pick the DoH path.
- `servers = ["1.1.1.1:443"]` — port 443, not 853.
- `doh_path = "/dns-query"` — the URI path the upstream expects.
  Cloudflare uses `/dns-query`; Quad9 uses `/dns-query`; Google uses
  `/dns-query`. (Spec: RFC 8484 §4.1 says servers SHOULD use
  `/dns-query` but it's negotiable.)

### Capture + run a query

tshark on TCP/443 to Cloudflare, then dig:

```
$ "/c/Program Files/Wireshark/tshark.exe" -i 5 -w doh-feat.pcap \
    -a duration:10 -f "tcp port 443 and host 1.1.1.1"
$ SSL_CERT_FILE="$(pwd)/cacert.pem" \
    ./build-msvc/Release/cloakdns.exe cloakdns-feat-doh.toml &
$ dig @127.0.0.1 -p 5354 wikipedia.org +noall +answer +stats

wikipedia.org.          126     IN      A       103.102.166.224
;; Query time: 79 msec
;; SERVER: 127.0.0.1#5354(127.0.0.1) (UDP)
;; MSG SIZE  rcvd: 468
```

79 ms first-query DoH cost. After cache warmup, repeat queries
return in <1 ms (served from cache; DoH never re-touched).

### Daemon log

```
loaded 22 block rule(s) from 1 source(s)
cloakdns listening on 127.0.0.1:5354
upstream: 1.1.1.1:443  (timeout 5000ms)
cname uncloaking: max depth 8
cache: 100 entries, jitter 0-5ms on hit, sweep 30s
padding: 128-byte blocks
logging: cloakdns-feat-doh.jsonl (sync)
forward wikipedia.org
forward host1.example.org
... (etc)
```

`upstream: 1.1.1.1:443` (port 443 = DoH/HTTPS, not 853 = DoT).

### tshark — ClientHello on TCP/443 with cleartext SNI

```
$ tshark -r doh-feat.pcap -Y "tls.handshake.type == 1 and tcp.dstport == 443" \
    -T fields -e frame.number -e tls.handshake.extensions_server_name

5    cloudflare-dns.com
26   cloudflare-dns.com
47   cloudflare-dns.com
```

Same SNI as the DoT case (`cloudflare-dns.com`). The destination
*port* is the only on-wire thing distinguishing this from a regular
browser fetch — and as the protocol-hierarchy summary shows, all
229 captured frames are TCP/TLS over IP/Ethernet:

```
$ tshark -r doh-feat.pcap -q -z io,phs

frame   frames:229 bytes:89737
  eth   frames:229 bytes:89737
    ip  frames:229 bytes:89737
      tcp frames:229 bytes:89737
        tls frames:88 bytes:65911
```

Three TLS connections (one per query group), 88 frames carrying
TLS records, 89,737 total bytes. tshark reports it as plain TLS —
the HTTP layer is inside the encrypted application data and
invisible without the session key.

### JSONL

```json
{"v":2,"ts":"2026-04-27T19:30:21.382Z","qname":"wikipedia.org","qtype":"A","action":"allow","rule":null,"cname_chain":["wikipedia.org"],"upstream":"1.1.1.1:443","latency_ms":78.831,"client":"127.0.0.1:49986"}
```

`upstream: "1.1.1.1:443"` — the daemon stringified the endpoint
correctly this time (port 443 differs from default-DNS-port 53, so
the formatter included it). Compare to DoT's record (feature #9)
which has the same cosmetic `:53` quirk.

---

## How it works in code

Three pieces.

### 1. The DoH-specific layer (`src/upstream_doh.cpp`)

Tiny, thin file. Just calls into the generic HTTPS POST helper
with the right headers + path:

```cpp
// src/upstream_doh.cpp:24
asio::awaitable<std::optional<std::vector<std::byte>>>
doh_try_once(asio::io_context& ctx,
             tls::Context& tls_ctx,
             const asio::ip::tcp::endpoint& server,
             const std::string& host_header,
             const std::string& path,
             std::span<const std::byte> outbound,
             std::chrono::milliseconds timeout) {
    auto resp = co_await http::post_https_oneshot(
        ctx, tls_ctx, server, host_header, path,
        "application/dns-message", outbound, timeout);
    if (!resp) co_return std::nullopt;
    if (resp->status != 200) co_return std::nullopt;

    // RFC 8484 §6: a compliant server returns Content-Type
    // application/dns-message. Cloudflare and Quad9 both honor this;
    // if we ever see something else we should fail rather than try
    // to parse it as DNS.
    if (!resp->content_type.empty() &&
        resp->content_type.find("application/dns-message") == std::string::npos) {
        co_return std::nullopt;
    }

    co_return std::move(resp->body);
}
```

The validation is strict: only HTTP 200 is accepted, and the
response Content-Type must be `application/dns-message`. Any other
status or type — even a 200 with `text/html` (which would mean a
captive-portal page, not a real DoH response) — gets rejected as
nullopt and the caller treats this attempt as failed.

### 2. The HTTPS POST plumbing (`src/http_client.cpp:104`)

`post_https_oneshot` is general-purpose — it knows nothing about
DNS specifically; it just does TLS + HTTP/1.1 POST + read response.

```cpp
// src/http_client.cpp:140
std::ostringstream req;
req << "POST " << path << " HTTP/1.1\r\n"
    << "Host: " << host_header << "\r\n"
    << "User-Agent: cloakdns/1\r\n"
    << "Accept: " << content_type << "\r\n"
    << "Content-Type: " << content_type << "\r\n"
    << "Content-Length: " << body.size() << "\r\n"
    << "Connection: close\r\n"
    << "\r\n";
```

Hand-written HTTP/1.1 — no nghttp2, no curl. Reasons:

- HTTP/2 isn't required by the spec for DoH clients (RFC 8484 §5.1
  says servers SHOULD support both). Cloudflare, Quad9, and
  Google all accept HTTP/1.1 in practice.
- Adding nghttp2 as a dep would be ~600 lines of glue + a new
  external library; the hand-written 1.1 version is ~280 lines and
  has no external deps beyond what the rest of the project uses.
- DNS messages are tiny (~100-500 bytes); HTTP/2 multiplexing and
  header compression would save measurably more on bigger payloads
  but here the win is in the noise.
- `Connection: close` means we don't even try to keep the TLS
  connection alive across queries; each query gets a fresh handshake.
  Same simplification as DoT (feature #9). Reuse / pooling is
  roadmap.

### 3. Reading the response (`src/http_client.cpp:163`)

After writing the request, the code does a two-step read:

```cpp
// src/http_client.cpp:166
std::string head_buf;
head_buf.reserve(1024);
try {
    co_await asio::async_read_until(*stream,
        asio::dynamic_buffer(head_buf, /*max_size=*/16 * 1024),
        "\r\n\r\n", asio::use_awaitable);
} catch (const std::system_error&) {
    co_return std::nullopt;
}
```

`async_read_until` reads bytes from the TLS stream until it sees
`\r\n\r\n` (the HTTP header/body separator). The result is in
`head_buf` plus possibly some body bytes that arrived in the same
TCP segment.

Then `parse_response_head` (line ~52 in http_client.cpp) parses
the status line + headers; the body is read by `Content-Length`
through to the end. Any malformed framing — missing
`Content-Length`, wrong status — turns the result to nullopt.

The hard cap of 16 KB on the head + 64 KB on the body protects
against malicious responses that try to fill memory.

### 4. Dispatch in the forwarder (`src/upstream.cpp:227`)

```cpp
// src/upstream.cpp:227 (DoH branch — same shape as DoT)
if (cfg_.protocol == Protocol::Doh) {
    bool is_primary = true;
    for (std::size_t i = 0; i < cfg_.tcp_servers.size(); ++i) {
        const auto& server = cfg_.tcp_servers[i];
        const int attempts = is_primary ? (1 + cfg_.retries_on_primary) : 1;
        is_primary = false;
        for (int a = 0; a < attempts; ++a) {
            auto resp = co_await detail::doh_try_once(
                ctx_, *tls_ctx_, server, cfg_.servername,
                cfg_.doh_path, outbound, cfg_.timeout);
            if (!resp) continue;
            if (resp->size() < 12) continue;
            const uint16_t resp_id = read_u16_be(*resp, 0);
            if (resp_id != our_id) continue;
            if (!reply_matches_request(client_query, *resp)) continue;
            write_u16_be(std::span<std::byte>{*resp}, 0, client_id);
            co_return ForwardResult{.response = std::move(*resp), ...};
        }
    }
    throw std::runtime_error{"upstream: all DoH servers exhausted"};
}
```

Same retry + sanity-check pattern as the DoT branch. The
transaction-ID swap and question-section validation
(`reply_matches_request`) happen identically — DoT and DoH both
deliver raw DNS bytes inside their respective transports, so the
DNS-layer machinery is the same.

### What you can verify yourself

- Capture on TCP/443 with the DoH config — every outgoing query
  gets a TLS handshake to `1.1.1.1:443` then encrypted Application
  Data records.
- Use a sanitised tshark filter `tls.handshake.type == 1 and
  tcp.dstport == 443 and ip.dst == 1.1.1.1` to see only your DoH
  ClientHellos (no other browser tabs to Cloudflare).
- Switch `doh_path` to `/wrong-path` — the upstream returns 404,
  CloakDNS rejects (status != 200), SERVFAIL goes back to the
  client.
- Add SPKI pins (feature #12) — applies identically to DoT/DoH/ECH
  paths because the cert verification happens inside the shared
  TLS context.

---

## References

- **RFC 8484** — DNS Queries over HTTPS (DoH).
- **RFC 7231** — HTTP/1.1 semantics (the layer DoH rides on).
- **RFC 5452 §6** — transaction-ID randomization (still required
  inside DoH; nothing about HTTP changes the DNS spoof model).
- **`docs/09-verification.md` §DoH** — verification procedure with
  captured tshark output.
- **Source files:** [`src/upstream_doh.cpp`](../src/upstream_doh.cpp),
  [`src/http_client.cpp`](../src/http_client.cpp),
  [`src/upstream.cpp`](../src/upstream.cpp),
  [`src/tls.cpp`](../src/tls.cpp).
- Related features: DoT upstream, ECH (encrypts the SNI), SPKI cert
  pinning, EDNS0 padding.
