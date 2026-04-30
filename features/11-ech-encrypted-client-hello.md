# Encrypted Client Hello on the outbound link (RFC 9849)

CloakDNS can opt into **Encrypted Client Hello (ECH)** on the TLS
handshake to its upstream resolver. The TLS ClientHello is split
into an outer (cleartext) part containing only a decoy hostname and
an inner (encrypted) part containing the real hostname plus the
client's actual TLS extensions. An on-path observer sees only the
decoy in the cleartext SNI; the real hostname never appears.

This is opt-in (CMake-gated `-DCLOAKDNS_ECH=ON`, requires OpenSSL
4.0+) and is the only privacy layer that closes the SNI-leak gap
left by DoT and DoH.

---

## The problem

You've enabled DoT or DoH (features #9, #10). The DNS query bytes
themselves are encrypted between CloakDNS and the upstream. Done?

Not quite. Open Wireshark and look at any TLS handshake CloakDNS
makes:

```
TLS ClientHello → TCP/853 (or :443)
  Extension: server_name = cloudflare-dns.com  ← cleartext
  Extension: supported_versions = [...]
  Extension: signature_algorithms = [...]
  ... (everything else, including the cipher suite list, is also
       cleartext)
```

The `server_name` extension (RFC 6066) carries the hostname the
client wants to talk to. It's plaintext because the server uses it
to pick the right certificate (different domains on the same IP
need different certs, and the server has to know which domain
*before* the TLS handshake can complete). So even with DoT or DoH,
**the upstream's hostname is still visible to anyone on the path.**

For CloakDNS specifically the leak says "this client uses
cloudflare-dns.com as its DNS resolver" — which combined with
already-public Cloudflare-IP knowledge is enough to identify the
client as a CloakDNS-with-Cloudflare-DoT user. For a regular
HTTPS connection (browser to a website) the equivalent leak is
much worse: every site you visit is recorded by anyone watching
your traffic.

ECH (RFC 9849, finalised early 2025; stable OpenSSL support
shipped April 2026) closes this gap by **encrypting the
ClientHello itself.** It works like this:

1. The server publishes an **ECHConfigList** in DNS (in an HTTPS-
   record SvcParam, key 5). This contains an HPKE public key + a
   "public name" that the server is fine with appearing in
   cleartext.
2. The client looks up the ECHConfigList ahead of time.
3. When opening a TLS connection, the client builds **two**
   ClientHellos:
   - **Outer**: cleartext, contains only a minimal extension set
     and `server_name = <public name from ECHConfigList>`. This is
     the decoy.
   - **Inner**: contains the real hostname and extensions. The
     client encrypts it with HPKE using the server's public key,
     then puts the ciphertext into a new TLS extension
     (`encrypted_client_hello`, ext type `0xfe0d`).
4. The client sends only the outer ClientHello on the wire.
5. The server sees the outer SNI matches its public name, decrypts
   the inner ClientHello using its HPKE private key, and proceeds
   with the inner ClientHello as if it had been the original
   request.

Network observers see only the outer SNI (the public name). The
real hostname is encrypted before any byte leaves the client.

### Concrete user-impact example

You enable DoT to `cloudflare-dns.com` (port 853). Your hotel Wi-Fi
operator can no longer see your DNS queries (they're inside TLS),
but they can see this:

```
your_ip → 1.1.1.1:853 [TLS handshake]
  ClientHello with SNI = cloudflare-dns.com
```

That's enough information to log "this client uses CloakDNS-style
encrypted DNS to Cloudflare" and tag your session.

With ECH enabled (and CloakDNS configured against an upstream that
publishes ECH — e.g. `defo.ie`, the testbed Stephen Farrell
maintains for ECH research), the same observation becomes:

```
your_ip → 213.108.108.101:443 [TLS handshake]
  ClientHello with SNI = cover.defo.ie     ← decoy public name
  Extension: encrypted_client_hello (0xfe0d)
```

The observer can tell you opened TLS to that IP, but not what
hostname was requested. The real hostname (`defo.ie` in the testbed,
or whatever DoH/DoT upstream you're using when ECH adoption catches
up) is encrypted.

The honest caveat (April 2026): **none of the major public DoH/DoT
resolvers publish ECH yet.** Cloudflare, Quad9, Google have all
deployed ECH on their *web* edge (browsers can use ECH when
visiting `cloudflare.com` etc.), but their DNS endpoints
(`cloudflare-dns.com`, `dns.quad9.net`, `dns.google`) don't have
`ech=` SvcParams in their HTTPS records yet. So ECH-on-DoH against
a real upstream is gated on adoption that's still ~1-2 years out.
The CloakDNS implementation works today against `defo.ie` (which
publishes ECH purely for testing) and will work against
production resolvers as soon as they enable it on their DNS
endpoints.

---

## See it live

Run end-to-end on **2026-04-28**. We use `defo.ie:443` as the
upstream because it's the only publicly-accessible host that
currently publishes a real ECH config we can use. The "DoH" layer
on top will fail (defo.ie isn't a DoH server) — that's expected.
What we're verifying is the **TLS-level ECH behaviour**: extension
present in the ClientHello, real hostname not in cleartext SNI.

### Config

```toml
# cloakdns-ech-test.toml
[server]
listen_addr = "127.0.0.1"
listen_port = 5354

[upstream]
protocol     = "doh"
servers      = ["213.108.108.101:443"]
servername   = "defo.ie"
doh_path     = "/dns-query"
timeout_ms   = 4000
padding_block_size = 128

ech_enabled            = true
ech_outer_servername   = "cover.defo.ie"
ech_config_list_b64    = "AMD+DQA8+QAgACDruPRQzL/Iv0RNnTNHFTk0UosjqqpEVpxu1BQU3C7PbwAEAAEAAQANY292ZXIuZGVmby5pZQAA/g0APF0AIAAgDZOrs291bsLHWlBOCh1hnPcpiTiK808fBTV2L8hWlQoABAABAAEADWNvdmVyLmRlZm8uaWUAAP4NADxlACAAIN1gXf0Rb0zGqQ8rLcPwXy+aS97ntf/yUZlze/lqg8xRAAQAAQABAA1jb3Zlci5kZWZvLmllAAA="

[blocklist]
sources = ["blocklists/tier1.txt"]

[cache]
max_entries = 100

[logging]
path  = "cloakdns-ech-test.jsonl"
async = false
```

The new fields:

- `ech_enabled = true` — turn on the ECH path. Daemon refuses to
  start if `ech_supported()` is false (i.e. you didn't build with
  `-DCLOAKDNS_ECH=ON` against OpenSSL 4.0+).
- `ech_outer_servername = "cover.defo.ie"` — the decoy hostname
  that will appear in cleartext SNI. This must match the
  `public_name` baked into the ECHConfigList; defo.ie's
  ECHConfigList specifies `cover.defo.ie` as its public name.
- `ech_config_list_b64` — base64-encoded ECHConfigList. Fetched
  from defo.ie's HTTPS DNS record:

  ```
  $ python tools/e2e/india_adtech_mine.py  # not the right script,
  $ # but tools/e2e/verify_ech.py shows the bootstrap step
  ```

  Effectively: `dig defo.ie TYPE65 @1.1.1.1 +short` returns the
  HTTPS RR, parse out the `ech=` SvcParam value, base64-encode.

### Capture + run

```
$ "/c/Program Files/Wireshark/tshark.exe" -i 5 -w ech-feat.pcap \
    -a duration:10 -f "tcp port 443 and host 213.108.108.101"
$ SSL_CERT_FILE="$(pwd)/cacert.pem" \
    ./build-msvc/Release/cloakdns.exe cloakdns-ech-test.toml &
$ dig @127.0.0.1 -p 5354 example.com +time=4 +tries=1
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 42093
;; Query time: 648 msec
```

`SERVFAIL` is expected — `defo.ie` isn't a DoH server, so the HTTP
POST fails. What we want is what happened *before* that failure:
the TLS handshake with ECH applied.

### What tshark captured

ClientHellos on TCP/443 to `213.108.108.101` carrying the ECH
extension (`0xfe0d`):

```
$ tshark -r ech-feat.pcap -Y "tls.handshake.extension.type == 0xfe0d" \
    -T fields -e frame.number -e tcp.dstport -e tls.handshake.extensions_server_name

5    443    cover.defo.ie
22   443    cover.defo.ie
```

Two ClientHellos in the capture, both:

- on TCP port **443** (HTTPS port — DoH would target this anyway).
- carry TLS extension type **0xfe0d** = `encrypted_client_hello`
  (RFC 9849 §11).
- have **`cover.defo.ie`** in the cleartext `server_name` — the
  configured outer / decoy.

Critically, the inner hostname `defo.ie` (which CloakDNS's
`servername` field set as the real hostname) **never appears as a
cleartext SNI**:

```
$ tshark -r ech-feat.pcap \
    -Y 'tls.handshake.type == 1 and tls.handshake.extensions_server_name == "defo.ie"' \
    -T fields -e frame.number
(empty)
```

Empty result = no ClientHello in the capture had `defo.ie` as its
cleartext server_name. That's the proof — the real hostname is
gone from the wire.

### Defence-in-depth: byte-level scan

The `tools/e2e/verify_ech.py` harness goes one step further: after
filtering by extension and SNI field, it also dumps the raw bytes
of every ClientHello frame and greps for the inner hostname's
literal text. Even if some quirk of the dissector hid the real
hostname from the `extensions_server_name` field, it'd still show
up if the actual bytes contained it. This third assertion has
always come out empty in our runs.

---

## How it works in code

Three pieces.

### 1. Build-time gate (CMake)

ECH is opt-in via a CMake option:

```cmake
# CMakeLists.txt
option(CLOAKDNS_ECH "Encrypted Client Hello — requires OpenSSL 4.0+" OFF)
if(CLOAKDNS_ECH)
    find_package(OpenSSL 4.0 REQUIRED)
else()
    find_package(OpenSSL 3.0 REQUIRED)
endif()
```

Reasons it's opt-in:

- OpenSSL 4.0+ is brand-new (released April 2026); not every
  distro has it yet. A user building against system OpenSSL 3.x
  shouldn't be told "your build is broken."
- ECH on the outbound link only matters if you're going to use
  it. A self-hosted user who's pointing CloakDNS at their own VPS
  doesn't need ECH.
- The compile gate `CLOAKDNS_HAVE_ECH` is what turns on the ECH
  code paths in `tls.cpp`. Without it, ECH-related fields in the
  config silently get rejected at startup (`fatal:
  upstream.ech_enabled = true but this build was compiled
  without ECH support`).

### 2. The TLS-level wiring (`src/tls.cpp:125`)

`configure_ssl_for_connection` is the single helper used by all
three TLS paths (DoT, DoH, anything else). When the config carries
an ECHConfigList AND the build has `CLOAKDNS_HAVE_ECH`, it sets
the per-SSL ECH parameters:

```cpp
// src/tls.cpp:125
bool configure_ssl_for_connection(SSL* ssl,
                                  const ContextConfig& cfg,
                                  const std::string& real_sni) {
    if (!ssl || real_sni.empty()) return false;

#ifdef CLOAKDNS_HAVE_ECH
    if (!cfg.ech_config_list.empty()) {
        // Inner SNI: real hostname; cert verification matches against this
        // post-handshake. Goes inside the ECH-encrypted ClientHello.
        if (SSL_set_tlsext_host_name(ssl, real_sni.c_str()) != 1) {
            ERR_print_errors_fp(stderr);
            return false;
        }
        if (SSL_set1_host(ssl, real_sni.c_str()) != 1) {
            ERR_print_errors_fp(stderr);
            return false;
        }
        // ECHConfigList must be set before the outer-name override so the
        // outer-name validator inside OpenSSL has a config to validate
        // against. Order matters in OpenSSL 4.0+.
        const auto* bytes = reinterpret_cast<const unsigned char*>(
            cfg.ech_config_list.data());
        if (SSL_set1_ech_config_list(ssl, bytes,
                                     cfg.ech_config_list.size()) != 1) {
            ERR_print_errors_fp(stderr);
            return false;
        }
        // Outer SNI (cleartext): the decoy. When unset, OpenSSL uses the
        // public_name embedded in the ECHConfigList. The third arg is the
        // 4.0-introduced no_outer flag — 0 to honor our explicit name.
        if (!cfg.ech_outer_servername.empty()) {
            if (SSL_ech_set1_outer_server_name(ssl,
                    cfg.ech_outer_servername.c_str(), 0) != 1) {
                ERR_print_errors_fp(stderr);
                return false;
            }
        }
        return true;
    }
#endif

    // ECH disabled or unavailable: standard SNI path.
    if (SSL_set_tlsext_host_name(ssl, real_sni.c_str()) != 1) return false;
    if (SSL_set1_host(ssl, real_sni.c_str()) != 1) return false;
    return true;
}
```

Three OpenSSL calls form the ECH setup:

- `SSL_set_tlsext_host_name(ssl, real_sni)` — sets the inner SNI
  (the real hostname). This is the same call used in the non-ECH
  path; with ECH, OpenSSL sticks this value inside the encrypted
  inner ClientHello rather than in the cleartext `server_name`.
- `SSL_set1_host(ssl, real_sni)` — sets the hostname OpenSSL will
  match against the cert SAN list during cert verification. Without
  this, the cert chain would validate but the hostname check
  wouldn't.
- `SSL_set1_ech_config_list(ssl, bytes, len)` — feeds the
  ECHConfigList bytes (as fetched from DNS). OpenSSL parses them,
  picks a config + cipher suite, performs the HPKE encapsulation.
- `SSL_ech_set1_outer_server_name(ssl, outer_sni, 0)` — overrides
  the cleartext SNI from the ECHConfigList's `public_name` to a
  custom value. The `0` is OpenSSL 4.0's `no_outer` flag — passing
  1 instead would suppress the outer SNI entirely.

The order matters: ECHConfigList must be set before
`SSL_ech_set1_outer_server_name`, because the outer-name validator
inside OpenSSL 4.0 wants the parsed config to validate against. Got
that wrong during initial integration; the comment captures the
lesson.

### 3. Wire-flow consequence

Once `configure_ssl_for_connection` returns successfully, the next
`async_handshake` call inside `dot_try_once` /
`post_https_oneshot` automatically does an ECH handshake — there's
no separate ECH-specific code path in DoT/DoH. The ECH flag is
attached to the SSL object and OpenSSL takes care of everything
during the handshake.

If ECH negotiation fails (server doesn't support it, or
ECHConfigList is stale, or the HPKE encrypted blob fails to
decrypt), OpenSSL 4.0 returns an explicit ECH-failure error code
which the surrounding try/catch converts to nullopt → CloakDNS
treats this upstream as exhausted and tries the next.

### Build-time API gating

The compile gate `CLOAKDNS_HAVE_ECH` is set by CMake when
`-DCLOAKDNS_ECH=ON` was passed:

```cmake
# CMakeLists.txt
if(CLOAKDNS_ECH)
    target_compile_definitions(cloak_dns_core PUBLIC CLOAKDNS_HAVE_ECH)
endif()
```

The runtime function `tls::ech_supported()` returns this flag's
value, which the config validator checks at startup:

```cpp
// src/config.cpp ~line 125
if (out.ech_enabled) {
    if (!tls::ech_supported()) {
        fail("upstream.ech_enabled = true but this build was compiled "
             "without ECH support");
    }
    if (out.ech_config_list.empty()) {
        fail("upstream.ech_enabled = true but ech_config_list_b64 is "
             "empty");
    }
}
```

Belt + braces: a binary built without ECH refuses to load a config
that asks for ECH; a binary built with ECH still requires the user
to supply an ECHConfigList (no point claiming ECH if you have no
key).

### What you can verify yourself

- Build with `-DCLOAKDNS_ECH=ON` and capture against `defo.ie:443`
  using the steps above. Both ClientHellos should carry extension
  `0xfe0d`.
- Disable ECH (`ech_enabled = false`), re-capture — extension
  `0xfe0d` is gone, cleartext SNI is now `defo.ie` (the inner) not
  `cover.defo.ie` (the outer).
- Run `tools/e2e/verify_ech.py` for the full automated three-
  assertion harness (extension present, inner SNI never as
  server_name, no inner-hostname bytes anywhere in raw ClientHello
  frames).

---

## References

- **RFC 9849** — TLS Encrypted Client Hello (the spec).
- **RFC 9460** — Service Binding (HTTPS) DNS records (where the
  ECHConfigList is published).
- **`learnings/sni-ech-and-encrypted-dns.md`** — from-scratch
  explanation of SNI and ECH for newcomers to TLS.
- **`learnings/encrypted-upstream-plan.md`** — the architectural
  plan that drove the M19a/M19b/M20 milestones.
- **`docs/09-verification.md` §ECH** — verification procedure with
  captured tshark output.
- **`tools/e2e/verify_ech.py`** — automated wire-level harness.
- **Source files:** [`src/tls.cpp`](../src/tls.cpp),
  [`src/ech_bootstrap.cpp`](../src/ech_bootstrap.cpp),
  [`src/dot_adapter.cpp`](../src/dot_adapter.cpp),
  [`src/doh_adapter.cpp`](../src/doh_adapter.cpp),
  [`src/resolver.cpp`](../src/resolver.cpp) (`Control::swap_ech_config`
  fan-out across Adapters on SIGHUP/reload),
  [`CMakeLists.txt`](../CMakeLists.txt).
- Related features: DoT upstream, DoH upstream, SPKI cert pinning,
  EDNS0 padding.
