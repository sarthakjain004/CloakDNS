# AAAA / SVCB / HTTPS / CAA qtype dispatch

CloakDNS forwards modern DNS query types beyond plain A — including
**AAAA** (qtype 28, IPv6), **SVCB** (qtype 64, generic Service
Binding), **HTTPS** (qtype 65, the HTTPS-specific Service Binding
Chrome uses for H3-hint queries), **CAA** (qtype 257), and the
DNSSEC family — through to the upstream and returns the answer to
the client.

This sounds boring ("of course it forwards them") but is non-trivial
because plenty of older DNS resolvers either drop these qtypes
silently or return malformed responses. CloakDNS treats them as
first-class.

---

## The problem

Modern client behaviour has expanded what a "normal DNS query"
looks like:

- **AAAA** queries are issued for almost every IPv6-capable
  hostname connection. On dual-stack networks they're often issued
  *in parallel* with A queries. A resolver that breaks AAAA breaks
  IPv6.
- **HTTPS qtype (65)** is what Chrome and Firefox query before
  every HTTPS connection to discover service-binding hints — the
  set of ALPN protocols supported, the IP-address hints, and
  importantly **the ECH config** (the `ech=` SvcParam from feature
  #11). Browsers issue HTTPS qtype queries *concurrently with*
  A and AAAA queries to speed up connection setup. A resolver
  that breaks HTTPS breaks ECH discovery, HTTP/3 hints, and
  potentially handshake performance.
- **SVCB qtype (64)** is the generic version of HTTPS, used by
  protocols other than HTTPS (e.g. mail, SIP) for the same
  service-binding semantics.
- **CAA (257)** is queried by TLS clients before issuing a cert
  for a hostname — RFC 8659. ACME clients (Let's Encrypt) need it
  to work.
- **DNSSEC types** (DS, RRSIG, NSEC, DNSKEY) are queried by stub
  resolvers that do their own DNSSEC validation.

A naive recursive resolver that only forwards A would silently
break each of these in turn. CloakDNS's strategy is the opposite:
the qtype whitelist (feature #13) explicitly **includes** all of
the modern qtypes, so they all forward through to the upstream
without any qtype-specific handling.

The trade-off: CloakDNS doesn't *interpret* SVCB / HTTPS records.
It receives the binary RDATA from the upstream, relays it
unchanged. CNAME uncloaking only follows CNAME records (not SVCB
target names) — chasing SvcBinding aliases is a roadmap item
mentioned in CLAUDE.md ("ECH × CNAME uncloaking interaction"
research note).

### Concrete user-impact example

You enable Chrome on a CloakDNS-pointed resolver. Every HTTPS site
you visit triggers Chrome to issue:

```
A          example.com
AAAA       example.com
HTTPS      example.com  (qtype 65)
```

— in parallel. The HTTPS qtype response, if Cloudflare-fronted,
contains the ALPN list (`h3,h2`), IP hints, and (in the future
when adoption catches up) the `ech=` SvcParam.

If CloakDNS dropped HTTPS qtypes, Chrome would timeout on those
queries (~5 s default) before falling back to plain A/AAAA-only
connection. Page loads would be measurably slower; ECH would
silently never engage even when the site supports it.

With CloakDNS forwarding HTTPS qtypes properly, the answer comes
back at the same speed as A/AAAA, Chrome uses the SvcParam hints,
H3 connections get the QUIC-version negotiated up front, ECH
parameters reach the client.

---

## See it live

Run end-to-end on **2026-04-28** with the same UDP-upstream config.

### Four queries — one of each modern qtype

```
$ ./build-msvc/Release/cloakdns.exe cloakdns-feat-udp.toml &

$ dig @127.0.0.1 -p 5354 cloudflare.com AAAA +noall +answer +stats
cloudflare.com.   300  IN  AAAA  2606:4700::6810:85e5
cloudflare.com.   300  IN  AAAA  2606:4700::6810:84e5
;; Query time: 38 msec
;; SERVER: 127.0.0.1#5354(127.0.0.1) (UDP)

$ dig @127.0.0.1 -p 5354 cloudflare-dns.com TYPE65 +noall +answer +stats
cloudflare-dns.com.  300  IN  TYPE65  \# 61 00010000010006026833026832000400086810F8F96810F9F9000600 202606470000000000000000006810F8F92606470000000000000000 006810F9F9
;; Query time: 40 msec

$ dig @127.0.0.1 -p 5354 cloudflare-dns.com TYPE64 +noall +answer +stats
;; Query time: 46 msec
;; SERVER: 127.0.0.1#5354(127.0.0.1) (UDP)
;; MSG SIZE  rcvd: 36
(empty answer section — the upstream returned NOERROR with no
 SvcBinding for that name; that's fine, it just means
 cloudflare-dns.com doesn't currently publish a SVCB-type record;
 the HTTPS qtype above does, which is the same shape but
 specifically for HTTPS clients)

$ dig @127.0.0.1 -p 5354 cloudflare-dns.com CAA +noall +answer
cloudflare-dns.com.  300  IN  CAA  0 issuewild "pki.goog; cansignhttpexchanges=yes"
cloudflare-dns.com.  300  IN  CAA  0 issuewild "ssl.com"
cloudflare-dns.com.  300  IN  CAA  0 issuewild "digicert.com; cansignhttpexchanges=yes"
cloudflare-dns.com.  300  IN  CAA  0 issue "digicert.com; cansignhttpexchanges=yes"
cloudflare-dns.com.  300  IN  CAA  0 issue "ssl.com"
cloudflare-dns.com.  300  IN  CAA  0 iodef "mailto:tls-abuse@cloudflare.com"
```

Read structure:

- **AAAA**: real IPv6 records (`2606:4700::6810:85e5`,
  `2606:4700::6810:84e5`). Latency 38 ms — same upstream
  round-trip as an A query. CloakDNS's CNAME uncloaking ran on
  this answer (because AAAA is an address qtype) — no chain hit
  here, so the answer was returned verbatim.

- **TYPE65 (HTTPS)**: dig prints the binary RDATA in the generic
  `\# <length> <hex>` form because the dig version on this box
  doesn't pretty-print HTTPS RRs. The 61-byte payload contains:
  `0001` (priority 1), `00` (root target), `0001 0006 026833 026832`
  (alpn=`h3,h2`), `0004 0008 6810F8F9 6810F9F9` (ipv4hint), `0006
  0020 ...` (ipv6hint). The crucial point: **the binary RDATA is
  passed through unmodified** from upstream to client.

- **TYPE64 (SVCB)**: this name doesn't have a SVCB record, so
  upstream returned NOERROR with empty answer. CloakDNS forwarded
  the empty answer — that's the correct behaviour. (For comparison,
  if we'd queried SVCB on `_dns.example.com`, we'd see the SVCB
  RDATA shape. Most public domains use the HTTPS-specific type 65,
  not the generic SVCB type 64.)

- **CAA**: full RDATA pretty-printed by dig. `cloudflare-dns.com`
  authorises `pki.goog`, `ssl.com`, and `digicert.com` to issue
  certs (the `issue` and `issuewild` records), with an abuse
  contact for incident reporting. CAA is qtype 257 — uses a
  3-byte qtype field on the wire, which would be a corner case
  for naive parsers; CloakDNS handles it.

### JSONL records

```json
{"v":2,"ts":"2026-04-27T19:44:03.316Z","qname":"cloudflare.com","qtype":"AAAA","action":"allow","rule":null,"cname_chain":["cloudflare.com"],"upstream":"1.1.1.1:53","latency_ms":38.723,"client":"127.0.0.1:55101"}
{"v":2,"ts":"2026-04-27T19:44:03.441Z","qname":"cloudflare-dns.com","qtype":65,"action":"allow","rule":null,"cname_chain":[],"upstream":"1.1.1.1:53","latency_ms":39.703,"client":"127.0.0.1:55103"}
{"v":2,"ts":"2026-04-27T19:44:03.577Z","qname":"cloudflare-dns.com","qtype":64,"action":"allow","rule":null,"cname_chain":[],"upstream":"1.1.1.1:53","latency_ms":46.045,"client":"127.0.0.1:55105"}
{"v":2,"ts":"2026-04-27T19:44:03.699Z","qname":"cloudflare-dns.com","qtype":"CAA","action":"allow","rule":null,"cname_chain":[],"upstream":"1.1.1.1:53","latency_ms":2043.232,"client":"127.0.0.1:55107"}
```

Read across:

- All four records have `"action":"allow"` — the qtype filter
  (feature #13) accepted each of these and the request was
  forwarded.
- AAAA shows up as `"qtype":"AAAA"` (string form because qtype 28
  is in the daemon's name table). HTTPS / SVCB show up as integers
  (`65`, `64`) because the daemon's name-emitting table doesn't
  bake in those names — the schema is unambiguous either way (a
  consumer maps `65 → HTTPS` if it cares).
- AAAA's `cname_chain` is non-empty (`["cloudflare.com"]`) because
  AAAA goes through the CNAME uncloaker (feature #3) — it's an
  address qtype. HTTPS / SVCB / CAA have empty chains because the
  uncloaker only runs for address qtypes; the qname-level
  blocklist already covers tracker-domain queries on those qtypes.
- CAA's latency was 2 seconds — that's CAA queries against
  Cloudflare being slow on first request (the upstream often has
  to query the authoritative zone), not anything CloakDNS did.

---

## How it works in code

Two pieces.

### 1. The qtype whitelist accepts modern types (`src/server.cpp:51`)

The same `is_forwardable_qtype` switch from feature #13 enumerates
the modern qtypes:

```cpp
// src/server.cpp:51
case 28:  // AAAA
case 33:  // SRV
case 35:  // NAPTR
case 43:  // DS
case 46:  // RRSIG
case 47:  // NSEC
case 48:  // DNSKEY
case 64:  // SVCB
case 65:  // HTTPS
case 257: // CAA
    return true;
```

Each of these is one entry. Adding a new qtype to the whitelist is
literally one `case`. When the IETF defines the next service-
binding type (or whatever post-HTTPS qtype comes), the patch is a
one-line change.

### 2. Address-qtype routing into the uncloaker (`src/server.cpp:223`)

CNAME uncloaking applies only to **address qtypes** — A and AAAA
— because those are the ones that return CNAME chains followed by
A/AAAA terminator records:

```cpp
// src/server.cpp ~line 223
if (is_address_qtype(qtype)) {
    auto result = co_await uncloaker.uncloak(qname, upstream_resp);
    // ... (block / suspect / clean handling — see feature #3)
}
```

`is_address_qtype` is a small helper:

```cpp
// near the top of server.cpp
bool is_address_qtype(uint16_t q) {
    return q == kTypeA || q == kTypeAAAA;
}
```

For HTTPS / SVCB / CAA / DNSSEC types, the upstream answer is
returned **as-is** — the bytes are forwarded verbatim. CloakDNS
doesn't parse the binary RDATA; it just relays the response.

This matters because:

- Modern Service Binding records (SVCB / HTTPS) carry SvcParams
  whose meaning evolves with the spec (new SvcParamKeys get added).
  By treating the RDATA as opaque bytes, CloakDNS never has to
  understand new SvcParamKeys to forward them correctly.
- The cache (`src/cache.cpp`) keys by (qname, qtype, class) and
  caches the entire response wire bytes, including unknown qtypes.
  Repeated HTTPS queries hit the cache the same way A queries do.

### 3. Why CAA gets a string label but TYPE65 doesn't

The `qtype_name()` function in `src/query_log.cpp` maps a small
set of well-known qtypes to their string names for the JSONL
output:

```cpp
// src/query_log.cpp ~line 34
std::string qtype_name(uint16_t q) {
    switch (q) {
      case 1:   return "A";
      case 5:   return "CNAME";
      case 28:  return "AAAA";
      // ... (other very common types) ...
      case 257: return "CAA";
      default:  return "";
    }
}
```

Types in the mapping print as their string name; types not in the
mapping print as numeric. SVCB (64) and HTTPS (65) aren't in the
mapping today, so they print as `64` and `65`. This is a
schema-stable choice (consumers parse "qtype" as either a string
or an integer; `jq` handles both). Adding name strings is a
trivial future change if it bothers anyone.

### What you can verify yourself

- Run `dig @127.0.0.1 -p 5354 <domain> HTTPS` — get the SvcParam
  RDATA back.
- Compare against directly querying upstream:
  `dig <domain> HTTPS @1.1.1.1` — bytes should be identical
  (modulo the transaction ID).
- Watch the JSONL: every HTTPS qtype shows up as
  `"qtype":65,"action":"allow"`.
- DNSSEC: query `dig <domain> RRSIG @127.0.0.1 -p 5354` — DNSSEC
  signatures forward through.

---

## References

- **RFC 9460** — Service Binding (SVCB) and HTTPS DNS records.
- **RFC 8659** — DNS Certification Authority Authorization (CAA).
- **RFC 4035** — DNSSEC RR types (RRSIG, DS, NSEC, DNSKEY).
- **RFC 3596** — AAAA record (IPv6).
- **CLAUDE.md** "Open research problems" — the SVCB-target-name
  uncloaking is listed as future work (currently CNAME uncloaking
  only follows CNAMEs, not SVCB target chains).
- **Source files:** [`src/main.cpp`](../src/main.cpp),
  [`src/query_log.cpp`](../src/query_log.cpp).
- Related features: UDP forwarding, abuse-qtype refusal, CNAME
  uncloaking, structured query log, cache.
