# Abuse-qtype refusal (ANY / AXFR / IXFR / multi-question)

CloakDNS uses an explicit **whitelist** of "qtypes a recursive
resolver should plausibly forward" and refuses everything else.
Forbidden qtypes get an immediate `REFUSED` response (RCODE 5);
the upstream is never contacted. The forbidden set: **ANY (255),
AXFR (252), IXFR (251), multi-question messages, and every qtype
not in the whitelist.**

This shuts down a class of low-effort DNS amplification, zone-
transfer probing, and reconnaissance attempts that no recursive-
resolver client legitimately needs.

---

## The problem

Recursive resolvers historically supported a long tail of qtypes —
ANY ("give me every record for this name"), AXFR ("send the entire
zone"), IXFR ("send incremental updates since serial X"). All three
were designed for **authoritative-side** operations:

- ANY was useful when an admin wanted a quick "what records exist
  for this name" diagnostic. Browsers / apps **never** send ANY;
  it's not part of any normal client flow.
- AXFR is the zone-transfer mechanism. A secondary nameserver pulls
  a complete zone from a primary. Normal clients never send AXFR.
- IXFR is the incremental-update mechanism. Same audience — DNS
  operators between two of their own servers.

In a recursive resolver — what CloakDNS is — accepting these qtypes
gets you three problems:

1. **DNS amplification**. ANY responses can be huge (an
   authoritative server might return dozens of records). An
   attacker sends a small "ANY example.com" query with a forged
   source IP and the resolver replies to that forged IP with a
   large answer. Multiplier: 30-50x bytes amplification. Botnets
   used this for years to DDoS targets.
2. **Reconnaissance**. AXFR / IXFR against an open recursive
   leaks zone data the operator probably didn't intend to publish.
3. **Memory/CPU pressure**. ANY responses are large; building them
   exercises a code path that's rarely tested compared to the A /
   AAAA hot path.

CloakDNS handles this defensively:

- **Whitelist, not blacklist.** Anything not explicitly known to
  be a normal client qtype is refused. The whitelist is small
  (A, AAAA, NS, CNAME, SOA, PTR, MX, TXT, SRV, NAPTR, DS, RRSIG,
  NSEC, DNSKEY, SVCB, HTTPS, CAA — the qtypes browsers and OSes
  actually send). New qtypes added to the spec stay refused until
  someone explicitly opts them in.
- **Multi-question messages refused.** A DNS message with more
  than one question in the QUESTION section is malformed in
  practice (the spec allows it but no real client uses it; servers
  treat it as an error). CloakDNS refuses to forward.
- **Refused at qname-decision time, before forwarding.** No
  upstream resolver bandwidth is wasted.

### Concrete user-impact example

Your CloakDNS daemon is exposed to the LAN (i.e. listening on a
non-loopback interface so other devices can use it as their
resolver). A misbehaving guest device — or an opportunistic attack
script that scans for open resolvers — fires:

```
$ dig @your-lan-ip your-domain.com ANY
```

Without the abuse-qtype filter: CloakDNS forwards the ANY upstream,
gets back a potentially large answer, returns it. If the source IP
on the client's UDP packet was forged, you've just reflected
amplified bytes at someone.

With the filter: CloakDNS sees `qtype=255` (ANY), is_forwardable_qtype
returns false, builds a small REFUSED response (no answer section),
sends that 50-byte refusal back. Amplification ratio is ~1:1; the
attack doesn't work.

The flip side: if you ever have a legitimate need for ANY (rare,
diagnostic), you can't use this resolver — you'd have to query the
authoritative server directly. That's by design.

---

## See it live

Run end-to-end on **2026-04-28** with the same UDP-upstream config
used in feature #1.

### Five queries demonstrating the filter

```
$ ./build-msvc/Release/cloakdns.exe cloakdns-feat-udp.toml &

$ dig @127.0.0.1 -p 5354 example.com ANY +notcp +noall +stats
;; Query time: 1 msec
;; SERVER: 127.0.0.1#5354(127.0.0.1) (UDP)

$ dig @127.0.0.1 -p 5354 example.com IXFR=1 +notcp +noall +stats
;; Query time: 0 msec
;; SERVER: 127.0.0.1#5354(127.0.0.1) (UDP)

$ dig @127.0.0.1 -p 5354 example.com AXFR +time=2
;; Connection to 127.0.0.1#5354(127.0.0.1) for example.com failed: connection refused.
;; Connection to 127.0.0.1#5354(127.0.0.1) for example.com failed: connection refused.

$ dig @127.0.0.1 -p 5354 example.org +short
172.66.157.237
```

Reading these:

- **ANY (qtype 255)**: dig got back a REFUSED response. Query time
  1 ms (refused locally, no upstream). The empty `+noall` output
  is dig showing nothing because `dig` filters out the actual
  REFUSED message under that flag set; the daemon stdout (next
  block) confirms what was actually returned.
- **IXFR=1 (qtype 251)**: same. `+notcp` forces UDP. Daemon
  refused.
- **AXFR (qtype 252)**: dig **always** uses TCP for AXFR per RFC
  5936 §4.2 — so it never reaches our UDP-only listener. From
  dig's perspective the "connection refused" is a TCP-level
  rejection (CloakDNS isn't listening on TCP/5354). This works
  out: AXFR is killed by transport mismatch even before our qtype
  filter would catch it.
- **A query**: forwards normally — confirms the filter only
  catches abuse qtypes, not all queries.

### Daemon stdout

```
refuse  example.com  qtype=255
refuse  example.com  qtype=251
forward example.org
```

Two `refuse` lines (qtype 255 = ANY, qtype 251 = IXFR), one
`forward` line for the legitimate A query. AXFR doesn't appear
because it never reached the daemon — it was TCP-only and CloakDNS
has no TCP listener on this port.

### JSONL record for a refused query

```json
{"v":2,"ts":"2026-04-27T19:41:33.115Z","qname":"example.com","qtype":255,"action":"refuse","rule":null,"cname_chain":[],"upstream":null,"latency_ms":0.155,"client":"127.0.0.1:49176"}
```

Notice:

- `"action":"refuse"` — distinct from `"block"` in the log.
- `"qtype":255` — emitted as integer rather than string because the
  daemon's qtype-name table doesn't include 255 (it's deliberately
  not in the whitelist; the table is constructed from forwardable
  types).
- `"upstream":null` — no upstream contacted.
- `"latency_ms":0.155` — sub-millisecond, pure local decision.
- `"cname_chain":[]` — never walked any chain.

---

## How it works in code

Two pieces.

### 1. The forwardable-qtype whitelist (`src/server.cpp:51`)

```cpp
// src/server.cpp:51
// Whitelist of qtypes safe to forward as a recursive-resolver front end.
// Notably excludes ANY (255) and AXFR/IXFR (252/251) — abuse vectors with
// no normal-client use case. Includes only the qtypes a desktop OS or
// browser actually sends.
bool is_forwardable_qtype(uint16_t q) {
    switch (q) {
      case 1:   // A
      case 2:   // NS
      case 5:   // CNAME
      case 6:   // SOA
      case 12:  // PTR
      case 15:  // MX
      case 16:  // TXT
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
      default:
        return false;
    }
}
```

A flat `switch` whitelist. Browsers send A, AAAA, HTTPS (qtype 65
for h3 hint), CNAME (rarely directly but sometimes during chain
follows), MX (mail clients), SRV (some SIP / Matrix clients),
TXT (DKIM-style verification), CAA (TLS clients before connecting).
The DNSSEC types (DS, RRSIG, NSEC, DNSKEY) are present so a stub
resolver running DNSSEC validation can do its work through
CloakDNS.

Anything else — including many newer qtypes — defaults to false.
Adding support means changing one line. The maintenance cost of
"opt-in via whitelist" is much lower than the security cost of
"deny via blacklist that you have to remember to extend."

### 2. The handler refuse path (`src/server.cpp:163`)

```cpp
// src/server.cpp:163
// 1. Reject multi-question and unsupported qtypes (ANY, AXFR, ...)
//    before consulting the blocklist. Chrome never asks these; if
//    something does, it's almost certainly abuse.
if (msg.questions.size() != 1 || !is_forwardable_qtype(qtype)) {
    auto response = build_refused_response(query, msg);
    std::cout << "refuse  " << qname << "  qtype=" << qtype << std::endl;
    log_record(LogAction::Refuse, qname, qtype);
    co_await sock.async_send_to(
        asio::buffer(response), from, use_awaitable);
    co_return;
}
```

Two refuse triggers `OR`'d together:

- **`msg.questions.size() != 1`** — multi-question message. RFC
  1035 §4.1.2 allows the QDCOUNT field to be > 1 but no real-world
  client uses this, and most servers treat it as a parse error.
  Refusing is safer than handling.
- **`!is_forwardable_qtype(qtype)`** — the whitelist check above.

`build_refused_response` (in `src/dns_writer.cpp`) constructs the
response: copies the client's question, sets RCODE to 5 (REFUSED),
sets the QR bit, returns. No answer / authority / additional
sections — REFUSED responses are tiny (~50 bytes) by design,
killing any amplification potential.

### Why we don't blanket-refuse based on qclass

DNS technically supports multiple `class` values (IN, CH, HS, NONE,
ANY) but in practice only IN (the Internet class) is used. We
*could* add a `qclass != IN → refuse` filter; today CloakDNS
forwards anything in the whitelist regardless of class. This is a
trivially low-impact gap (no real client sends non-IN classes)
that's not worth the maintenance burden of a class whitelist.

### Why TCP isn't a listener

CloakDNS only listens on UDP. RFC 7766 says recursive resolvers
"SHOULD" support TCP for queries that don't fit in UDP, but in
practice modern DNS over UDP works fine for almost everything
(EDNS0 lets messages grow up to 4096 bytes; truncated responses
are rare and the OS resolver retries on TCP itself). Not having
a TCP listener has the side benefit that AXFR / IXFR over TCP
literally cannot reach CloakDNS — they fail at the transport layer
without even hitting the qtype filter.

This is also why dig's "Connection refused" message in the AXFR
case isn't CloakDNS rejecting it — it's the OS rejecting the TCP
connect to a port that has no TCP listener.

### What you can verify yourself

- Run any of the abuse qtypes through CloakDNS — see refuse lines
  in the log + JSONL `"action":"refuse"` records.
- Try qtype 6 (SOA) or qtype 16 (TXT) — should forward normally
  because they're in the whitelist.
- Try a deliberately-invalid qtype (e.g. `dig +qid=12345 ... TYPE9999`)
  — refused as expected.

---

## References

- **RFC 1035** — DNS, including the QDCOUNT / QCLASS / QTYPE
  semantics.
- **RFC 8482** — recommends servers respond with HINFO instead of
  ANY answers (the route some authoritative servers take to
  neutralise amplification). CloakDNS goes further by refusing
  ANY upstream entirely.
- **RFC 5936** — DNS Zone Transfer Protocol (AXFR/IXFR
  specification, mandates TCP transport).
- **Source files:** [`src/main.cpp`](../src/main.cpp),
  [`src/dns_writer.cpp`](../src/dns_writer.cpp).
- Related features: domain blocking, structured query log.
