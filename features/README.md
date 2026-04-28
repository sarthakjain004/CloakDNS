# CloakDNS feature documentation

One markdown file per shipped feature. Each follows the same shape:

1. **The problem** — what real-world thing this exists to solve, in
   plain English, with a concrete user-impact example.
2. **See it live** — reproducible commands, captured output from
   real runs (every block of "captured output" was actually run on
   the demo machine, not invented).
3. **How it works in code** — the file:line references, code
   excerpts, and explanation needed to understand the
   implementation.

The order below roughly follows the layered architecture: the
basic resolver at the bottom, blocking on top of it, encrypted
upstream above that, the modern privacy layers at the top.

## Index

| # | Feature | What it does |
|---|---|---|
| 01 | [UDP DNS forwarding](01-udp-dns-forwarding.md) | The foundation: receive UDP queries, forward to upstream, return answers |
| 02 | [Domain blocking](02-domain-blocking.md) | Match against blocklists, return synthesised `0.0.0.0` / `::` |
| 03 | [CNAME uncloaking](03-cname-uncloaking.md) | Walk CNAME chains; block if any hop matches a rule |
| 04 | [Allowlist passthrough](04-allowlist-passthrough.md) | Override blocklist for specific names |
| 05 | [TTL cache + jitter](05-ttl-cache-with-jitter.md) | Local cache with TTL rewrite + FP-Radar timing-fingerprinting defence |
| 06 | [EDNS0 padding (RFC 8467)](06-edns0-padding.md) | Pad outgoing queries to fixed block size — defence against traffic analysis |
| 07 | [Hot-reload (SIGHUP / SIGBREAK)](07-hot-reload.md) | Reload blocklist + allowlist without restart |
| 08 | [Structured query log](08-structured-query-log.md) | One JSONL record per query with full action / chain / latency metadata |
| 09 | [DoT upstream (RFC 7858)](09-dot-upstream.md) | Encrypted DNS over TLS to the upstream resolver |
| 10 | [DoH upstream (RFC 8484)](10-doh-upstream.md) | Encrypted DNS over HTTPS — port 443 indistinguishability |
| 11 | [ECH (RFC 9849)](11-ech-encrypted-client-hello.md) | Encrypt the TLS ClientHello so the cleartext SNI no longer leaks |
| 12 | [SPKI cert pinning (RFC 7469)](12-spki-cert-pinning.md) | Pin the upstream's leaf-cert public key — defeats CA mis-issuance |
| 13 | [Abuse-qtype refusal](13-abuse-qtype-refusal.md) | Refuse ANY / AXFR / IXFR / multi-question — kills DNS amplification |
| 14 | [Modern qtype dispatch](14-modern-qtype-dispatch.md) | Forward AAAA / SVCB / HTTPS / CAA / DNSSEC types properly |

## How these were verified

Every "See it live" section in every doc was run end-to-end on a
Windows 11 box on 2026-04-28 against the same MSVC-built
`cloakdns.exe` (with `-DCLOAKDNS_ECH=ON` against FireDaemon
OpenSSL 4.0.0). Captured output is the literal stdout / pcap-
extracted text from those runs, not invented.

After each doc was written, a separate "validate" agent re-read it
against a strict checklist (problem section has a concrete example,
captured output is realistic, code citations match the actual
files, etc.). Docs that failed validation were patched and
re-validated before moving to the next feature.

The orchestration scripts that produce the live-verification
evidence live under [`tools/e2e/`](../tools/e2e/):

- `verify_ech.py` — ECH wire-level harness.
- `reload_test.py` — hot-reload signal smoke.
- `jitter_test.py` — cache-jitter distribution measurement.
- `tier_hit_rates.py` — per-tier catch-rate miner against the E2E
  corpus.
- `sanitizer_replay.py` — Linux-only sanitizer-clean-under-traffic
  replay.

The full verification audit is in
[`docs/09-verification.md`](../docs/09-verification.md).

## What's not yet verified live

Two items remain on the verification roadmap and aren't covered by
docs in this directory:

- **Long-form fuzzing** — the libFuzzer harness in
  `tests/fuzz/fuzz_dns_parser.cpp` does a 60-second smoke per CI
  push; a 24-hour-plus run on a managed corpus is still planned.

That's the single feature on the canonical CLAUDE.md list still
without live evidence. Everything in this directory has both
research grounding (cited papers / RFCs) and observed behaviour on
a real machine.
