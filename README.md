# CloakDNS

A DNS-level tracker and ad blocker written in modern C++20. CloakDNS sits in
front of your machine's resolver, drops queries to known tracker, ad, and
fingerprinting domains before any TCP connection is opened, and follows CNAME
chains so trackers cloaked as first-party subdomains don't slip past.

CloakDNS targets gaps that browser extensions can't close: CNAME-cloaked
tracking that browsers see as first-party, the client-side pixel leg of
server-side conversion APIs (Meta CAPI, TikTok Events, sGTM — pure
backend-to-backend traffic is outside any local DNS's reach, but most
deployments fire a browser pixel in parallel that we do block), and
non-browser apps (smart TVs, IoT, native apps) that an extension never sees.
The feature set is grounded in published web-tracking research rather than a
hand-written tracker list — every blocking layer maps to a paper in
`papers/`. See [`CLAUDE.md`](CLAUDE.md) for the full feature matrix and
research justifications.

> **Status:** in active development. The resolver core (M0–M12) plus the
> encrypted upstream stack — DoT, DoH, and opt-in ECH (M19a, M19b, M20) —
> is implemented, tested, and runs as a Linux daemon / Windows service.
> Some roadmap items (DoH/DoT bypass detection, GPC-aware logging, admin
> UI) are not yet shipped — see [Roadmap](#roadmap).

## Features

Implemented on `main`:

- **Bounds-checked DNS parser** — handles the wire format (queries, answers,
  CNAME chains, EDNS OPT records) with no heap escapes from malformed input;
  fuzzed with libFuzzer.
- **Blocklist engine** — exact, suffix-wildcard (`*.tracker.com`), and regex
  rules over a unified hash + suffix-trie matcher.
- **Curated priority tiers** — research-cited rules for cookie-syncing hubs,
  fingerprinting providers, CNAME-cloaking domains, data brokers, email
  trackers, and server-side conversion APIs in `tools/priority_tiers/`.
- **Federated blocklist updater** — Python tool (`tools/update_blocklists.py`)
  merges and deduplicates StevenBlack, OISD, EasyList, EasyPrivacy, Peter
  Lowe's list, NextDNS-CNAME, and any feeds enabled in
  `tools/blocklist_sources.toml`.
- **CNAME uncloaking** — recursively resolves CNAME chains (RFC 1034 depth
  limit) and blocks if any hop matches the blocklist.
- **TTL-aware response cache** — LRU eviction, periodic sweep, TTL rewrite at
  read time, and configurable jitter to defend against the FP-Radar
  DNS-timing fingerprinting vector (PETS 2022).
- **EDNS0 padding** — pads outgoing queries to a configurable block size
  (RFC 8467) to reduce DoH/DoT traffic-analysis surface.
- **Encrypted upstream — single binary, no sidecar** — native DoT
  (RFC 7858) and DoH (RFC 8484) over OpenSSL with SPKI cert pinning
  (RFC 7469). EDNS0 padding is applied before encryption. Pi-hole and
  Blocky still require a `cloudflared` / `stubby` / Unbound sidecar for
  the same job (and Pi-hole's documented cloudflared path is being
  deprecated after Feb 2026).
- **Opt-in Encrypted Client Hello on the outbound link (RFC 9849)** —
  encrypts the upstream TLS ClientHello so an on-path observer can't see
  which upstream we're speaking to. CMake-gated against OpenSSL 4.0+.
  Live-verified on 2026-04-27 against the `defo.ie` ECH testbed: the
  outgoing ClientHello carries TLS extension `0xfe0d`, the cleartext
  SNI shows the configured outer name (`cover.defo.ie`), and the inner
  hostname (`defo.ie`) never appears in cleartext on the wire. A
  reproduction harness lives at `tools/e2e/verify_ech.py` (manual run —
  not yet wired into CI because the runners don't provision OpenSSL
  4.0 or privileged `tshark`). AdGuard Home's tracking issue for this
  ([#2558](https://github.com/AdguardTeam/AdGuardHome/issues/2558)) is
  still open; among the major self-hosted DNS sinkholes, CloakDNS
  appears to be the first to ship this.
- **AAAA / SVCB / HTTPS dispatch** — Chrome's H3 hint queries (qtype 65) are
  forwarded; abuse vectors (ANY, AXFR, IXFR) are dropped.
- **Hot-reload** — `SIGHUP` (POSIX) / `SIGBREAK` (Windows) re-reads the
  blocklist and config without dropping in-flight queries.
- **Structured query log** — one JSON line per query with timestamp, qname,
  qtype, action (allowed / blocked / nxdomain / refused), CNAME chain, and
  upstream latency. Optional client-IP redaction via FNV-1a hash.
- **Service deployment** — systemd unit (`deploy/cloakdns.service`) and
  Windows Service installer (`deploy/install-windows.ps1`).

## How CloakDNS compares

A 2026-04-27 sweep of the eight closest products (Pi-hole, AdGuard Home,
NextDNS, Blocky, AdGuard public DNS, Brave Shields, uBlock Origin, Safari
ITP) is in `learnings/competitive-positioning.md`. Headline differentiators
that hold up against that field:

- **Single-binary encrypted upstream.** Pi-hole v6 (April 2026) still
  requires a `cloudflared` / Unbound / stubby sidecar for DoH/DoT;
  CloakDNS does both natively in one binary, like AdGuard Home and
  Blocky.
- **ECH on the outbound link.** Among self-hosted DNS sinkholes, no
  competitor we found ships ECH on the resolver's outbound TLS today.
  NextDNS's ECH is server-side (clients → NextDNS) and does not help
  self-hosted setups.
- **CNAME uncloaking matters more than it used to.** uBlock Origin's
  CNAME uncloaking is Firefox-only; Chrome's Manifest V3 transition
  (completed late 2024) removed the API gorhill needs. For the Chrome
  majority a CNAME-aware system DNS is the only remaining defence.
- **Research-grounded blocklist with paper-level provenance.** Every
  priority tier in `tools/priority_tiers/` maps to a paper in `papers/`.
  Per-rule provenance in logs is on the roadmap and would be unique
  among the eight.
- **Cache TTL jitter as a DNS-timing-fingerprinting defence.** Cited
  from FP-Radar (PETS 2022); none of the competitors expose this.

Areas where competitors are still ahead and CloakDNS should close the
gap: web admin UI (Pi-hole, AGH), per-client policies (AGH), Prometheus
metrics (Blocky), mobile encrypted-DNS profile generation (AGH,
NextDNS).

## Architecture

```
       UDP/53 (or :5354 unprivileged)
                │
        ┌───────▼────────┐
        │   listener     │  Asio coroutine, parses + dispatches
        └───────┬────────┘
                │
        ┌───────▼────────┐
        │   blocklist    │  exact / suffix / regex match
        └───┬─────────┬──┘
       hit  │         │  miss
            ▼         ▼
       ┌────────┐  ┌──────────┐
       │ block  │  │  cache   │  TTL-aware, jittered
       │ NXDom  │  └────┬─────┘
       └────────┘       │ miss
                        ▼
                 ┌──────────────┐
                 │  uncloaker   │  CNAME chain → blocklist re-check
                 └──────┬───────┘
                        │
                 ┌──────▼───────┐
                 │   upstream   │  UDP/53 to 1.1.1.1 / 9.9.9.9
                 └──────────────┘
```

A walkthrough of every module is in [`docs/03-architecture.md`](docs/03-architecture.md).

## Requirements

- **C++20** compiler — Clang ≥ 15, GCC ≥ 13, MSVC 2022 (17.5+), or Apple
  Clang (Xcode 15+).
- **CMake** ≥ 3.25.
- **Ninja** recommended; Visual Studio 2022 generator works on Windows.
- **Python** 3.10+ for `tools/update_blocklists.py`.

Asio (header-only) and tomlplusplus are fetched automatically by CMake.

## Build

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Sanitizer-clean builds are supported via `-DCLOAKDNS_SANITIZE=<mode>`:

```bash
# AddressSanitizer + UndefinedBehaviorSanitizer
cmake -S . -B build-asan -DCLOAKDNS_SANITIZE=asan+ubsan
cmake --build build-asan -j
ctest --test-dir build-asan --output-on-failure

# ThreadSanitizer (separate build dir; cannot mix with ASan)
cmake -S . -B build-tsan -DCLOAKDNS_SANITIZE=tsan
```

On Windows, `build-msvc.bat` configures and builds with the Visual Studio 2022
generator.

## Quick start

1. Fetch a merged blocklist (optional; the priority tiers ship in-tree):

   ```bash
   python tools/update_blocklists.py
   ```

2. Run the resolver. With the bundled `cloakdns.toml` it listens on
   `127.0.0.1:5354` (unprivileged), so no `sudo` is needed for a smoke test:

   ```bash
   ./build/cloakdns --config cloakdns.toml
   ```

3. Verify it blocks a known tracker and resolves a clean name:

   ```bash
   dig @127.0.0.1 -p 5354 doubleclick.net   # → 0.0.0.0 (blocked)
   dig @127.0.0.1 -p 5354 example.com       # → upstream answer
   ```

4. Point your OS resolver at CloakDNS. To bind privileged port 53, run as a
   service (see [Deployment](#deployment)) and set `listen_port = 53` in
   `cloakdns.toml`.

## Configuration

`cloakdns.toml` controls the listener, upstream resolvers, blocklist and
allowlist sources, cache, CNAME chain depth, and logging. The shipped file is
self-documenting; the full schema lives in
[`include/cloakdns/config.hpp`](include/cloakdns/config.hpp). A typical setup:

```toml
[server]
listen_addr = "127.0.0.1"
listen_port = 53

[upstream]
servers            = ["1.1.1.1:53", "9.9.9.9:53"]
timeout_ms         = 2000
padding_block_size = 128       # RFC 8467 EDNS0 padding

[blocklist]
sources = [
    "blocklists/tier1.txt",
    "tools/priority_tiers/fingerprinting.txt",
    "tools/priority_tiers/cname_cloaking.txt",
    "tools/priority_tiers/cookie_syncing.txt",
    "blocklists/merged.txt",   # written by update_blocklists.py
]

[cache]
max_entries   = 50000
jitter_max_ms = 5              # FP-Radar timing-fingerprint defense

[logging]
path  = "cloakdns-queries.jsonl"
async = true
```

Reload the blocklist and config without restarting:

- **Linux / macOS:** `kill -HUP <pid>`.
- **Windows:** `CTRL_BREAK_EVENT` to a daemon launched with
  `CREATE_NEW_PROCESS_GROUP`. The Win32 `GenerateConsoleCtrlEvent` API
  only delivers events to processes in the same console group, so a
  plain `taskkill` won't reach the daemon. The verifier at
  `tools/e2e/reload_test.py` is the canonical reference — it launches
  cloakdns with the right `creationflags` and calls
  `p.send_signal(signal.CTRL_BREAK_EVENT)`.

## Deployment

- **Linux (systemd):** copy `deploy/cloakdns.service`, `cloakdns.toml`, and
  the binary into place; `systemctl enable --now cloakdns`.
- **Windows:** run `deploy/install-windows.ps1` from an elevated shell. It
  registers the service, hardens ACLs on the config and log directories, and
  starts it.

Listening on port 53 needs `CAP_NET_BIND_SERVICE` (Linux) or membership in
the appropriate service account (Windows). The installers handle this; for
ad-hoc use, run on `:5354` and either iptables-redirect or use a stub
resolver pointing at CloakDNS.

## Testing

- **Unit + integration:** GoogleTest under `tests/`, run via `ctest`. Covers
  the parser, blocklist engine, cache, uncloaker, upstream forwarder, and
  config loader.
- **Fuzzing:** libFuzzer harness in `tests/fuzz/fuzz_dns_parser.cpp`. CI runs
  a 60-second smoke; for longer corpus runs see
  [`docs/05-dev-setup.md`](docs/05-dev-setup.md).
- **Sanitizers:** ASan, UBSan, and TSan all run clean. Linux CI builds two
  matrix variants; macOS builds ASan+UBSan only (Apple Clang has no
  LeakSanitizer).
- **End-to-end captures:** `results/E2E_*.md` records real-traffic runs
  (Chrome on Windows, India top-100 sweep). Capture-mining notes are in
  `learnings/`.

## Documentation

- [`docs/01-dns-primer.md`](docs/01-dns-primer.md) — DNS protocol from the
  ground up.
- [`docs/02-tracking-background.md`](docs/02-tracking-background.md) — the
  tracking research behind the feature set.
- [`docs/03-architecture.md`](docs/03-architecture.md) — module-by-module.
- [`docs/04-cpp-stack.md`](docs/04-cpp-stack.md) — C++20, Asio, modern CMake,
  GoogleTest patterns used.
- [`docs/05-dev-setup.md`](docs/05-dev-setup.md) — toolchain, sanitizers,
  port-53 gotchas.
- [`docs/06-implementation-roadmap.md`](docs/06-implementation-roadmap.md) —
  ordered milestones with acceptance criteria.
- [`learnings/`](learnings/) — postmortems and design notes from real
  implementation problems (Windows `WSAECONNRESET`, Apple libc++
  portability, Safari ITP cross-eTLD+1 detection, federated blocklist
  refresh, DNS-over-Tor tradeoff analysis).

## Roadmap

Milestones complete on `main`: M0 (UDP echo) → M20 (ECH). The encrypted
upstream stack — DoT, DoH, and opt-in ECH — landed across PRs #4, #5, #6.
Remaining work:

| ID    | Feature                                                | State |
|-------|--------------------------------------------------------|-------|
| M20.1 | Auto-fetch ECHConfigList from HTTPS DNS RR (qtype 65)  | planned |
| —     | DoH/DoT bypass detection (port 443/853 monitoring)     | planned |
| —     | DNS-over-Tor optional upstream                         | analyzed, deferred (see `learnings/dns-over-tor-tradeoff.md`) |
| —     | GPC-aware logging                                      | planned |
| —     | Tracker-type tagging (Roesner Type A–E)                | planned |
| —     | India-adtech priority tier (mined from E2E sweep)      | planned |
| —     | License selection (currently unspecified)              | planned |

Limitations DNS blocking cannot fix (first-party tracking, server-to-server
joins, behavioral biometrics, shared-CDN trackers) are documented in
[`CLAUDE.md`](CLAUDE.md#what-dns-blocking-cannot-stop-known-limitations).

## References

The feature set is grounded in:

- Siby et al., *Encrypted DNS → Privacy?* (NDSS 2020)
- Vekaria et al., *SoK: Web Tracking* (2025)
- Englehardt & Narayanan, *OpenWPM 1M Census* (CCS 2016)
- Acar et al., *The Web Never Forgets* (CCS 2014)
- Roesner et al., *Detecting and Defending Against Third-Party Tracking*
  (NSDI 2012)
- Dao et al., *CNAME Cloaking* (IEEE TNSM 2021)
- *Cascading Spy Sheets* (NDSS 2025)
- FP-Radar (PETS 2022)

PDFs live in [`papers/`](papers/). The full mapping from each paper to the
features they justify is in [`CLAUDE.md`](CLAUDE.md#research-justifications).

## License

Not yet specified. The third-party dependencies CloakDNS fetches at build
time (Asio, tomlplusplus, GoogleTest) ship under their own permissive
licenses.
