# CloakDNS

**A privacy guard that runs on your computer (or home network) and quietly
blocks the companies that track you across apps and websites.**

## What does it actually do?

When you open a website or app, your device first asks "where do I find this
server?" — that lookup is what DNS does. Most apps don't just ask for the
website you wanted. They also ask, in the background, for dozens of trackers,
ad networks, fingerprinters, and analytics services. CloakDNS sits in the
middle of that conversation and refuses to look up the tracker addresses, so
your device never even connects to them. The pages and apps you actually use
still work; the parts that exist only to watch you don't.

You'd run CloakDNS if:

- You want **one setting** that protects every app on your computer, not just
  your browser. Mail clients, system processes, native apps, mobile games —
  all of them go through the same DNS pipe.
- You also want to protect your **phone, smart TV, and IoT devices** on your
  home network. Those devices completely ignore browser ad blockers.
- You want defenses against tricks that **browser ad blockers have given up
  on** — for example, trackers that disguise themselves as part of the site
  you're visiting. (Chrome's 2024 extension API change broke uBlock Origin's
  ability to defeat this trick on Chrome.)
- You'd rather lean on **what privacy researchers have actually measured**
  than on a hand-curated tracker list. Every blocking tier in CloakDNS maps
  back to a published academic paper — see the citations in
  [`CLAUDE.md`](CLAUDE.md#research-justifications).

## What it can't do

CloakDNS blocks the *names* of tracking companies, not the trackers
themselves. So it cannot help with:

- Trackers that share a domain with the website you actually wanted
  (first-party tracking).
- Tracking that happens between two web servers without your device being
  involved (server-to-server APIs like Meta Conversions, TikTok Events).
  CloakDNS does block the **browser-side pixel** that almost every such
  setup also fires — but the pure backend leg is invisible to any local
  defense.
- Fingerprinting that runs entirely inside your browser and never makes a
  DNS request.

For those layers you still want browser tools (uBlock Origin, NoScript, Brave
Shields) or a full proxy. CloakDNS is the network layer that protects
everything else.

## How does it know what to block?

Two sources, kept separate so you can mix them as you like:

1. **Public community blocklists** — the same lists Pi-hole and uBlock use
   (StevenBlack, OISD, EasyList, EasyPrivacy, Peter Lowe's list, NextDNS-CNAME).
   The bundled `tools/update_blocklists.py` script downloads and merges them
   for you on demand.
2. **Research-derived priority tiers** — small, hand-tracked lists in
   `tools/priority_tiers/` where every entry maps to a specific published
   paper (citations in [`CLAUDE.md`](CLAUDE.md#research-justifications)).
   For example, the cookie-syncing tier comes from a 2016 study that
   observed *one tracker cookie being shared with 82 different companies*
   — the sort of source that doesn't show up in a generic blocklist.

Both sources update via the same script.

> **Status:** the resolver core, blocklists, CNAME uncloaking, encrypted
> upstream (DoT, DoH), and opt-in encrypted-ClientHello are all implemented,
> tested, and run as a Linux daemon or Windows service. Some roadmap items
> (DoH/DoT bypass detection, GPC-aware logging, an admin UI) aren't yet
> built — see [Roadmap](#roadmap).

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
  reproduction harness lives at `tools/e2e/verify_ech.py`. AdGuard
  Home's tracking issue for this
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

Compared against the eight closest products (Pi-hole, AdGuard Home, NextDNS,
Blocky, AdGuard public DNS, Brave Shields, uBlock Origin, Safari ITP), the
headline differentiators are:

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
  priority tier in `tools/priority_tiers/` maps to a published paper
  (citations in [`CLAUDE.md`](CLAUDE.md#research-justifications)).
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

Per-feature deep-dives — including the code paths each one walks through
— live in [`features/`](features/) (one numbered doc per feature, 14 in
all).

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
   ./build/cloakdns cloakdns.toml
   ```

   The config path is a positional argument; if omitted, CloakDNS looks
   for `cloakdns.toml` next to the binary or in the current directory.

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
  the parser, blocklist engine, cache, uncloaker, resolver (with fake
  protocol adapters for retry / RFC 5452 ID match / EDNS0 padding), and
  config loader.
- **Fuzzing:** libFuzzer harness in `tests/fuzz/fuzz_dns_parser.cpp`. CI
  runs a 60-second smoke on every PR.
- **Sanitizers:** ASan, UBSan, and TSan all run clean. Linux CI builds two
  matrix variants; macOS builds ASan+UBSan only (Apple Clang has no
  LeakSanitizer).
- **Live wire test:** `tools/e2e/verify_ech.py` boots CloakDNS against the
  defo.ie ECH testbed, captures the upstream TLS handshake with `tshark`,
  and asserts the inner SNI never appears in cleartext. Gated behind the
  `ci:live-net` PR label so external-network flakiness doesn't break
  unrelated PRs.

## Documentation

- [`features/`](features/) — one numbered doc per shipped feature
  (UDP forwarding, blocking, CNAME uncloaking, cache, padding, hot-reload,
  query log, DoT, DoH, ECH, SPKI pinning, qtype handling). Each one walks
  through the relevant code paths.
- [`CLAUDE.md`](CLAUDE.md) — full feature matrix with research
  justifications and the mapping from blocking layers to papers.

## Roadmap

Milestones complete on `main`: M0 (UDP echo) → M20 (ECH). The encrypted
upstream stack — DoT, DoH, and opt-in ECH — landed across PRs #4, #5, #6.
Remaining work:

| ID    | Feature                                                | State |
|-------|--------------------------------------------------------|-------|
| M20.1 | Auto-fetch ECHConfigList from HTTPS DNS RR (qtype 65)  | planned |
| —     | DoH/DoT bypass detection (port 443/853 monitoring)     | planned |
| —     | DNS-over-Tor optional upstream                         | analyzed, deferred |
| —     | GPC-aware logging                                      | planned |
| —     | Tracker-type tagging (Roesner Type A–E)                | planned |
| —     | India-adtech priority tier (mined from E2E sweep)      | planned |

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

The full mapping from each paper to the features it justifies is in
[`CLAUDE.md`](CLAUDE.md#research-justifications).

## License

MIT — see [LICENSE](LICENSE). The third-party dependencies CloakDNS
fetches at build time (Asio, tomlplusplus, GoogleTest) ship under their
own permissive licenses, all compatible with MIT.
