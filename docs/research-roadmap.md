# Research Roadmap — paper-mandated features beyond the shipped set

This doc is the bridge between the academic literature in [`papers/`](../papers)
and the next wave of CloakDNS features. The 14 shipped features (see
[`features/`](../features)) already cover the core threat model. This is the
*forward-looking* list: things the research says are **necessary**, that the
mainstream blockers (Pi-hole, AdGuard Home, dnscrypt-proxy, Technitium, blocky)
**do not do**, that are achievable **at the DNS layer** — i.e. without shipping
a browser extension, injecting JavaScript, or terminating TLS to inspect page
content.

## How this list was filtered

Every one of the 32 papers in `papers/` was read. Four filters were applied:

1. **DNS-implementable.** A forwarder can block domains/IPs, choose its
   upstream transport, pad/reshape its own packets, normalise timing, inject
   or refuse queries, and enrich its logs. It cannot see a URL path, a
   JavaScript API call, or a canvas readback. Anything needing that is out.
2. **No browser dependency.** No extension, no JS shim, no in-page
   instrumentation, no whole-browser swap. The whole point of DNS-level
   defence is that it runs beneath the browser for every app on the box.
3. **The authors frame it as necessary** — a stated gap, "beyond the
   browser" call, or future work — not merely possible.
4. **Competitors don't already ship it.** Parity features (plain domain
   blocking, CNAME-name uncloaking, DoT/DoH, variable EDNS0 padding) don't
   count even when a paper endorses them.

A note on scope: the **15 browser-fingerprinting papers** (Eckersley/
Panopticlick, AmIUnique, Canvas, FPStalker, PriVaricator, FPGuard, FPScanner,
the Laperdrix survey, PriveShield, BrowserFM, Beyond-the-Crawl, …) produced
**nothing** that survives filters 1–2. Their defences are uniformly
browser-engine changes (canvas/WebGL/audio normalisation, API removal) or
anti-FP browsers (Tor Browser, Brave). Cao 2017 even argues the network/IP
layer is *unsuitable* for fingerprinting. That's an honest finding, not a gap
in the reading — fingerprinting is fought in the browser, tracking
*infrastructure* is fought at DNS.

## Summary

| # | Feature | Primary paper | Type | Competitor gap |
|---|---|---|---|---|
| 1 | Server-side / Conversion-API endpoint blocking | Vekaria SoK 2025 | Blocklist tier | None ship a server-side-CAPI tier |
| 2 | Constant-size "perfect padding" on the upstream leg | Siby NDSS 2020 | Engine feature | Only variable pad-to-multiple exists |
| 3 | Cookie-syncing-hub tier, ranked by fan-out | Englehardt 2016, Acar 2014 | Blocklist tier + ranking | Flat lists only, no syncing-hub priority |
| 4 | DNS decoy / cover-query injection | Brunton & Nissenbaum 2015, AdNauseam 2017 | Engine feature | Nobody injects decoy DNS queries |
| 5 | CNAME uncloaking + resolved-IP reputation | Vekaria SoK 2025 (Safari heuristic) | Engine increment | CNAME *name*-only everywhere |

"Type" matters for planning: items 1 and 3 are mostly **blocklist curation**
(data, shippable today), item 5 is a small **engine increment** on an existing
feature, and items 2 and 4 are **new engine features** that need design and
tests.

---

## 1. Block server-side / Conversion-API tracking endpoints

**The mandate.** Vekaria et al., *SoK: Advances and Open Problems in Web
Tracking* (2025), make this their headline open problem: trackers have shifted
logic from the client to the server, and "companies like Google, Meta, Amazon,
or TikTok have deployed so-called conversion APIs… server-side tracking is hard
to audit as APIs and signals become **undetectable by client-side
mechanisms**" (§10.2). The open question they pose: "How does server-side
tracking work, how can it be effectively detected and mitigated?"

**Why competitors don't have it.** Pi-hole, AdGuard Home, and dnscrypt-proxy
block *client-side* tracker domains pulled from EasyList/EasyPrivacy. None ship
a curated tier for server-side infrastructure: Meta Conversions API ingestion
hosts, server-side Google Tag Manager (sGTM) container subdomains, TikTok
Events API endpoints. This is also the one tracking class **no browser
extension can ever observe** — the data flows server-to-server, never touching
the page.

**DNS implementation.** A priority blocklist tier of CAPI ingestion hosts and
sGTM container subdomains, sinkholed like any other block and tagged in the
structured log (feature 08) as `server-side-endpoint`. When a site fronts its
own sGTM on a first-party subdomain, that subdomain still resolves through the
forwarder — making the resolver one of the only client-controllable choke
points for server-side flows. Pairs naturally with CNAME uncloaking (feature
03): sGTM is frequently reached via a first-party CNAME.

**Status (shipped + attributed):** the `server_side_apis.txt` tier ships and is
loaded as a named `[[blocklist.tier]]`, so a block on a server-side endpoint is
now tagged `"category":"server-side-endpoint"` in the query log. Remaining work
is ongoing curation of new CAPI/sGTM endpoints.

**Effort:** blocklist curation. The category-attribution layer (named tiers +
log tagging) is now in place. Highest strategic value — this is the strongest
"beyond the browser" story CloakDNS can tell.

## 2. Constant-size "perfect padding" on the upstream leg

**The mandate.** Siby et al., *Encrypted DNS ⇒ Privacy? A Traffic Analysis
Perspective* (NDSS 2020), is the load-bearing paper. Its conclusion: "the most
promising approach to protect DoH is to have clients mimicking the
**repacketization** strategies of Tor, without replicating the encryption
scheme or re-routing" (§VIII). The numbers make the case — website-identifying
F1 score under each defence:

| Defence | F1 (lower = better) |
|---|---|
| EDNS0 padding, multiple of 128 B | **0.69** |
| EDNS0 padding, multiple of 468 B | **0.43** |
| "Perfect padding" — every record forced to one fixed size | **0.066** |

The pad-to-a-multiple scheme that CloakDNS (feature 06) and dnscrypt-proxy use
today is the 0.43–0.69 row. The collapse to 0.066 needs *every* message on the
wire to be length-identical.

**Why competitors don't have it.** dnscrypt-proxy and CloakDNS do *variable*
EDNS0 padding — pad up to the next multiple of N. Siby proves that's
insufficient. **Nobody does single global fixed-size repacketization** on the
upstream socket.

**DNS implementation.** The forwarder owns its outbound DoT/DoH socket, so it
can enforce one constant TLS-record size on every query *and* response leg:
pad short messages up to a single global constant, fragment longer ones to the
same boundary. This is a direct upgrade to the existing padding module rather
than a new subsystem. Siby's complementary suggestion (§VIII) — a slimmer DNS
header to make constant-size cells cheaper — only applies on a link CloakDNS
controls both ends of (CloakDNS-to-CloakDNS), so treat it as a later,
optional refinement.

**Effort:** engine feature, low-to-medium risk. Builds directly on a strength
you already have (padding + ECH), and it's the single best-evidenced item here.

## 3. Cookie-syncing-hub tier, ranked by fan-out

**The mandate.** Two papers converge. Englehardt & Narayanan, *Online Tracking:
A 1-Million-Site Measurement* (CCS 2016): 45 of the top 50 third parties sync
cookies; doubleclick.net "shares 108 different cookies with 118 other third
parties"; and the single most promiscuous cookie (**adverticum.net**) "is
synced or leaked to 82 other parties which are collectively present on **752 of
the top 1,000 websites**." Acar et al., *The Web Never Forgets* (CCS 2014),
shows the asymmetry that matters for blocking: a lone respawner is low-impact
(~1.4% of sites), but merchenta.com respawned an ID and "passed it to adnxs.com
through an HTTP redirect sync call," and adnxs.com is on ~11% of sites — so the
damage concentrates at the high-prevalence *receiver*. With back-end merges,
the fraction of parties able to recover >40% of a user's history jumps "from
0.3% to 22.1%."

The decisive property: cookie syncing "enables back-end server-to-server data
merges hidden from public view" — invisible to every client-side tool, visible
to a resolver as a lookup to the hub.

**Why competitors don't have it.** They apply *flat* lists where every entry has
equal priority. None maintain a **prevalence-ranked syncing-hub tier** that
prioritises the high-fan-out *receivers* (adnxs.com, doubleclick.net,
adverticum.net) — the highest-leverage single cut against server-side merges.

**DNS implementation.** A dedicated priority tier (hubs + top receivers) checked
first, carrying a `prominence`/fan-out rank field so the most-promiscuous
receivers can't be dropped from a trimmed list. Optionally, log when one client
emits queries to several known sync endpoints in sequence — a DNS-observable
signature of an ID-passing redirect chain.

**Status (shipped + attributed):** `cookie_syncing.txt` ships as the
`syncing-hub` named tier — blocks carry `"category":"syncing-hub"` — and now
leads with a fan-out-ranked priority-receivers block (doubleclick.net,
adverticum.net, adnxs.com, rubiconproject.com, openx.net). The rank is
documentary ordering, since the engine blocks all-or-nothing.

**Effort:** blocklist curation; the named-tier attribution is in place. A
numeric per-rule rank and the cross-endpoint sync-chain logging remain future
work, and feed the planned Python blocklist updater (CLAUDE.md item 20).

## 4. DNS decoy / cover-query injection

**The mandate.** Brunton & Nissenbaum, *Obfuscation: A User's Guide* (2015),
supply the principle: generate plausible artificial activity so that "it becomes
much more difficult to say of any query that it was a product of human intention
rather than an automatic output" (the TrackMeNot design, §1.4). Howe &
Nissenbaum, *Engineering Privacy and Protest: AdNauseam* (2017), supply the
engineering details — a user-configurable injection rate and the
indistinguishability requirement: "it must be difficult for an adversary to
distinguish injected noise from the data it is attempting to collect."

Why it's *necessary* and not just nice: Siby (item 2) proves padding removes
*size* information but cannot remove *which domains you look up*. Decoy
injection attacks exactly that residual signal, so it's the natural complement
to constant-size padding.

**Why competitors don't have it.** None of Pi-hole, AdGuard Home,
dnscrypt-proxy, Technitium, or blocky inject decoy queries. This is the most
genuinely novel item in the entire corpus.

**DNS implementation.** A rate-limited background task issues realistic dummy
lookups over the same DoH/DoT/DoQ channel as real traffic. The papers double as
a spec, and the guardrails are non-negotiable:

- **Per-instance randomised seed lists** (TrackMeNot-style evolving seeds). A
  shared static decoy pattern becomes a fingerprint the upstream can filter out
  — Brunton & Nissenbaum, §5.3: "a technique that relies on blending in… will
  become far more vulnerable if widely adopted."
- **Human-like timing and a realistic popular-domain distribution**, or the
  decoys are trivially separable from real traffic (indistinguishability).
- **Fire-and-forget responses → null sink.** Decoy answers are never cached and
  never returned to a client. AdNauseam (§III.A) flags the open risk that a
  malicious responder poisons the channel via the decoy's response; reuse the
  existing SPKI-pinned transport (feature 12) and discard the answer.
- **Hard volume cap.** Brunton & Nissenbaum, §4.1: noise that "consumes all
  available resources… becomes a denial-of-service attack." DNS queries are
  tiny, but the decoy stream must be rate-limited and must respect upstream
  limits, or the feature is indefensible.

Ship it as an additive layer beside padding/ECH, never as a standalone privacy
claim — the book is explicit that obfuscation is "an addition to the privacy
toolkit, not a replacement."

**Effort:** new engine feature, medium risk (the design subtleties above are
where it lives or dies). Highest novelty of the five.

## 5. CNAME uncloaking + resolved-IP reputation

**The mandate.** Vekaria's SoK (2025) describes Safari's defence (§5.3.2):
"detects third-party hosts cloaked under first-party subdomains using heuristics
applied to the first-party host's CNAME **and IP address**." The IP half is the
part CloakDNS — and everyone else — currently skips.

**Why competitors don't have it.** Pi-hole's deep-CNAME-inspect and AdGuard
Home both check the CNAME *name* chain only. Neither tests the resolved A/AAAA
IP against known tracker-network ranges. A cloaked tracker whose chain endpoint
isn't on the name blocklist, but whose IP sits inside a tracker's address
space, gets through every one of them.

**DNS implementation.** CloakDNS already walks the CNAME chain (feature 03).
Add a second check: each resolved IP is tested against tracker ASN/CIDR
reputation data, and the response is blocked if **name OR IP** matches. This
turns a current parity feature into a genuine differentiator.

**Effort:** engine increment on existing code, plus an IP-reputation dataset to
ingest and keep fresh.

---

## Honorable mentions

Real, paper-backed, DNS-doable — but narrower in impact than the top five.

- **Evercookie / respawning-vendor tier** (Acar 2014). Named respawning
  infrastructure: `bbcdn-bbnaut.ibillboard.com` (respawned 69 cookies across 24
  sites), `kiks.yandex.ru`, `iovation.com`. The paper's own conclusion is that
  these vectors are *un-blockable in-browser* — "the only way to defend… is to
  clear state on all browsers simultaneously" — which makes cutting the vendor
  at DNS the clean defence. A dedicated tier, not generic ad-block entries.
- **Data-broker / identity-graph tier** (Vekaria 2025 + *Guarding Digital
  Privacy* 2025) with cross-broker correlation logging. Concrete net-new,
  high-precision target surfaced by the reading: **`developer.myacxiom.com`**
  (Acxiom AbiliTec identity-resolution API), alongside LiveRamp IdentityLink and
  Oracle BlueKai / Data Cloud subdomains (allowlist the corporate `oracle.com`).
- **GPC-non-compliance log tagging** (*GPC Compliance at Scale* 2025). Only
  ~44–45% of applicable sites honour Global Privacy Control, and "regulators
  currently do not have any mechanism to audit ad networks' compliance." A
  `gpc_noncompliant: true` field on log entries to known opt-out-ignoring
  infrastructure is a passive audit trail **no competitor produces**. Pure
  logging enrichment on feature 08.
- **One concrete blocklist gap** (FPGuard 2015). CloakDNS lists
  `threatmetrix.com` but not **`online-metrix.net`** (`aa.online-metrix.net`) —
  the ThreatMetrix data-collection CDN where the fingerprint payload actually
  lands. Cheap, high-precision addition to the fingerprinting tier.
- **Oblivious DoH (ODoH) upstream mode** (Siby 2020, §VIII: "more research in
  the direction of Oblivious DNS is needed… so that no parties can become main
  surveillance actors"). Protects against the *resolver itself*, which pinned
  DoT/DoH + ECH does not. Demoted from the top five only because
  dnscrypt-proxy already offers anonymised-relay / ODoH options, so it's not
  fully competitor-absent — but it is new *for CloakDNS*.

## Two caveats

1. **A mislabelled paper.** `papers/25_Hoang_2020_DNS_IP_Fingerprinting.pdf` is
   **not** Hoang et al., "Domain Name Encryption Is Not Enough" (PETS 2020). The
   file is actually *Tik-Tok: The Utility of Packet Timing in Website
   Fingerprinting Attacks* (Rahman et al., PETS 2020) — a Tor timing paper with
   nothing DNS-actionable. CLAUDE.md cites Hoang for IP-based tracking surviving
   encrypted DNS, but that paper isn't in the folder. Fix the citation or add
   the real PDF before leaning on it.
2. **"Achievable" is not uniform.** Items 1 and 3 are blocklist *data* and
   shippable now; item 5 is a small increment on existing code; items 2 and 4
   are new engine features needing design, tests, and (for 4) careful anti-DoS
   and indistinguishability work. All five are within a forwarder's reach — they
   are not equal in effort.

## How these map onto the shipped features

| Roadmap item | Builds on |
|---|---|
| 1 Server-side endpoint blocking | 02 domain blocking, 03 CNAME uncloaking, 08 query log |
| 2 Constant-size padding | 06 EDNS0 padding, 09/10 DoT/DoH transport |
| 3 Syncing-hub tier | 02 domain blocking, blocklist updater (CLAUDE.md #20) |
| 4 Decoy injection | 05 cache+jitter, 09/10 transport, 12 SPKI pinning |
| 5 CNAME + IP reputation | 03 CNAME uncloaking |

## References

Papers cited above (all in [`papers/`](../papers)):

- **24** — Siby et al., *Encrypted DNS ⇒ Privacy? A Traffic Analysis
  Perspective*, NDSS 2020. (Items 2, 4-motivation, ODoH.)
- **28** — Vekaria et al., *SoK: Advances and Open Problems in Web Tracking*,
  2025. (Items 1, 5; data-broker tier.)
- **15** — Englehardt & Narayanan, *Online Tracking: A 1-Million-Site
  Measurement*, CCS 2016. (Item 3; prominence metric.)
- **16** — Acar et al., *The Web Never Forgets*, CCS 2014. (Item 3; evercookie
  tier.)
- **22** — Brunton & Nissenbaum, *Obfuscation: A User's Guide*, MIT Press 2015.
  (Item 4.)
- **20** — Howe & Nissenbaum, *Engineering Privacy and Protest: AdNauseam*,
  2017. (Item 4.)
- **35** — *Guarding Digital Privacy*, 2025. (Data-broker tier;
  `developer.myacxiom.com`.)
- **37** — *Websites' Global Privacy Control Compliance at Scale*, 2025.
  (GPC log tagging.)
- **09** — Faiz Khademi et al., *FPGuard*, DBSec 2015. (`online-metrix.net`
  blocklist gap.)

Related internal docs: [`features/`](../features) (shipped features),
[`docs/02-tracking-background.md`](02-tracking-background.md) (the research that
motivates the core set), [`docs/06-implementation-roadmap.md`](06-implementation-roadmap.md)
(the M0→M13 build order for what already exists).
