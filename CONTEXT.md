# CloakDNS

CloakDNS is a privacy-focused DNS server: it intercepts queries on a machine or network, blocks tracker domains before connections happen, and resists DNS-based fingerprinting (CNAME cloaking, traffic analysis, encrypted-DNS bypass).

## Language

**Server**:
The CloakDNS daemon. Owns the io_context, listens on UDP/53, wires every other module at startup, handles SIGHUP/SIGBREAK reloads.
_Avoid_: Daemon, Runtime, App, Bootstrap

**Resolver**:
The upstream DNS forwarder. Picks an Adapter (UDP / DoT / DoH / future DoQ / Tor), applies retry, ID rewrite, RFC 5452 question-echo check, and EDNS0 padding once before the Adapter's single-shot send.
_Avoid_: UpstreamForwarder (legacy), Forwarder, Client

**Resolver Adapter**:
A protocol-specific single-shot exchange. Sends one outbound query and returns one `UpstreamReply` or `nullopt`. Owns its own `tls::Context` when the protocol needs one (DoT, DoH); UDP has no TLS state.
_Avoid_: Strategy, Backend, Driver

**Blocklist**:
The set of domains and wildcard patterns whose A/AAAA queries are answered with a synthesized block response. Hot-reloadable via SIGHUP.
_Avoid_: Filter, Denylist

**Uncloaker**:
Walks a CNAME chain hop-by-hop on every query, checking each hop against the **Blocklist**. Stops at the first match or at the depth configured by `uncloak.max_depth`.
_Avoid_: CnameWalker, ChainResolver

**Query Logger**:
The structured JSON log of every query/answer pair (schema-versioned, currently v3). Async-capable; consumed by the analytics dashboard.
_Avoid_: Logger, Recorder

**ECH Config**:
The ECHConfigList bytes used by DoT/DoH **Resolver Adapters** for Encrypted Client Hello. Fetched at startup from the upstream's HTTPS RR (the "ECH Bootstrap") or supplied inline via TOML; hot-swappable via SIGHUP.
_Avoid_: ECHKeys, EchPayload

## Relationships

- A **Server** owns one **Resolver**, one **Blocklist**, one **Uncloaker**, one DNS Cache, and one **Query Logger**.
- A **Resolver** holds 1..N **Resolver Adapters** of one protocol kind.
- An **Uncloaker** delegates each hop to the **Resolver** and checks each result against the **Blocklist**.
- An **ECH Config** lives on a DoT or DoH **Resolver Adapter** and is replaced atomically on SIGHUP.

## Example dialogue

> **Dev:** "Where does the RFC 5452 question-echo check live?"
> **Architect:** "On the **Resolver** — once, after every **Adapter**'s single-shot returns. The Adapter only frames one wire exchange; policy stays in the Resolver."
>
> **Dev:** "What if a CNAME chain crosses three hops?"
> **Architect:** "The **Uncloaker** asks the **Resolver** for each hop's A record. Each result is checked against the **Blocklist**. The Adapter doesn't know about CNAME chains — it just sends one query."

## Flagged ambiguities

- "Forwarder" was used (and still is in legacy code) to mean **Resolver**. Migration: `UpstreamForwarder` → `Resolver` as part of the #1 deepening.
- "Bootstrap" overloaded **Server** startup and **ECH Config** fetching. Resolved: **Server** = the daemon; **ECH Bootstrap** = the HTTPS-RR fetch step.
