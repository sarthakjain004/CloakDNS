# Structured query log

Every DNS query CloakDNS handles produces one JSON record on a
single line in a configured `.jsonl` (JSON-lines) file. Each record
captures: when, what, which action was taken, which rule (if any)
matched, the CNAME chain (if any), which upstream answered, the
daemon-side latency, and which client asked.

The result is a queryable forensic log of every DNS decision the
daemon ever made — feedable to `jq`, ingestable by SIEM tools,
analysable in pandas, replayable into the tier hit-rate miner.

---

## The problem

Most DNS resolvers either log nothing (the OS resolver), log
everything but in their own opaque format (Pi-hole's FTL DB), or
log to a vendor-controlled cloud you can't fully audit (NextDNS).

For research, debugging, or just understanding what's happening on
your network, you want a log that is:

- **Per-query**, not aggregate. You want to be able to ask "which
  trackers did my phone hit while I was on cnn.com?" and answer
  that exactly.
- **Structured**, not free-form text. You want to query it without
  writing regex.
- **Local**, not phoned home to a vendor.
- **Stable schema**, so a script you write today still works in 6
  months.

CloakDNS's JSONL log gives you all four. One JSON object per line,
schema-versioned, written to a path you choose, never sent anywhere.

### Concrete user-impact example

You notice an Android app on your phone is making weird outbound
connections at 3 a.m. Your phone is configured to use CloakDNS as
its resolver.

You can answer "what did this device ask for between 3:00 and 3:05
last night?" with one shell pipeline:

```
$ jq -r 'select(.client | startswith("192.168.1.42:") and .ts > "2026-04-28T03:00" and .ts < "2026-04-28T03:05") | "\(.ts) \(.action) \(.qname)"' \
       cloakdns-queries.jsonl
2026-04-28T03:01:14.221Z block doubleclick.net
2026-04-28T03:01:14.450Z allow cdn.heyvideoz.example
2026-04-28T03:01:14.612Z allow api.heyvideoz.example
... etc
```

That's a forensic-grade trace of the device's behaviour. No vendor
involved; the data lives on your machine. If you're doing privacy
research, the same file is a clean dataset for tier hit-rate
analysis (the verification round in this project did exactly that
across the 1,217 unique hosts in `results/E2E/*/visits.jsonl`).

The same log feeds the tier-hit-rate miner
(`tools/e2e/tier_hit_rates.py`) which converts your priority tiers
from "list with research justification" to "list with measured
catch rate against your own browsing."

---

## See it live

Run end-to-end on **2026-04-28**.

### Config

```toml
# cloakdns-feat-log.toml
[server]
listen_addr = "127.0.0.1"
listen_port = 5354

[upstream]
protocol     = "udp"
servers      = ["1.1.1.1:53"]
timeout_ms   = 3000

[blocklist]
sources = ["blocklist-feat-log.txt"]

[cache]
max_entries = 100

[logging]
path  = "cloakdns-feat-log.jsonl"
async = false
```

`blocklist-feat-log.txt` (two rules so we can demonstrate uncloaking
on a real CNAME chain):

```
0.0.0.0 doubleclick.net
0.0.0.0 edgekey.net
```

The `async = false` setting means the logger writes synchronously
inside the request-handling coroutine. The other mode (`async =
true`) hands records to a background writer thread for higher
throughput; either way the schema and ordering guarantees are the
same.

### Trigger one query of every action type

```
$ ./build-msvc/Release/cloakdns.exe cloakdns-feat-log.toml &
$ dig @127.0.0.1 -p 5354 example.com +short          # 1) allow
172.66.147.243

$ dig @127.0.0.1 -p 5354 example.com +short          # 2) cached
172.66.147.243

$ dig @127.0.0.1 -p 5354 doubleclick.net +short      # 3) block
0.0.0.0

$ dig @127.0.0.1 -p 5354 www.washingtonpost.com +short  # 4) uncloak
0.0.0.0

$ dig @127.0.0.1 -p 5354 example.com ANY +notcp      # 5) refuse
;; ->>HEADER<<- opcode: QUERY, status: REFUSED, ...
```

Then ~30 more `dig host1.example.org` ... `dig host30.example.org`
to overflow the ofstream's ~4 KB buffer (so the records flush to
disk while the daemon is still alive — the daemon flushes on
buffer overflow or graceful shutdown; a hard `taskkill /F` would
lose unflushed records).

### The first six records

```json
{"v":2,"ts":"2026-04-27T19:23:52.957Z","qname":"example.com","qtype":"A","action":"allow","rule":null,"cname_chain":["example.com"],"upstream":"1.1.1.1:53","latency_ms":8.182,"client":"127.0.0.1:65087"}
{"v":2,"ts":"2026-04-27T19:23:53.027Z","qname":"example.com","qtype":"A","action":"cached","rule":null,"cname_chain":[],"upstream":null,"latency_ms":15.591,"client":"127.0.0.1:65089"}
{"v":2,"ts":"2026-04-27T19:23:53.107Z","qname":"doubleclick.net","qtype":"A","action":"block","rule":"doubleclick.net","cname_chain":[],"upstream":null,"latency_ms":0.090,"client":"127.0.0.1:65090"}
{"v":2,"ts":"2026-04-27T19:23:53.171Z","qname":"www.washingtonpost.com","qtype":"A","action":"uncloak","rule":"edgekey.net","cname_chain":["www.washingtonpost.com","50992.edgekey.net"],"upstream":"1.1.1.1:53","latency_ms":49.896,"client":"127.0.0.1:65091"}
{"v":2,"ts":"2026-04-27T19:23:53.303Z","qname":"example.com","qtype":255,"action":"refuse","rule":null,"cname_chain":[],"upstream":null,"latency_ms":0.165,"client":"127.0.0.1:65093"}
{"v":2,"ts":"2026-04-27T19:23:53.402Z","qname":"host1.example.org","qtype":"A","action":"allow","rule":null,"cname_chain":["host1.example.org"],"upstream":"1.1.1.1:53","latency_ms":44.088,"client":"127.0.0.1:65094"}
```

Each line is a complete JSON object. Read field by field, here's
what's in each record:

| Field | Type | Meaning |
|---|---|---|
| `v` | int | Schema version. Currently `2`. Will be bumped when the field set changes. |
| `ts` | RFC 3339 string | Wallclock timestamp when the query was received (UTC). |
| `qname` | string | The name asked for, lower-cased. |
| `qtype` | string OR int | `"A"`, `"AAAA"`, `"HTTPS"`, etc. for known qtypes. Numeric (e.g. `255`) for any qtype CloakDNS doesn't know by name — note record 5: `"qtype":255` because qtype 255 = ANY, which CloakDNS deliberately doesn't include in its name table since it never forwards ANY. |
| `action` | string | One of `allow`, `block`, `cached`, `uncloak`, `refuse`, `suspicious`, `servfail`. |
| `rule` | string OR null | The matching blocklist suffix, or `null` if no rule fired. |
| `cname_chain` | array of strings | The hostname trail walked while resolving (qname-only for direct queries; multi-hop for uncloaked chains). Empty array when the query didn't trigger a chain walk (block, cached, refuse). |
| `upstream` | string OR null | `"<host>:<port>"` of the upstream that answered, or `null` for actions that didn't contact upstream (block, refuse). |
| `latency_ms` | float | Daemon-side wall time from query receipt to response sent. |
| `client` | string | `"<ip>:<port>"` of the client that asked. Optional FNV-1a hash redaction is available via `redact_client = true`. |

### What each action means

- **`allow`** — Forwarded upstream, real answer returned. The
  default for any qname not on a list.
- **`cached`** — Served from local cache (no upstream contact). The
  cache key is qname+qtype+class.
- **`block`** — Matched a blocklist rule at qname-match time;
  synthesised `0.0.0.0` / `::` / NODATA returned without contacting
  upstream.
- **`uncloak`** — The qname itself didn't match anything, but a hop
  in its CNAME chain did. Synthesised block returned. `cname_chain`
  shows where in the chain the rule hit.
- **`refuse`** — The query was malformed or used a forbidden qtype
  (ANY/AXFR/IXFR/multi-question). REFUSED rcode returned.
- **`suspicious`** — The chain crossed registrable-domain boundaries
  but no rule matched; the upstream answer was returned (this is
  not a block — see `03-cname-uncloaking.md`).
- **`servfail`** — Upstream errored or the chain hit a fatal parse
  problem. SERVFAIL returned.

### Useful queries with `jq`

Top trackers blocked in the last hour:

```
jq -r 'select(.action == "block") | .rule' cloakdns-feat-log.jsonl \
  | sort | uniq -c | sort -rn | head
```

Average daemon latency by action:

```
jq -s 'group_by(.action) | map({action: .[0].action, avg_ms: (map(.latency_ms) | add/length)})' \
   cloakdns-feat-log.jsonl
```

Every uncloaked chain seen today:

```
jq -r 'select(.action == "uncloak") | "\(.qname) -> \(.cname_chain | join(" -> ")) [via \(.rule)]"' \
   cloakdns-feat-log.jsonl
```

The schema is stable enough that `jq` queries you write today keep
working — when fields are added, the `v` number bumps and old
queries continue to function (they just don't see the new fields).

---

## How it works in code

Three pieces.

### 1. `to_json_line` — hand-rolled JSON emitter (`src/query_log.cpp:132`)

CloakDNS doesn't pull in a full JSON library; it appends bytes
directly so emission is a single `std::string` allocation:

```cpp
// src/query_log.cpp:132
std::string to_json_line(const QueryLog& r) {
    std::string out;
    out.reserve(256);
    out += R"({"v":)";
    out += std::to_string(kQueryLogSchemaVersion);
    out += R"(,"ts":")";
    append_timestamp(out, r.ts);
    out += R"(","qname":)";
    append_json_string(out, r.qname);
    out += R"(,"qtype":)";
    if (const auto name = qtype_name(r.qtype); !name.empty()) {
        append_json_string(out, name);
    } else {
        out += std::to_string(r.qtype);
    }
    // ... action, rule, cname_chain, upstream, latency_ms, client ...
    out += '}';
    return out;
}
```

Field order is fixed; sets up the JSON-lines format (one record per
line — no commas between, no enclosing array). `append_json_string`
escapes the eight standard JSON-control characters but does NOT
do unicode escaping (qnames are restricted to a safe ASCII subset
upstream in `src/blocklist.cpp:is_valid_domain_char`).

### 2. The log path (`src/query_log.cpp:211`)

```cpp
// src/query_log.cpp:211
void QueryLogger::log(QueryLog record) {
    if (cfg_.path.empty()) return;
    if (cfg_.redact_client && !record.client.empty()) {
        record.client = redact_client_id(record.client);
    }
    auto line = to_json_line(record);

    if (!cfg_.async) {
        std::scoped_lock lk{mu_};
        write_one(line);
        return;
    }

    {
        std::scoped_lock lk{mu_};
        if (queue_.size() >= cfg_.queue_size) {
            ++dropped_;
            return;
        }
        queue_.push_back(std::move(line));
    }
    cv_.notify_one();
}
```

In sync mode, the request handler waits while the line is appended.
In async mode, the line is queued and the writer thread picks it
up. Async has bounded queue size; if the writer can't keep up
(writer thread starved or filesystem slow), the logger drops
records and increments `dropped_` instead of unbounded growth.

### 3. The handler call sites (`src/main.cpp`)

Every action in the handler maps to one `log_record(...)` call. A
tiny lambda captures the per-query state once and re-uses it across
each branch:

```cpp
// src/server.cpp ~line 132 — per-query log helper
auto log_record = [&](LogAction action,
                      const string& qname,
                      uint16_t qtype,
                      string rule = "",
                      vector<string> chain = {},
                      optional<string> upstream = nullopt,
                      optional<tls::EchStatus> ech = nullopt) {
    QueryLog rec;
    rec.ts          = wallclock_start;
    rec.qname       = qname;
    rec.qtype       = qtype;
    rec.action      = action;
    rec.rule        = std::move(rule);
    rec.cname_chain = std::move(chain);
    rec.upstream    = std::move(upstream);
    rec.client      = to_string_via_stream(from);
    rec.latency_ms  = chrono::duration<double, std::milli>(
        chrono::steady_clock::now() - t0).count();
    if (ech && *ech != tls::EchStatus::NotTried) {
        rec.tls_ech_status = string{tls::to_string(*ech)};
    }
    logger.log(std::move(rec));
};
```

Every branch in `handle()` (refuse, block, cached, allow, uncloak,
suspicious, servfail) emits exactly one `log_record(...)` call. The
1:1 ratio means a single dig query = one JSONL line, no surprises.

### Optional client redaction

When `[logging] redact_client = true`, the `client` field becomes
`hash:<8 hex chars>` (an FNV-1a 64-bit hash truncated to 32 bits)
instead of the raw `ip:port`. Useful if you want the log to be
shareable / less personally identifying while still preserving
"same client" linkability across records.

### What you can verify yourself

- Send queries with `dig`, then `tail -F cloakdns-feat-log.jsonl |
  jq` to see them stream live.
- Run `tools/e2e/tier_hit_rates.py` against your live log to see
  per-tier catch rates as your browsing happens.
- Toggle `redact_client = true` and confirm the client field flips
  from `127.0.0.1:65087` to `hash:abcd1234`.
- Confirm `latency_ms` is sub-millisecond for `block` and `cached`,
  tens of milliseconds for `allow`, and similar to `allow` for
  `uncloak` (since uncloak still forwards once before deciding).

---

## References

- **Source files:** [`src/query_log.cpp`](../src/query_log.cpp),
  [`include/cloakdns/query_log.hpp`](../include/cloakdns/query_log.hpp),
  [`src/main.cpp`](../src/main.cpp).
- **`tools/e2e/tier_hit_rates.py`** — example consumer of this log
  format (mines hit-rate per tier from JSONL records).
- **JSONL spec:** <https://jsonlines.org/> — the trivially-parseable
  one-record-per-line format.
- Related features: domain blocking, CNAME uncloaking, abuse-qtype
  refusal, cache.
