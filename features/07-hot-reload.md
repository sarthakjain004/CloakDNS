# Hot reload (SIGHUP / SIGBREAK)

Send the daemon a process signal (`SIGHUP` on Linux/macOS,
`CTRL_BREAK_EVENT` on Windows) and it re-reads the blocklist and
allowlist files **without restarting** — no dropped UDP queries, no
fresh cache, no momentary outage in your network.

---

## The problem

Blocklists evolve. You'll hit several scenarios where you want to
update the rule set:

- The federated `tools/update_blocklists.py` script just merged in
  a fresh feed and produced a newer `blocklists/merged.txt`.
- You added a new rule manually (e.g. you noticed a tracker the
  feeds miss).
- You updated your allowlist to whitelist some domain that was
  legitimately blocked.
- You're tuning rule files iteratively while debugging a site.

Without hot reload, every change requires:

1. Stop the daemon.
2. (briefly) every device on your network that uses CloakDNS as its
   resolver gets DNS errors / falls back to a public resolver.
3. Restart the daemon.
4. Cache is empty; the next thousand queries all go upstream.

For a personal laptop that's a minor annoyance. For a daemon serving
the household — phones, smart TVs, IoT — even a 5-second outage
manifests as a "wifi is broken" complaint. With hot reload:

1. Edit the blocklist file.
2. Send one signal.
3. The daemon swaps in the new ruleset atomically, in-flight queries
   keep flowing, the cache is preserved (cached answers are still
   valid — TTLs haven't moved), no queries are dropped.

The cache preservation is deliberate: if a name was forwarded
yesterday and is still cached, reload doesn't re-issue the lookup.
Only the **rule decision** is refreshed; whether the cached answer
is still served depends on whether the new rules now block that
qname (block always wins over cache; see `02-domain-blocking.md`).

### Concrete user-impact example

You've got CloakDNS running on a home server, configured as the DHCP-
advertised resolver for the LAN. Three phones, two laptops, a smart
TV, and a smart speaker all use it. You realise your kid's school
website depends on a specific domain that tier 1 catches.

Without hot reload: you SSH in, edit the blocklist, restart cloakdns,
and during the ~3-second restart window every device on the network
sees DNS failures. The smart TV's streaming app drops out and asks
to relogin; one phone's app shows a generic "no internet" error.

With hot reload: edit, signal, done. None of the devices notice. In-
flight queries on the daemon at the moment of signal complete using
the OLD blocklist; queries that arrive after the signal use the new
one. The atomic swap means there's no transient state where rules
are half-loaded.

---

## See it live

Run end-to-end on **2026-04-28** using the bundled verifier
`tools/e2e/reload_test.py`. The script:

1. Writes a fresh `cloakdns-reload.toml` (UDP upstream, single-source
   blocklist).
2. Writes `blocklist-reload.txt` containing one rule
   (`will-be-removed.example`).
3. Spawns the daemon under `subprocess.Popen` with
   `CREATE_NEW_PROCESS_GROUP` (Windows) so it can later send
   `signal.CTRL_BREAK_EVENT`. On POSIX the same script falls back to
   `signal.SIGHUP`.
4. Sends a dig before reload — `example.org` should resolve normally.
5. Appends `0.0.0.0 example.org` to `blocklist-reload.txt`.
6. Sends the reload signal to the daemon.
7. Sends a second dig — `example.org` should now return `0.0.0.0`.

### Run

```
$ python tools/e2e/reload_test.py
=== BEFORE reload — example.org should resolve to a real IP ===
['172.66.157.237', '104.20.26.136']

=== adding example.org to the blocklist file and sending reload ===

=== AFTER reload — example.org should now be 0.0.0.0 ===
['0.0.0.0']
```

### Daemon stdout (captured by the script)

```
loaded 1 block rule(s) from 1 source(s)
cloakdns listening on 127.0.0.1:5354
upstream: 1.1.1.1:53  (timeout 3000ms)
cname uncloaking: max depth 8
cache: 100 entries, jitter 0-5ms on hit, sweep 30s
padding: 128-byte blocks
logging: cloakdns-reload.jsonl (sync)
forward example.org

reload (SIGBREAK): rebuilding blocklist
loaded 2 block rule(s) from 1 source(s)
block   example.org  via example.org  qtype=1
```

Read structure:

- **Initial load**: `loaded 1 block rule(s) from 1 source(s)` —
  `will-be-removed.example` is the only rule.
- **First query**: `forward example.org` — passes through because
  no rule matches.
- **`reload (SIGBREAK): rebuilding blocklist`** — the daemon's
  signal handler fired and called `build_blocklist` again.
- **Post-reload**: `loaded 2 block rule(s) from 1 source(s)` — rule
  count went 1 → 2 because we appended `example.org` to the same
  file.
- **Second query**: `block example.org via example.org qtype=1` —
  the new rule now catches `example.org`.

The script exits with code 0; that's its assertion that "before
returned a real IP AND after returned 0.0.0.0" both hold. (See
`tools/e2e/reload_test.py` for the actual assertions.)

### What's NOT in the JSONL log

The JSONL file (`cloakdns-reload.jsonl`) is empty after this run.
That's because `reload_test.py` ends with `p.terminate()` →
`p.kill()` to clean up — a hard process termination that doesn't let
the QueryLogger flush its in-memory queue. For a clean shutdown,
send the daemon SIGINT (Ctrl-C) instead — that triggers
`ctx.stop()` (line 519 in `src/main.cpp`) which lets the logger
drain. Hot reload itself never affects the log; only the test
harness's cleanup does.

---

## How it works in code

Three pieces.

### 1. Atomic swap pattern (`src/main.cpp:281`)

The daemon stores the active blocklist in a `std::shared_ptr` held
behind an internal accessor:

```cpp
// src/main.cpp ~line 281
// Hot-reload-friendly shared-pointer holder. main() builds each
// fresh Blocklist into a new shared_ptr; the listener loads its
// current shared_ptr per query (so in-flight queries keep using
// the old Blocklist they snapshotted).
```

Each query handler at the start of its work makes a shared snapshot
of the *current* blocklist. The reload logic later replaces that
shared_ptr atomically. The two threads never read inconsistent
state because they're never reading the same pointer concurrently —
the listener has its own snapshot for its query, and the reload
writes a new shared_ptr that future queries will pick up. The OLD
Blocklist is reference-counted; once the last in-flight query
finishes, it drops to refcount zero and is freed.

This is the idiomatic "left-right" pattern for read-mostly data.
No locks on the hot path. The cost is one shared_ptr load per
query, which is essentially free.

### 2. The signal handler (`src/main.cpp:526`)

```cpp
// src/main.cpp ~line 526
#if defined(_WIN32)
    constexpr int kReloadSignal = SIGBREAK;
    const char* kReloadName = "SIGBREAK";
#else
    constexpr int kReloadSignal = SIGHUP;
    const char* kReloadName = "SIGHUP";
#endif
    asio::signal_set reload_signals{ctx, kReloadSignal};
    std::function<void(const std::error_code&, int)> on_reload;
    on_reload = [&](const std::error_code& ec, int) {
        if (ec) return;   // cancelled (e.g. shutdown)
        try {
            std::cout << "\nreload (" << kReloadName << "): rebuilding blocklist" << std::endl;
            auto fresh = std::make_shared<cloak::Blocklist>(build_blocklist(cfg));
            blocklist_store(std::move(fresh));
        } catch (const std::exception& e) {
            std::cerr << "reload failed (" << e.what()
                      << ") — keeping previous blocklist" << std::endl;
        }
        // Re-arm.
        reload_signals.async_wait(on_reload);
    };
```

Two important properties:

1. **The handler is re-armed at the end** — `reload_signals.async_wait(on_reload)`
   schedules itself again. Without this, the signal would only work
   the first time. Asio's signal_set delivers each signal once;
   you have to ask again to receive the next.
2. **Failures roll back, not crash**. If `build_blocklist` throws
   (file missing, parse error, etc.), the catch handler logs the
   error and leaves the *old* blocklist in place. The daemon
   doesn't die just because someone fat-fingered a syntax error in
   their rule file.

### 3. Why the cache survives reload

The reload only rebuilds the Blocklist; it doesn't touch the
DnsCache. That's intentional:

- Cached *positive* answers are still valid — they were correct
  upstream answers, the upstream's data didn't change just because
  your rules did.
- If a previously-allowed domain is now blocked, the next query
  hits the **block check first** in `handle()` (before cache
  lookup; see `02-domain-blocking.md` and main.cpp:154). So the
  new rule wins regardless of cache state.
- If a previously-blocked-now-allowed domain is queried, the
  qname-level block is gone, the cache had no entry (because the
  block branch never inserted), so it forwards normally and caches
  the new answer.

The combination means hot-reload never produces a "but the cache
still has the old answer" surprise. The block check is always
authoritative.

### Why Windows uses CTRL_BREAK_EVENT instead of SIGHUP

POSIX has SIGHUP. Windows doesn't, so we use the closest analogue
that survives Asio's signal_set: SIGBREAK. The catch is delivery —
SIGHUP can be sent with plain `kill -HUP <pid>`, but
`CTRL_BREAK_EVENT` only travels between processes that share a
console group. To send it from another process, that process has
to launch the daemon with `CREATE_NEW_PROCESS_GROUP` first; then it
can `signal.CTRL_BREAK_EVENT` the child group ID.

`tools/e2e/reload_test.py` is the canonical reference for how to
do this from Python. It's also what `learnings/demo-doh-dot-ech.md`
points at if you want to drive reloads from the command line on
Windows. (The original README incorrectly suggested
`taskkill /F /BREAK` — `/BREAK` isn't a valid taskkill flag and
taskkill can't reach across console groups anyway. Fixed in the
fixes branch.)

### What you can verify yourself

- Run `python tools/e2e/reload_test.py` — it returns exit 0 only
  if the before/after assertion passes.
- Modify the blocklist file by hand while the daemon is running,
  send the signal, watch `cloakdns-queries.jsonl` for the new
  rule's effects.
- Try a malformed rule file (e.g. an unreadable path) — the daemon
  logs `reload failed: <reason> — keeping previous blocklist` and
  keeps serving traffic with the old rules.

---

## References

- **`tools/e2e/reload_test.py`** — the canonical signalling harness;
  works on Linux (SIGHUP) and Windows (CTRL_BREAK_EVENT).
- **`docs/09-verification.md` §Hot-reload** — documented procedure
  with pass/fail criteria.
- **Source files:** [`src/main.cpp`](../src/main.cpp) — listener,
  signal handler, atomic shared_ptr swap.
- Related features: domain blocking, allowlist passthrough,
  structured query log.
