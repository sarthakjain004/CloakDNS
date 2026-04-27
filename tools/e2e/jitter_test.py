"""
Cache jitter verifier — measures the dig query-time distribution for
cache hits under ``jitter_max_ms = 0`` vs ``50`` to confirm the
configured jitter is actually applied to responses served from cache.

Usage (from project root):
    python tools/e2e/jitter_test.py

Expected output: ``jitter=0`` samples cluster at 0-1 ms; ``jitter=50``
samples spread across roughly 0-50 ms (plus a few ms of dig RTT).
"""
import re, statistics, subprocess, sys, time, pathlib, shutil, signal

# Walk up from tools/e2e/ to the project root.
ROOT = pathlib.Path(__file__).resolve().parents[2]
EXE  = ROOT / "build-msvc/Release/cloakdns.exe"
DIG  = shutil.which("dig") or "dig"
QTIME = re.compile(r";; Query time: (\d+) msec")

POPEN_FLAGS = (subprocess.CREATE_NEW_PROCESS_GROUP
               if sys.platform == "win32"
               else 0)
RELOAD_SIGNAL = (signal.CTRL_BREAK_EVENT
                 if sys.platform == "win32"
                 else signal.SIGTERM)

def write_toml(jitter_ms):
    (ROOT / "cloakdns-jitter.toml").write_text(f"""\
[server]
listen_addr = "127.0.0.1"
listen_port = 5354

[upstream]
protocol     = "udp"
servers      = ["1.1.1.1:53"]
timeout_ms   = 3000

[blocklist]
sources = ["blocklists/tier1.txt"]

[cache]
max_entries   = 100
jitter_max_ms = {jitter_ms}

[logging]
path  = "cloakdns-jitter.jsonl"
async = false
""")

def measure(jitter_ms, n=30):
    write_toml(jitter_ms)
    p = subprocess.Popen([str(EXE), "cloakdns-jitter.toml"],
                         cwd=str(ROOT),
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL,
                         creationflags=POPEN_FLAGS)
    try:
        time.sleep(1.2)
        # First query: warms the cache
        subprocess.run([DIG, "@127.0.0.1", "-p", "5354", "example.com",
                        "+time=3", "+tries=1"],
                       capture_output=True, text=True, timeout=6)
        # Subsequent queries: cache hits
        times = []
        for _ in range(n):
            r = subprocess.run([DIG, "@127.0.0.1", "-p", "5354", "example.com",
                                "+time=3", "+tries=1"],
                               capture_output=True, text=True, timeout=6)
            m = QTIME.search(r.stdout)
            if m:
                times.append(int(m.group(1)))
        return times
    finally:
        try:
            p.send_signal(RELOAD_SIGNAL)
            p.wait(timeout=2)
        except subprocess.TimeoutExpired:
            p.kill()
        except Exception:
            p.kill()
        p.wait()
        time.sleep(0.5)

def report(label, times):
    if not times:
        print(f"{label}: no samples"); return
    times_sorted = sorted(times)
    print(f"{label}: n={len(times)} "
          f"min={min(times)} median={statistics.median(times)} "
          f"max={max(times)} mean={statistics.mean(times):.1f} "
          f"stdev={statistics.pstdev(times):.1f}")
    print(f"  samples: {times_sorted}")

print("=== jitter=0  (cache hits should all be ~0 ms) ===")
report("jitter=0",  measure(0))
print()
print("=== jitter=50 (cache hits should spread 0-50 ms) ===")
report("jitter=50", measure(50))
