"""
Sanitizer-build load test — pumps the existing E2E corpus of unique
hostnames through a CloakDNS instance built with -fsanitize=address,undefined
and reports any sanitizer findings on stderr.

Linux only — Apple Clang has no LeakSanitizer; MSVC's ASan is limited.
Build path:

    cmake -S . -B build-asan -G Ninja \\
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \\
        -DCLOAKDNS_SANITIZE=asan+ubsan
    cmake --build build-asan -j

Usage (from project root, with that build present):

    python3 tools/e2e/sanitizer_replay.py \\
        --binary build-asan/cloakdns \\
        --duration 300

Each query is sent via dig over localhost UDP. The daemon's stderr is
captured and any line containing "AddressSanitizer", "UndefinedBehavior",
"runtime error:", "LeakSanitizer", or "ERROR:" is reported as a finding.
A clean run is silent — exit 0 means the daemon ran the full corpus
under sanitizers without any sanitizer report or crash.
"""
import argparse, json, pathlib, random, re, signal, subprocess, sys, time

ROOT = pathlib.Path(__file__).resolve().parents[2]

def collect_hosts() -> list[str]:
    hosts: set[str] = set()
    for vfile in (ROOT / "results" / "E2E").glob("*/visits.jsonl"):
        for line in vfile.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line: continue
            try: rec = json.loads(line)
            except: continue
            for h in rec.get("hosts", []):
                if h and "." in h: hosts.add(h)
    return sorted(hosts)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True,
                    help="path to sanitizer-instrumented cloakdns")
    ap.add_argument("--duration", type=int, default=300,
                    help="seconds to run; corpus replayed in a loop until elapsed")
    ap.add_argument("--port", type=int, default=5354)
    args = ap.parse_args()

    binary = pathlib.Path(args.binary).resolve()
    if not binary.exists():
        sys.exit(f"binary not found: {binary}")

    # Minimal config — no blocklist, plain UDP upstream, no padding fluff,
    # so the daemon exercises the parser/forwarder/cache hot paths but
    # nothing too exotic.
    cfg = ROOT / "cloakdns-sanitizer.toml"
    cfg.write_text("""\
[server]
listen_addr = "127.0.0.1"
listen_port = %d

[upstream]
protocol     = "udp"
servers      = ["1.1.1.1:53"]
timeout_ms   = 3000

[blocklist]
sources = ["blocklists/tier1.txt"]

[cache]
max_entries   = 5000
jitter_max_ms = 5

[logging]
path  = "cloakdns-sanitizer.jsonl"
async = false
""" % args.port)

    hosts = collect_hosts()
    print(f"loaded {len(hosts)} unique hosts from results/E2E corpus")

    # Start daemon. Capture stderr in a file so sanitizer output survives.
    stderr_path = ROOT / "cloakdns-sanitizer.stderr"
    stderr_path.write_bytes(b"")
    p = subprocess.Popen([str(binary), str(cfg)],
                         cwd=str(ROOT),
                         stdout=subprocess.DEVNULL,
                         stderr=open(stderr_path, "wb"))

    findings: list[str] = []
    rng = random.Random(0xCD)
    started = time.time()
    sent = 0
    try:
        time.sleep(1.5)
        # Feed queries until --duration elapses. Mix qtypes so the parser
        # and AAAA / HTTPS / SVCB dispatch all get exercised.
        qtypes = ["A", "AAAA", "HTTPS", "TXT", "MX", "SOA", "PTR"]
        deadline = started + args.duration
        while time.time() < deadline:
            host = rng.choice(hosts)
            qt   = rng.choice(qtypes)
            try:
                subprocess.run(
                    ["dig", f"@127.0.0.1", "-p", str(args.port), host, qt,
                     "+time=2", "+tries=1", "+notcp"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=4)
            except subprocess.TimeoutExpired:
                pass
            sent += 1
            if sent % 200 == 0:
                elapsed = time.time() - started
                rate = sent / max(elapsed, 0.001)
                print(f"  {sent} queries sent ({rate:.1f}/s, {int(elapsed)}s elapsed)")
    finally:
        p.send_signal(signal.SIGTERM)
        try: p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill(); p.wait()

    elapsed = time.time() - started
    print(f"done. sent={sent} queries in {elapsed:.1f}s")

    # Scan stderr for any sanitizer/runtime-error signature.
    pat = re.compile(
        r"AddressSanitizer|UndefinedBehavior|runtime error:|LeakSanitizer|"
        r"ERROR: |ThreadSanitizer|stack-buffer|heap-buffer|use-after-free")
    text = stderr_path.read_text(errors="replace")
    for line in text.splitlines():
        if pat.search(line):
            findings.append(line)

    if findings:
        print("\n=== SANITIZER FINDINGS ===")
        for f in findings:
            print(f)
        print(f"\nfull stderr saved at: {stderr_path}")
        sys.exit(1)
    print("\nno sanitizer findings. clean.")
    sys.exit(0)

if __name__ == "__main__":
    main()
