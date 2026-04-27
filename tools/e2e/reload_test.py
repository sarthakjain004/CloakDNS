"""
Hot-reload verifier — exercises the SIGHUP/SIGBREAK reload path on a
running cloakdns and asserts a newly-added blocklist rule takes effect
without restarting the daemon.

This script also doubles as the canonical reference for how to send the
reload signal on Windows: cloakdns must be started with
``CREATE_NEW_PROCESS_GROUP`` and signalled with ``CTRL_BREAK_EVENT``
(``signal.CTRL_BREAK_EVENT``). The Win32 ``GenerateConsoleCtrlEvent``
API only delivers the event to processes that share a console group,
so an ad-hoc ``kill`` from a separate Bash session won't work — see
``docs/09-verification.md`` for context.

POSIX path: ``kill -HUP <pid>``. This script's logic still works on
Linux/macOS — Python's ``signal.SIGHUP`` is the equivalent there, but
we send the Windows-specific event because that's the platform where
the helper is non-trivial.

Usage (from project root):
    python tools/e2e/reload_test.py
"""
import os, signal, subprocess, sys, time, pathlib, shutil

# Walk up from tools/e2e/ to the project root.
ROOT = pathlib.Path(__file__).resolve().parents[2]
BL   = ROOT / "blocklist-reload.txt"
TOML = ROOT / "cloakdns-reload.toml"
EXE  = ROOT / "build-msvc/Release/cloakdns.exe"
DIG  = shutil.which("dig") or "dig"

# Pick the right reload signal for the platform.
RELOAD_SIGNAL = (signal.CTRL_BREAK_EVENT
                 if sys.platform == "win32"
                 else signal.SIGHUP)
POPEN_FLAGS   = (subprocess.CREATE_NEW_PROCESS_GROUP
                 if sys.platform == "win32"
                 else 0)

# Self-contained config — written fresh each run so the test doesn't
# depend on a hand-edited file.
TOML.write_text("""\
[server]
listen_addr = "127.0.0.1"
listen_port = 5354

[upstream]
protocol     = "udp"
servers      = ["1.1.1.1:53"]
timeout_ms   = 3000

[blocklist]
sources = ["blocklist-reload.txt"]

[cache]
max_entries = 100

[logging]
path  = "cloakdns-reload.jsonl"
async = false
""")

def dig_short(name):
    out = subprocess.run(
        [DIG, "@127.0.0.1", "-p", "5354", name, "+short", "+time=3", "+tries=1"],
        capture_output=True, text=True, timeout=8)
    return out.stdout.strip().splitlines()

# Reset blocklist to a starting state (one entry that's NOT example.org).
BL.write_text("0.0.0.0 will-be-removed.example\n")

p = subprocess.Popen(
    [str(EXE), str(TOML)],
    cwd=str(ROOT),
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    creationflags=POPEN_FLAGS)

failed = False
try:
    time.sleep(1.5)
    print("=== BEFORE reload — example.org should resolve to a real IP ===")
    before = dig_short("example.org")
    print(before)
    if not before or before == ["0.0.0.0"]:
        failed = True

    print("\n=== adding example.org to the blocklist file and sending reload ===")
    BL.write_text("0.0.0.0 will-be-removed.example\n0.0.0.0 example.org\n")
    p.send_signal(RELOAD_SIGNAL)
    time.sleep(1.5)

    print("\n=== AFTER reload — example.org should now be 0.0.0.0 ===")
    after = dig_short("example.org")
    print(after)
    if after != ["0.0.0.0"]:
        failed = True
finally:
    p.terminate()
    try:
        out, _ = p.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        p.kill()
        out, _ = p.communicate()
    print("\n=== daemon stdout (look for 'reload' or rule-count change) ===")
    print(out)

sys.exit(1 if failed else 0)
