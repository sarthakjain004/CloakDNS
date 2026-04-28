"""
Phase 4b verification: trigger an initial ECH bootstrap, wait briefly,
then SIGBREAK to force a re-bootstrap. The daemon should log a
"refreshed config — previous was Nh old" line on the second pass and
continue serving without restart.

This proves the staleness-tracking field (`fetched_at`) round-trips
through the bootstrap path and is consumed correctly on swap.

Usage (Windows dev box):
  python tools/e2e/bootstrap_refresh_test.py
"""
from __future__ import annotations

import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
EXE  = ROOT / "build-msvc/Release/cloakdns.exe"


CONFIG = """\
[server]
listen_addr = "127.0.0.1"
listen_port = 5354

[upstream]
protocol            = "doh"
servers             = ["213.108.108.101:443"]
servername          = "defo.ie"
doh_path            = "/dns-query"
timeout_ms          = 4000
ech_enabled         = true
ech_autobootstrap   = true
ech_bootstrap_servers = ["1.1.1.1:53", "1.0.0.1:53"]
ech_outer_servername = "cover.defo.ie"

[blocklist]
sources = ["blocklists/tier1.txt"]

[cache]
max_entries = 100

[logging]
path = ""
"""


def main() -> int:
    if sys.platform != "win32":
        print("written for Windows; adapt the SIGBREAK plumbing for POSIX",
              file=sys.stderr)
        return 2
    if not EXE.is_file():
        print(f"binary not found: {EXE}", file=sys.stderr)
        return 2

    workdir = pathlib.Path(tempfile.mkdtemp(prefix="cloakdns-stale-"))
    toml = workdir / "cloakdns.toml"
    toml.write_text(CONFIG)
    log = workdir / "cloak.log"

    p = subprocess.Popen(
        [str(EXE), str(toml)],
        cwd=str(ROOT),
        stdout=log.open("w"),
        stderr=subprocess.STDOUT,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    failed = False
    try:
        time.sleep(3)  # Let initial bootstrap complete.

        # SIGBREAK triggers the reload path which re-runs bootstrap.
        p.send_signal(signal.CTRL_BREAK_EVENT)
        time.sleep(3)  # Give the async re-bootstrap time to land.

        log_text = log.read_text()
        print("=== daemon log ===", file=sys.stderr)
        print(log_text, file=sys.stderr)

        if "ech bootstrap: fetched" not in log_text:
            print("FAIL: initial bootstrap line missing from log", file=sys.stderr)
            failed = True
        if "ech: refreshed config" not in log_text:
            print("FAIL: refresh diagnostic missing — fetched_at didn't survive "
                  "the round-trip through swap_ech", file=sys.stderr)
            failed = True
        else:
            print("OK: bootstrap -> SIGBREAK -> re-bootstrap diagnostic visible.")
    finally:
        p.terminate()
        try: p.wait(timeout=5)
        except subprocess.TimeoutExpired: p.kill()

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
