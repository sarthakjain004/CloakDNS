"""
Log-level SIGBREAK/SIGHUP ECH-reload smoke.

Lighter-weight than reload_ech_test.py: skips the tshark wire capture
(which needs admin/Npcap) and instead asserts the cloakdns stdout shows

  1. "ech bootstrap: fetched N ECHConfigList bytes" - bootstrap path
     populated the config from a live HTTPS RR query
  2. "cloakdns listening on" - server up, initial swap done via the
     Control::swap_ech_config seam
  3. on SIGBREAK / SIGHUP, "reload (SIGBREAK): rebuilding blocklist"
  4. "swapped ECH config (N bytes)" - the post-refactor Control fan-out
     path executed across every Adapter

Pass --exe to point at any ECH-enabled cloakdns binary.

Usage:

  python tools/e2e/reload_ech_log_smoke.py --exe build-ech/cloakdns.exe
"""
from __future__ import annotations

import argparse
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]

DEFO_IP    = "213.108.108.101"
DEFO_HOST  = "defo.ie"
DEFO_OUTER = "cover.defo.ie"

CONFIG_TOML = f"""\
[server]
listen_addr = "127.0.0.1"
listen_port = 15354

[upstream]
protocol               = "doh"
servers                = ["{DEFO_IP}:443"]
servername             = "{DEFO_HOST}"
doh_path               = "/dns-query"
ech_enabled            = true
ech_outer_servername   = "{DEFO_OUTER}"
ech_grease             = false
ech_autobootstrap      = true
ech_bootstrap_servers  = ["1.1.1.1:53", "8.8.8.8:53"]

[blocklist]
sources = ["blocklists/tier1.txt"]

[uncloak]
max_depth = 4

[cache]
max_entries = 1024

[logging]
path = ""
"""

RELOAD_SIGNAL = (signal.CTRL_BREAK_EVENT
                 if sys.platform == "win32"
                 else signal.SIGHUP)
POPEN_FLAGS = (subprocess.CREATE_NEW_PROCESS_GROUP
               if sys.platform == "win32"
               else 0)


def wait_for(stream, needle, timeout, captured):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        line = stream.readline()
        if not line:
            time.sleep(0.05)
            continue
        captured.append(line)
        print(line, end="", flush=True)
        if needle in line:
            return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", required=True,
                    help="Path to ECH-enabled cloakdns binary")
    ap.add_argument("--bootstrap-timeout", type=float, default=15.0)
    ap.add_argument("--reload-timeout", type=float, default=10.0)
    args = ap.parse_args()

    exe = pathlib.Path(args.exe).resolve()
    if not exe.is_file():
        print(f"binary not found: {exe}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="cloak-ech-smoke-") as td:
        tdp = pathlib.Path(td)
        toml = tdp / "cloakdns.toml"
        toml.write_text(CONFIG_TOML)
        print(f"[smoke] config: {toml}")
        print(f"[smoke] exe:    {exe}")

        proc = subprocess.Popen(
            [str(exe), str(toml)],
            cwd=str(ROOT),  # so blocklist relative paths resolve
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            creationflags=POPEN_FLAGS,
        )
        captured: list[str] = []
        try:
            print("[smoke] phase 1 - wait for ECH bootstrap...", flush=True)
            ok_boot = wait_for(proc.stdout,
                               "ech bootstrap: fetched",
                               args.bootstrap_timeout, captured)
            if not ok_boot:
                print("FAIL: never saw 'ech bootstrap: fetched'",
                      file=sys.stderr, flush=True)
                return 1

            print("[smoke] phase 2 - wait for listening...", flush=True)
            ok_listen = wait_for(proc.stdout,
                                 "cloakdns listening",
                                 args.bootstrap_timeout, captured)
            if not ok_listen:
                print("FAIL: never saw 'cloakdns listening'",
                      file=sys.stderr, flush=True)
                return 1

            print("[smoke] phase 3 - sending reload signal...", flush=True)
            time.sleep(0.5)
            proc.send_signal(RELOAD_SIGNAL)

            print("[smoke] phase 4 - wait for reload + swap...", flush=True)
            ok_reload = wait_for(proc.stdout, "rebuilding blocklist",
                                 args.reload_timeout, captured)
            if not ok_reload:
                print("FAIL: never saw 'rebuilding blocklist'",
                      file=sys.stderr, flush=True)
                return 1
            ok_swap = wait_for(proc.stdout, "swapped ECH config",
                               args.reload_timeout, captured)
            if not ok_swap:
                print("FAIL: never saw 'swapped ECH config'",
                      file=sys.stderr, flush=True)
                return 1

            print("\n[smoke] PASS - Control fan-out fired on reload "
                  "signal. ECH bytes propagated to every Adapter "
                  "through the post-refactor seam.", flush=True)
            return 0
        finally:
            try:
                proc.send_signal(signal.SIGINT if sys.platform != "win32"
                                 else signal.CTRL_C_EVENT)
            except (ValueError, OSError):
                proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    sys.exit(main())
