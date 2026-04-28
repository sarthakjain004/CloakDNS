"""
Live SIGHUP/SIGBREAK ECH-reload verifier — Phase 1 of the ECH-completion
work in features/11. Spins up cloakdns with ECH enabled (config A,
defo.ie's ECHConfigList), captures the upstream TLS handshake, then
rewrites the config to ECH-disabled (config B) and sends the reload
signal. Captures a second handshake and asserts the wire shape changed:

  - BEFORE reload: TLS extension 0xfe0d (encrypted_client_hello) is
    present in every ClientHello to defo.ie's IP.
  - AFTER  reload: extension 0xfe0d is absent from every ClientHello.

If both assertions hold, the SIGHUP-reload of EchConfig is working
end-to-end. The script is intentionally side-by-side with reload_test.py
so the existing CTRL_BREAK_EVENT plumbing carries straight over.

Prerequisites:
  - cloakdns built with -DCLOAKDNS_ECH=ON (verified via cmake cache)
  - tshark on PATH (Wireshark)
  - dig on PATH

Usage:
  python tools/e2e/reload_ech_test.py [--interface N] [--tshark PATH]
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
EXE  = ROOT / "build-msvc/Release/cloakdns.exe"

# defo.ie publishes a real ECHConfigList. Reusing the bytes from
# cloakdns-ech-test.toml so this test is self-contained but matches
# what feature 11's live demo uses.
DEFO_IP   = "213.108.108.101"
DEFO_HOST = "defo.ie"
DEFO_OUTER = "cover.defo.ie"
DEFO_ECH_B64 = (
    "AMD+DQA8+QAgACDruPRQzL/Iv0RNnTNHFTk0UosjqqpEVpxu1BQU3C7PbwAEAAEAAQAN"
    "Y292ZXIuZGVmby5pZQAA/g0APF0AIAAgDZOrs291bsLHWlBOCh1hnPcpiTiK808fBTV2"
    "L8hWlQoABAABAAEADWNvdmVyLmRlZm8uaWUAAP4NADxlACAAIN1gXf0Rb0zGqQ8rLcPw"
    "Xy+aS97ntf/yUZlze/lqg8xRAAQAAQABAA1jb3Zlci5kZWZvLmllAAA="
)

ECH_EXT_TYPE = 0xfe0d


def make_config(toml_path: pathlib.Path, *, ech_on: bool, jsonl: pathlib.Path) -> None:
    if ech_on:
        ech_block = f"""\
ech_enabled            = true
ech_outer_servername   = "{DEFO_OUTER}"
ech_config_list_b64    = "{DEFO_ECH_B64}"
"""
    else:
        ech_block = "ech_enabled = false\n"
    toml_path.write_text(f"""\
[server]
listen_addr = "127.0.0.1"
listen_port = 5354

[upstream]
protocol     = "doh"
servers      = ["{DEFO_IP}:443"]
servername   = "{DEFO_HOST}"
doh_path     = "/dns-query"
timeout_ms   = 4000
padding_block_size = 128
{ech_block}
[blocklist]
sources = ["blocklists/tier1.txt"]

[cache]
max_entries   = 100
jitter_max_ms = 0

[logging]
path  = "{jsonl.as_posix()}"
async = false
""")


def collect_extension_types_from_pcap(pcap: pathlib.Path, tshark: str) -> list[list[int]]:
    """Return one inner list per ClientHello, each containing its TLS
    extension type numbers (decimal)."""
    out = subprocess.run(
        [tshark, "-r", str(pcap),
         "-Y", "tls.handshake.type == 1",
         "-T", "fields", "-e", "tls.handshake.extension.type"],
        capture_output=True, text=True, timeout=30)
    rows = [line.strip() for line in out.stdout.splitlines() if line.strip()]
    parsed = []
    for r in rows:
        # tshark joins multi-valued fields with ',' by default
        nums = []
        for tok in r.split(","):
            tok = tok.strip()
            if not tok:
                continue
            try:
                nums.append(int(tok))
            except ValueError:
                pass
        if nums:
            parsed.append(nums)
    return parsed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--interface", default="5",
                    help="tshark capture interface (default 5 = Wi-Fi on this dev box; "
                         "run `tshark -D` to see your numbering)")
    ap.add_argument("--tshark", default=shutil.which("tshark") or
                    "/c/Program Files/Wireshark/tshark")
    ap.add_argument("--dig", default=shutil.which("dig") or "dig")
    args = ap.parse_args()

    if sys.platform != "win32":
        # Same plumbing works on POSIX with SIGHUP — but the script as
        # written uses Windows paths, so guard against accidental Linux
        # runs until a maintainer adapts it.
        print("reload_ech_test: written for Windows; adapt paths for POSIX",
              file=sys.stderr)
        return 2

    if not EXE.is_file():
        print(f"binary not found: {EXE}", file=sys.stderr)
        return 2

    workdir = pathlib.Path(tempfile.mkdtemp(prefix="cloakdns-ech-reload-"))
    print(f"workdir: {workdir}", file=sys.stderr)

    toml = workdir / "cloakdns.toml"
    jsonl = workdir / "cloakdns.jsonl"
    pcap_pre = workdir / "pre.pcap"
    pcap_post = workdir / "post.pcap"
    tshark_log_pre = workdir / "tshark-pre.log"
    tshark_log_post = workdir / "tshark-post.log"
    cloak_log = workdir / "cloak.log"

    # Step 1: write config A (ECH on), start daemon.
    make_config(toml, ech_on=True, jsonl=jsonl)
    cloak = subprocess.Popen(
        [str(EXE), str(toml)],
        cwd=str(ROOT),
        stdout=cloak_log.open("w"),
        stderr=subprocess.STDOUT,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    time.sleep(1.0)

    capture_filter = f"host {DEFO_IP} and tcp port 443"

    failed = False
    try:
        # Step 2: capture pre-reload handshakes.
        ts1 = subprocess.Popen(
            [args.tshark, "-i", args.interface, "-f", capture_filter,
             "-w", str(pcap_pre), "-q"],
            stdout=tshark_log_pre.open("w"),
            stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        time.sleep(2.0)
        for q in ("example.com", "github.com"):
            subprocess.run(
                [args.dig, "@127.0.0.1", "-p", "5354", "+time=3", "+tries=1",
                 "+short", q],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        time.sleep(1.0)
        ts1.terminate()
        try: ts1.wait(timeout=5)
        except subprocess.TimeoutExpired: ts1.kill()

        pre_exts = collect_extension_types_from_pcap(pcap_pre, args.tshark)
        print(f"pre-reload  ClientHellos: {len(pre_exts)}, "
              f"with ECH ext: {sum(1 for e in pre_exts if ECH_EXT_TYPE in e)}",
              file=sys.stderr)

        # Step 3: rewrite config to ECH off, send reload signal, wait.
        make_config(toml, ech_on=False, jsonl=jsonl)
        cloak.send_signal(signal.CTRL_BREAK_EVENT)
        time.sleep(2.0)

        # Step 4: capture post-reload handshakes.
        ts2 = subprocess.Popen(
            [args.tshark, "-i", args.interface, "-f", capture_filter,
             "-w", str(pcap_post), "-q"],
            stdout=tshark_log_post.open("w"),
            stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        time.sleep(2.0)
        for q in ("example.org", "wikipedia.org"):
            subprocess.run(
                [args.dig, "@127.0.0.1", "-p", "5354", "+time=3", "+tries=1",
                 "+short", q],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        time.sleep(1.0)
        ts2.terminate()
        try: ts2.wait(timeout=5)
        except subprocess.TimeoutExpired: ts2.kill()

        post_exts = collect_extension_types_from_pcap(pcap_post, args.tshark)
        print(f"post-reload ClientHellos: {len(post_exts)}, "
              f"with ECH ext: {sum(1 for e in post_exts if ECH_EXT_TYPE in e)}",
              file=sys.stderr)

        # Assertions.
        if not pre_exts:
            print("FAIL: no ClientHellos captured pre-reload", file=sys.stderr)
            failed = True
        elif not all(ECH_EXT_TYPE in e for e in pre_exts):
            print(f"FAIL: some pre-reload ClientHellos missing ECH ext", file=sys.stderr)
            failed = True

        if not post_exts:
            print("FAIL: no ClientHellos captured post-reload", file=sys.stderr)
            failed = True
        elif any(ECH_EXT_TYPE in e for e in post_exts):
            print(f"FAIL: post-reload ClientHello carried ECH ext after reload", file=sys.stderr)
            failed = True

        if not failed:
            print("OK: SIGBREAK swap of ECH config visible on the wire — ECH "
                  "ext present pre-reload, absent post-reload.")

    finally:
        cloak.terminate()
        try: cloak.wait(timeout=5)
        except subprocess.TimeoutExpired: cloak.kill()
        print(f"\n=== cloak log ===\n{cloak_log.read_text()}", file=sys.stderr)

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
