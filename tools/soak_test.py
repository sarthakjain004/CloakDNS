"""
soak_test.py — fire DNS queries at a running cloakdns and sample its
RSS at intervals. Used in M13 to detect memory leaks under load.

Reports a markdown table:

| t   | rss_kb | qps | hits | misses | inserts | evictions |
|-----|--------|-----|------|--------|---------|-----------|

The RSS is queried via Get-Process (Windows) or /proc/<pid>/status
(Linux). Cache stats come via the dump line cloakdns prints on each
SIGUSR1 — if it doesn't have one, the columns stay blank.

Usage:
  python soak_test.py --pid 12345 --duration 300 --port 5354 \
      --interval 30 --out results/M13_soak.md
"""

from __future__ import annotations

import argparse
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import Iterable


def _encode(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        if label:
            out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def _query(server: tuple[str, int], name: str, tid: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.5)
    pkt = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) \
        + _encode(name) + struct.pack(">HH", 1, 1)
    try:
        sock.sendto(pkt, server)
        try:
            sock.recvfrom(4096)
        except socket.timeout:
            pass
    finally:
        sock.close()


def load_loop(server: tuple[str, int], stop: threading.Event,
              counter: list[int], names: Iterable[str]) -> None:
    tid = 0
    name_iter = iter(names)
    while not stop.is_set():
        try:
            n = next(name_iter)
        except StopIteration:
            return
        _query(server, n, tid & 0xFFFF)
        tid += 1
        counter[0] += 1


def rss_kb(pid: int) -> int | None:
    if sys.platform == "win32":
        try:
            out = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command",
                 f"(Get-Process -Id {pid}).WorkingSet64"],
                stderr=subprocess.DEVNULL, text=True, timeout=5)
            return int(out.strip()) // 1024
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
                ValueError, FileNotFoundError):
            return None
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except OSError:
        return None
    return None


def name_stream(prefix: str, count_per_round: int):
    """Endless stream of unique names, cycling around to revisit older
    names after `count_per_round` so the cache gets both miss and hit
    pressure."""
    i = 0
    while True:
        yield f"{prefix}-{i % count_per_round:06d}.example"
        i += 1


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="CloakDNS memory soak test")
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--server", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5354)
    ap.add_argument("--duration", type=int, default=300,
                    help="seconds to run the soak (default: 300)")
    ap.add_argument("--interval", type=int, default=30,
                    help="seconds between RSS samples (default: 30)")
    ap.add_argument("--unique-names", type=int, default=2000,
                    help="cycle window for cache miss-then-hit pressure")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--out", type=argparse.FileType("w", encoding="utf-8"),
                    default=sys.stdout)
    args = ap.parse_args(argv)

    server = (args.server, args.port)
    stop = threading.Event()
    counter = [0]
    threads = [
        threading.Thread(
            target=load_loop, args=(server, stop, counter,
                                    name_stream(f"soak-{i}", args.unique_names)),
            daemon=True)
        for i in range(args.workers)
    ]
    for t in threads:
        t.start()

    args.out.write("| t (s) | rss_kb | total_q | qps |\n")
    args.out.write("|-------|--------|---------|-----|\n")
    args.out.flush()

    t0 = time.monotonic()
    last_t = t0
    last_count = 0
    while True:
        elapsed = time.monotonic() - t0
        if elapsed >= args.duration:
            break
        time.sleep(min(args.interval, args.duration - elapsed))
        now = time.monotonic()
        rss = rss_kb(args.pid)
        rss_str = str(rss) if rss is not None else "?"
        total_q = counter[0]
        qps = (total_q - last_count) / max(1e-6, now - last_t)
        last_count, last_t = total_q, now
        args.out.write(
            f"| {int(now - t0):4d} "
            f"| {rss_str:>6} "
            f"| {total_q:7d} "
            f"| {qps:5.0f} |\n")
        args.out.flush()

    stop.set()
    for t in threads:
        t.join(timeout=2)

    args.out.write(f"\n_total queries: {counter[0]}, duration: "
                   f"{int(time.monotonic() - t0)}s_\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
