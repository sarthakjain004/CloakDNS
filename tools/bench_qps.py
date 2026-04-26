"""
bench_qps.py — fire DNS queries at a running cloakdns and report
latency percentiles for three paths: block, cached, forward.

Usage:
  python bench_qps.py --server 127.0.0.1 --port 5354 --count 500
"""

from __future__ import annotations

import argparse
import random
import socket
import statistics
import struct
import sys
import time
from typing import Callable, Union


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        if not label:
            continue
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def build_query(name: str, tx_id: int) -> bytes:
    hdr = struct.pack(">HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
    body = _encode_name(name) + struct.pack(">HH", 1, 1)     # A, IN
    return hdr + body


def one_query(server: tuple[str, int], name: str,
              timeout: float) -> float | None:
    """Returns round-trip time in ms, or None on timeout / error.

    Each call uses a fresh socket so a late response from one query
    cannot pollute the next call's recvfrom buffer (a problem the old
    shared-socket version had with the cache-miss flood)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    tx = random.randrange(0, 0xFFFF)
    pkt = build_query(name, tx)
    try:
        t0 = time.perf_counter()
        try:
            sock.sendto(pkt, server)
            resp, _ = sock.recvfrom(4096)
        except (socket.timeout, OSError):
            return None
        if len(resp) < 2 or struct.unpack(">H", resp[:2])[0] != tx:
            return None
        return (time.perf_counter() - t0) * 1000.0
    finally:
        sock.close()


def bench(server: tuple[str, int], name: Union[str, Callable[[int], str]],
          n: int, timeout: float) -> list[float]:
    """Run n queries serially. `name` may be a fixed string or a callable
    taking the iteration index and returning a fresh name (used for
    cache-miss sampling)."""
    samples: list[float] = []
    for i in range(n):
        qname = name(i) if callable(name) else name
        rtt = one_query(server, qname, timeout)
        if rtt is not None:
            samples.append(rtt)
    return samples


def percentiles(samples: list[float]) -> dict[str, float]:
    if not samples:
        return {"n": 0}
    s = sorted(samples)

    def pct(p: float) -> float:
        idx = min(len(s) - 1, int(p * len(s)))
        return s[idx]

    return {
        "n": len(s),
        "min_ms": s[0],
        "p50_ms": pct(0.50),
        "p95_ms": pct(0.95),
        "p99_ms": pct(0.99),
        "max_ms": s[-1],
        "mean_ms": statistics.mean(s),
    }


def format_row(label: str, stats: dict[str, float]) -> str:
    if stats["n"] == 0:
        return f"{label:16} no samples"
    return (f"{label:16} n={stats['n']:4d}  "
            f"min={stats['min_ms']:6.2f}  "
            f"p50={stats['p50_ms']:6.2f}  "
            f"p95={stats['p95_ms']:6.2f}  "
            f"p99={stats['p99_ms']:6.2f}  "
            f"max={stats['max_ms']:6.2f}  "
            f"mean={stats['mean_ms']:6.2f}  (ms)")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="CloakDNS latency benchmark")
    ap.add_argument("--server", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5354)
    ap.add_argument("--count", type=int, default=500)
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--warmup", type=int, default=20)
    ap.add_argument("--block-name", default="doubleclick.net",
                    help="domain expected to hit the blocklist")
    ap.add_argument("--forward-name", default="example.com",
                    help="domain expected to forward upstream on first query")
    args = ap.parse_args(argv)

    server = (args.server, args.port)

    # Warmup — primes sockets, fills any OS ARP / routing state.
    bench(server, args.forward_name, args.warmup, args.timeout)

    # Block path: synthesized response, no upstream, no cache.
    block = bench(server, args.block_name, args.count, args.timeout)

    # Cache-miss path: fresh, unique name per query forces upstream every time.
    def fresh_name(i: int) -> str:
        return f"rnd-{random.randrange(1_000_000_000)}-{i}.example"
    miss = bench(server, fresh_name, args.count, args.timeout)

    # Cache-hit path: re-prime right before measuring so we don't depend
    # on the warmup name still being in cache after the long miss flood
    # (its TTL is whatever upstream returned, often <2 minutes).
    bench(server, args.forward_name, 3, args.timeout)
    hit = bench(server, args.forward_name, args.count, args.timeout)

    print(format_row("block",       percentiles(block)))
    print(format_row("cache-miss",  percentiles(miss)))
    print(format_row("cache-hit",   percentiles(hit)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
