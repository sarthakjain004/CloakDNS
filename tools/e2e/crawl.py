"""
crawl.py — Playwright-driven E2E crawl.

For each site in the corpus:
  1. Open a fresh Chromium incognito context.
  2. page.goto(https://<site>/) with 30s budget.
  3. Capture every HTTP request URL the page issues.
  4. Wait 8s after `load` for lazy trackers to fire.
  5. Issue a DNS A query through cloakdns for each unique hostname
     the page contacted. cloakdns logs the action — that's our data.
  6. Record the visit window, success signal, console errors.
  7. Sleep 2s gap so cloakdns log is cleanly partitioned per site.

Note: this design does NOT redirect Chromium's own DNS through cloakdns.
Modifying Windows system DNS requires admin and risks leaving the box
in a broken state if the test crashes. Instead, we use Chromium as a
faithful third-party-resource discoverer (it actually loads the page,
runs JS, fetches subresources), then replay the discovered hostnames
through cloakdns. cloakdns's decision logic is exercised end-to-end on
real-world hostnames.

Usage:
  python tools/e2e/crawl.py --corpus tools/e2e/corpus.txt \
      --resolver 127.0.0.1:5354 --run-id 2026-04-26-smoke
"""

from __future__ import annotations

import argparse
import datetime
import json
import pathlib
import random
import socket
import struct
import sys
import time
import urllib.parse

from playwright.sync_api import sync_playwright, Error as PWError, TimeoutError as PWTimeout


# --- DNS client -------------------------------------------------------------


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        if not label:
            continue
        try:
            out += bytes([len(label)]) + label.encode("ascii")
        except UnicodeEncodeError:
            try:
                punycoded = label.encode("idna")
                out += bytes([len(punycoded)]) + punycoded
            except UnicodeError:
                return b""
    return out + b"\x00"


def dns_query(server: tuple[str, int], qname: str,
              timeout: float = 2.0) -> bool:
    """Fire one A query, wait for response. Returns True on
    transaction-id-matched reply within `timeout`."""
    name_bytes = _encode_name(qname)
    if not name_bytes:
        return False
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    tx = random.randrange(0, 0xffff)
    try:
        hdr = struct.pack(">HHHHHH", tx, 0x0100, 1, 0, 0, 0)
        body = name_bytes + struct.pack(">HH", 1, 1)
        try:
            sock.sendto(hdr + body, server)
            resp, _ = sock.recvfrom(4096)
            return len(resp) >= 2 and \
                struct.unpack(">H", resp[:2])[0] == tx
        except (socket.timeout, OSError):
            return False
    finally:
        sock.close()


# --- Crawl ------------------------------------------------------------------


def _hostname(url: str) -> str | None:
    try:
        return urllib.parse.urlparse(url).hostname
    except (ValueError, AttributeError):
        return None


def crawl_site(playwright, domain: str,
               server: tuple[str, int],
               nav_timeout_ms: int = 30_000,
               post_load_wait_ms: int = 8_000) -> dict:
    """Visit one site. Returns a visit record."""
    start_wall = datetime.datetime.now(datetime.timezone.utc)
    start_mono = time.monotonic()

    requested_hosts: set[str] = set()
    requested_hosts.add(domain)
    console_errors: list[str] = []
    failed_subresources: list[str] = []
    main_frame_loaded = False
    http_status = 0
    title = ""
    status = "ok"

    browser = playwright.chromium.launch(
        headless=True,
        args=["--disable-blink-features=AutomationControlled"],
    )
    try:
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/123.0.0.0 Safari/537.36",
            viewport={"width": 1366, "height": 768},
            ignore_https_errors=True,
        )
        page = context.new_page()

        page.on("request", lambda req: requested_hosts.add(_hostname(req.url) or ""))
        page.on("requestfailed",
                lambda req: failed_subresources.append(req.url))
        page.on("console", lambda msg: (
            console_errors.append(msg.text)
            if msg.type == "error" else None))

        try:
            response = page.goto(f"https://{domain}/",
                                 timeout=nav_timeout_ms,
                                 wait_until="load")
            if response is not None:
                http_status = response.status
                main_frame_loaded = response.ok
            else:
                main_frame_loaded = False
        except PWTimeout:
            status = "timeout"
        except PWError as e:
            status = "net_error"
            console_errors.append(f"playwright: {e}")

        if status == "ok" and main_frame_loaded:
            try:
                page.wait_for_timeout(post_load_wait_ms)
            except PWError:
                pass

        # Try cookie-banner accept (best-effort, 1.5s budget).
        for selector in ("button:has-text('Accept all')",
                         "button:has-text('Accept All')",
                         "button:has-text('Accept')",
                         "button:has-text('Agree')",
                         "[aria-label*='accept' i]"):
            try:
                btn = page.query_selector(selector)
                if btn:
                    btn.click(timeout=1500)
                    page.wait_for_timeout(2000)   # let post-consent trackers fire
                    break
            except PWError:
                pass

        try:
            title = (page.title() or "")[:120]
        except PWError:
            pass

        try:
            page.close()
            context.close()
        except PWError:
            pass
    finally:
        try:
            browser.close()
        except PWError:
            pass

    if not status:
        status = "ok" if main_frame_loaded else "http_error"
    elif status == "ok" and not main_frame_loaded:
        status = "http_error"

    requested_hosts.discard("")
    requested_hosts.discard(None)
    hosts = sorted(h for h in requested_hosts if h and "." in h)

    queried = 0
    failed = 0
    for h in hosts:
        if dns_query(server, h):
            queried += 1
        else:
            failed += 1

    end_wall = datetime.datetime.now(datetime.timezone.utc)
    return {
        "site":           domain,
        "url":            f"https://{domain}/",
        "start":          start_wall.isoformat(timespec="milliseconds"),
        "end":            end_wall.isoformat(timespec="milliseconds"),
        "elapsed_s":      round(time.monotonic() - start_mono, 3),
        "http_status":    http_status,
        "main_frame_loaded": main_frame_loaded,
        "status":         status,
        "title":          title,
        "host_count":     len(hosts),
        "hosts":          hosts,
        "queried":        queried,
        "failed":         failed,
        "console_errors": console_errors[:20],
        "failed_subresources": failed_subresources[:20],
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus",   default="tools/e2e/corpus.txt", type=pathlib.Path)
    ap.add_argument("--resolver", default="127.0.0.1:5354")
    ap.add_argument("--run-id",   required=True)
    ap.add_argument("--out-dir",  default="results/E2E", type=pathlib.Path)
    ap.add_argument("--max-sites", type=int, default=0,
                    help="cap corpus size for quick smoke; 0 = no cap")
    args = ap.parse_args(argv)

    host, port = args.resolver.split(":")
    server = (host, int(port))

    corpus = [
        line.strip()
        for line in args.corpus.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    if args.max_sites:
        corpus = corpus[:args.max_sites]

    run_dir = args.out_dir / args.run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    visits_path = run_dir / "visits.jsonl"

    print(f"crawling {len(corpus)} site(s) with Playwright + cloakdns")
    print(f"resolver: {server[0]}:{server[1]}")
    print(f"output:   {visits_path}")

    with sync_playwright() as pw, visits_path.open("w", encoding="utf-8") as out:
        for i, domain in enumerate(corpus, 1):
            print(f"  [{i:3d}/{len(corpus)}] {domain}", end=" ", flush=True)
            try:
                rec = crawl_site(pw, domain, server)
            except Exception as e:                      # noqa: BLE001
                rec = {
                    "site": domain, "url": f"https://{domain}/",
                    "status": "harness_error", "error": str(e),
                    "start": datetime.datetime.now(datetime.timezone.utc)
                                .isoformat(timespec="milliseconds"),
                    "end":   datetime.datetime.now(datetime.timezone.utc)
                                .isoformat(timespec="milliseconds"),
                    "hosts": [], "queried": 0, "failed": 0,
                    "host_count": 0, "console_errors": [],
                    "failed_subresources": [], "title": "",
                    "main_frame_loaded": False, "http_status": 0,
                }
                print(f"HARNESS_ERROR: {e}")
            else:
                print(f"{rec['status']:13s} hosts={rec['host_count']:3d} "
                      f"({rec['elapsed_s']:.1f}s)")
            out.write(json.dumps(rec) + "\n")
            out.flush()
            time.sleep(2.0)   # quiet gap for cloakdns log partitioning

    print(f"done. wrote {visits_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
