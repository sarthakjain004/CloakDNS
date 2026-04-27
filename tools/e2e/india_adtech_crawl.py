"""
India-adtech extended crawler — bot-bypass-equipped Playwright crawl
that re-runs the sites which failed (or got bot-blocked) in the
original E2E india-top100 sweep, plus a handful of additional Indian
sites for breadth.

Bot-detection bypass:
    * playwright-stealth (patches navigator.webdriver, plugins,
      languages, chrome.runtime, permissions etc. — the stuff Akamai
      Bot Manager / Cloudflare / DataDome read).
    * Headed Chromium (some bot stacks gate on the headless signal).
    * Realistic UA + viewport matching a desktop user.

Output is a visits.jsonl in the same shape as crawl.py emits, dropped
under results/E2E/india-top100-extra/. The downstream miner
(tools/e2e/india_adtech_mine.py) then re-runs to discover new
candidate vendors that weren't visible in the original sweep.

Usage (from project root):
    python tools/e2e/india_adtech_crawl.py
"""
from __future__ import annotations
import datetime, json, pathlib, sys, time, urllib.parse

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUTDIR = ROOT / "results" / "E2E" / "india-top100-extra"
OUTDIR.mkdir(parents=True, exist_ok=True)

# Sites that failed in the original sweep (E2E_india_top100.md headline:
# "Sites broken under cloakdns: 25"). These are the priority targets —
# bot-detection on Indian e-commerce + news was the most likely cause.
FAILED_SITES = [
    "myntra.com", "meesho.com", "nykaa.com", "ajio.com", "bigbasket.com",
    "firstcry.com", "tatacliq.com", "croma.com", "shopclues.com",
    "zee5.com", "jiosaavn.com",
    "timesofindia.indiatimes.com", "ndtv.com", "hindustantimes.com",
    "thehindu.com", "news18.com", "zeenews.india.com", "moneycontrol.com",
    "business-standard.com", "firstpost.com",
    "irctc.co.in", "makemytrip.com", "goibibo.com", "yatra.com",
    "redbus.in",
]

# Additional Indian top-50 sites worth covering for adtech-stack
# breadth (food delivery, fintech, edtech — different tracker stacks
# than news/ecomm).
EXTRA_SITES = [
    "swiggy.com", "zomato.com", "dunzo.com",
    "paytm.com", "phonepe.com", "groww.in",
    "byjus.com", "vedantu.com", "unacademy.com",
    "ola.cabs", "uber.com",
]

CORPUS = FAILED_SITES + EXTRA_SITES


def _hostname(url: str) -> str | None:
    try: return urllib.parse.urlparse(url).hostname
    except (ValueError, AttributeError): return None


def crawl_one(playwright, domain: str,
              nav_timeout_ms: int = 45_000,
              post_load_wait_ms: int = 10_000) -> dict:
    """Visit one site under stealth + headed Chromium. Returns the
    same record shape as crawl.py's crawl_site()."""
    from playwright_stealth import Stealth

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

    # Headed Chromium — some bot stacks (Akamai, DataDome) gate on the
    # headless signal even after stealth patches navigator.webdriver.
    # Realistic launch flags + Sec-CH-UA that matches a current Chrome.
    browser = playwright.chromium.launch(
        headless=False,
        args=[
            "--disable-blink-features=AutomationControlled",
            "--disable-features=IsolateOrigins,site-per-process",
            "--no-sandbox",
            "--disable-dev-shm-usage",
        ],
    )
    try:
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/132.0.0.0 Safari/537.36",
            viewport={"width": 1366, "height": 768},
            locale="en-IN",
            timezone_id="Asia/Kolkata",
            ignore_https_errors=True,
            extra_http_headers={
                "Accept-Language": "en-IN,en;q=0.9,hi;q=0.8",
                "sec-ch-ua": '"Not A(Brand";v="99", "Google Chrome";v="132", "Chromium";v="132"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
            },
        )
        # Apply stealth patches at the context level.
        Stealth().apply_stealth_sync(context)

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
        except Exception as e:
            status = "net_error"
            console_errors.append(f"goto: {e}")

        if status == "ok" and main_frame_loaded:
            try: page.wait_for_timeout(post_load_wait_ms)
            except Exception: pass

        # Best-effort cookie-banner accept.
        for sel in ("button:has-text('Accept all')",
                    "button:has-text('Accept All')",
                    "button:has-text('Accept')",
                    "button:has-text('Agree')",
                    "[aria-label*='accept' i]"):
            try:
                btn = page.query_selector(sel)
                if btn:
                    btn.click(timeout=1500)
                    page.wait_for_timeout(2000)
                    break
            except Exception: pass

        try: title = (page.title() or "")[:120]
        except Exception: pass

        try:
            page.close(); context.close()
        except Exception: pass
    finally:
        try: browser.close()
        except Exception: pass

    if not main_frame_loaded and status == "ok":
        status = "http_error"

    requested_hosts.discard(""); requested_hosts.discard(None)
    hosts = sorted(h for h in requested_hosts if h and "." in h)

    end_wall = datetime.datetime.now(datetime.timezone.utc)
    return {
        "site":               domain,
        "url":                f"https://{domain}/",
        "start":              start_wall.isoformat(timespec="milliseconds"),
        "end":                end_wall.isoformat(timespec="milliseconds"),
        "elapsed_s":          round(time.monotonic() - start_mono, 3),
        "http_status":        http_status,
        "main_frame_loaded":  main_frame_loaded,
        "status":             status,
        "title":              title,
        "host_count":         len(hosts),
        "hosts":              hosts,
        "console_errors":     console_errors[:20],
        "failed_subresources": failed_subresources[:20],
    }


def main():
    from playwright.sync_api import sync_playwright
    out_path = OUTDIR / "visits.jsonl"
    out_path.write_text("")  # truncate

    print(f"Crawling {len(CORPUS)} sites with stealth + headed Chromium")
    print(f"Output: {out_path}\n")

    with sync_playwright() as pw:
        for i, site in enumerate(CORPUS, 1):
            print(f"[{i}/{len(CORPUS)}] {site}", flush=True)
            try:
                rec = crawl_one(pw, site)
            except Exception as e:
                rec = {
                    "site": site,
                    "status": "crawl_exception",
                    "hosts": [], "host_count": 0,
                    "console_errors": [str(e)[:200]],
                    "failed_subresources": [],
                }
            with out_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
            print(f"   status={rec.get('status')} hosts={rec.get('host_count', 0)} "
                  f"http={rec.get('http_status', 0)} elapsed={rec.get('elapsed_s', 0):.1f}s",
                  flush=True)
            time.sleep(1.5)  # polite gap between sites

    print(f"\ndone. wrote {len(CORPUS)} records to {out_path}")


if __name__ == "__main__":
    sys.exit(main())
