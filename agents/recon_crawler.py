"""
Agent: Recon Crawler (replaces the mitmdump/Burp/Kali route entirely)
Drives a real headless browser (Playwright) to the target, captures every
network request the page actually makes, and automatically follows
same-origin links up to a page budget. No manual browsing required - you
give it a URL and a page count, it does the rest.

Writes findings in the same 'raw_traffic' schema the old mitmdump pipeline
used, so api_mapper.py needs zero changes.

Requires:
    pip install playwright
    playwright install chromium
    # Linux only, first time:
    playwright install-deps
"""

from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

import db

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)


def _same_origin(url, origin):
    try:
        return urlparse(url).netloc == origin
    except Exception:
        return False


def _attach_capture(page, captured):
    def on_response(response):
        try:
            req = response.request
            # Only keep API/data traffic, not every image/css/font asset
            if req.resource_type not in ("xhr", "fetch", "document"):
                return
            ctype = response.headers.get("content-type", "")
            body = ""
            if "json" in ctype or "text" in ctype:
                try:
                    body = response.text()[:5000]
                except Exception:
                    body = ""
            captured.append(
                {
                    "method": req.method,
                    "url": req.url,
                    "req_body": (req.post_data or "")[:2000],
                    "res_status": response.status,
                    "res_body": body,
                }
            )
        except Exception:
            pass  # a single bad response shouldn't kill the crawl

    page.on("response", on_response)


def run(session_id, start_url, max_pages=10, headless=True):
    origin = urlparse(start_url).netloc
    visited = set()
    to_visit = [start_url]
    captured = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        context = browser.new_context(user_agent=USER_AGENT)
        page = context.new_page()
        _attach_capture(page, captured)

        while to_visit and len(visited) < max_pages:
            url = to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)

            try:
                page.goto(url, wait_until="networkidle", timeout=15000)
            except Exception:
                continue  # dead link / timeout - skip and keep going

            try:
                hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
            except Exception:
                hrefs = []

            for href in hrefs:
                if _same_origin(href, origin) and href not in visited:
                    to_visit.append(href)

        browser.close()

    for entry in captured:
        db.add_finding(
            session_id=session_id,
            agent="recon_crawler",
            finding_type="raw_traffic",
            data=entry,
            target=origin,
        )

    return {"pages_visited": len(visited), "requests_captured": len(captured)}