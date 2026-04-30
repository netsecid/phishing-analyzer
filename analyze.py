#!/usr/bin/env python3
"""
analyze.py — Phishing URL analyzer with mobile browser emulation.

Usage: python analyze.py <url>
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout

SCREENSHOTS_DIR = Path(__file__).parent / "screenshots"
SCREENSHOTS_DIR.mkdir(exist_ok=True)

IPHONE_14 = {
    "user_agent": (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) "
        "Version/16.0 Mobile/15E148 Safari/604.1"
    ),
    "viewport": {"width": 390, "height": 844},
    "device_scale_factor": 3,
    "is_mobile": True,
    "has_touch": True,
}


def analyze(url: str) -> dict:
    result = {
        "url_input": url,
        "final_url": None,
        "title": None,
        "status": None,
        "headers": {},
        "screenshot": None,
        "error": None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(
            **IPHONE_14,
            ignore_https_errors=True,  # phishing pages often have cert issues
            java_script_enabled=True,
        )
        page = context.new_page()

        response = None

        def handle_response(r):
            nonlocal response
            # capture the first navigation response (primary document)
            if response is None and r.request.resource_type == "document":
                response = r

        page.on("response", handle_response)

        try:
            nav_response = page.goto(
                url,
                timeout=30_000,
                wait_until="networkidle",
            )
            if nav_response:
                result["status"] = nav_response.status
                result["headers"] = dict(nav_response.headers)

            result["final_url"] = page.url
            result["title"] = page.title()

        except PlaywrightTimeout:
            result["error"] = "timeout: page did not finish loading within 30s"
            # still try to grab whatever loaded
            result["final_url"] = page.url
            try:
                result["title"] = page.title()
            except Exception:
                pass

        except Exception as exc:
            result["error"] = str(exc)
            result["final_url"] = page.url

        # always attempt a screenshot, even on error
        try:
            safe_name = (
                url.replace("https://", "")
                .replace("http://", "")
                .replace("/", "_")
                .replace(":", "")[:80]
            )
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            screenshot_path = SCREENSHOTS_DIR / f"{ts}_{safe_name}.png"
            page.screenshot(path=str(screenshot_path), full_page=True)
            result["screenshot"] = str(screenshot_path)
        except Exception as exc:
            result["error"] = (result["error"] or "") + f" | screenshot failed: {exc}"

        context.close()
        browser.close()

    return result


def main():
    parser = argparse.ArgumentParser(description="Analyze a URL for phishing indicators.")
    parser.add_argument("url", help="Target URL to analyze")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    args = parser.parse_args()

    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = analyze(url)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Input URL   : {result['url_input']}")
        print(f"Final URL   : {result['final_url']}")
        print(f"Title       : {result['title']}")
        print(f"HTTP Status : {result['status']}")
        print(f"Screenshot  : {result['screenshot']}")
        if result["error"]:
            print(f"Error       : {result['error']}", file=sys.stderr)
        print("\n--- Response Headers ---")
        for k, v in result["headers"].items():
            print(f"  {k}: {v}")

    sys.exit(1 if result["error"] else 0)


if __name__ == "__main__":
    main()
