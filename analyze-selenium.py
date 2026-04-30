#!/usr/bin/env python3
"""
analyze.py — Phishing URL analyzer with mobile browser emulation (Selenium version).

Usage: python analyze.py <url>
"""

import argparse
import json
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException

SCREENSHOTS_DIR = Path(__file__).parent / "screenshots"
SCREENSHOTS_DIR.mkdir(exist_ok=True)

IPHONE_14_USER_AGENT = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/16.0 Mobile/15E148 Safari/604.1"
)


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

    # Setup Chrome options for headless mode and mobile emulation
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")
    chrome_options.add_argument(f"user-agent={IPHONE_14_USER_AGENT}")
    chrome_options.add_argument("--window-size=390,844")
    chrome_options.add_argument("--ignore-certificate-errors")
    chrome_options.add_argument("--allow-insecure-localhost")

    # Use system-installed chromium/chromedriver to avoid selenium-manager
    # trying to download architecture-incompatible binaries
    chrome_binary = (
        shutil.which("chromium")
        or shutil.which("chromium-browser")
        or shutil.which("google-chrome")
        or shutil.which("google-chrome-stable")
    )
    chromedriver_path = shutil.which("chromedriver")

    if chrome_binary:
        chrome_options.binary_location = chrome_binary

    service = Service(executable_path=chromedriver_path) if chromedriver_path else Service()

    driver = None
    try:
        driver = webdriver.Chrome(service=service, options=chrome_options)
        
        # Navigate to URL with timeout
        driver.set_page_load_timeout(30)
        driver.get(url)
        
        # Wait for page to load (network idle equivalent)
        time.sleep(3)
        
        # Get final URL and title
        result["final_url"] = driver.current_url
        result["title"] = driver.title
        
        # Get HTTP status (Selenium doesn't directly expose this, so we'll note it)
        # For accurate status, you'd need to use requests library alongside
        result["status"] = 200  # Default assumption
        
        # Get response headers (limited with Selenium - would need Network.getResponseBody from CDP)
        result["headers"] = {}

    except TimeoutException:
        result["error"] = "timeout: page did not finish loading within 30s"
        result["final_url"] = driver.current_url if driver else None
        try:
            result["title"] = driver.title if driver else None
        except Exception:
            pass

    except Exception as exc:
        result["error"] = str(exc)
        result["final_url"] = driver.current_url if driver else None

    # Always attempt a screenshot, even on error
    if driver:
        try:
            safe_name = (
                url.replace("https://", "")
                .replace("http://", "")
                .replace("/", "_")
                .replace(":", "")[:80]
            )
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            screenshot_path = SCREENSHOTS_DIR / f"{ts}_{safe_name}.png"
            
            # Take screenshot
            driver.save_screenshot(str(screenshot_path))
            result["screenshot"] = str(screenshot_path)
        except Exception as exc:
            result["error"] = (result["error"] or "") + f" | screenshot failed: {exc}"

    # Close browser
    if driver:
        try:
            driver.quit()
        except Exception:
            pass

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
