# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Phishing Analyzer is an internal web tool for security investigations. It captures full-page mobile screenshots of suspicious URLs via headless Chromium, runs Claude vision analysis to classify phishing/suspicious/legitimate/inconclusive, and generates takedown reports with registrar and hosting abuse contacts.

## Environment Setup

Create a `.env` file with these required variables:
```
APP_PASSWORD=your-login-password
SECRET_KEY=a-random-secret-for-signing-sessions

# AI provider (default: Anthropic)
MODEL_PROVIDER=anthropic
MODEL_NAME=claude-opus-4-7
ANTHROPIC_API_KEY=sk-ant-...

# Optional: external intel APIs
# URLSCAN_API_KEY=...
# VIRUSTOTAL_API_KEY=...
# SHODAN_API_KEY=...
# CENSYS_API_ID=...
# CENSYS_API_SECRET=...
```

Install dependencies:
```bash
pip install -r requirements.txt
playwright install chromium
playwright install-deps chromium   # Linux only
```

## Running the Application

```bash
# Start the web server
uvicorn main:app --host 0.0.0.0 --port 8000

# Run the CLI analyzer standalone
python analyze.py https://suspicious-site.example.com
python analyze.py https://suspicious-site.example.com --json

# Selenium alternative (for environments where Playwright fails)
python analyze-selenium.py https://suspicious-site.example.com --json
```

There is no formal test suite, linter configuration, or build system.

## Architecture

### Data Flow

```
POST /api/analyze
  → analyze.py (subprocess, 90s timeout)     # Chromium screenshot
  → database.py insert_case()                # SQLite case record
  → ai_analysis.py analyze_screenshot()      # Claude Opus vision → verdict
  → database.py update_case_ai_analysis()
  → takedown.py generate_takedown_report()   # only if phishing/suspicious
  → database.py update_case_takedown()
  → JSON response to frontend
```

### Module Responsibilities

- **`main.py`** — FastAPI entry point. Handles session auth (signed cookies via `itsdangerous`, 8-hour expiry, single shared `APP_PASSWORD`). Spawns `analyze.py` as a subprocess to isolate browser crashes from the server process. Mounts `/screenshots` as a static file directory.

- **`analyze.py`** — Playwright headless Chromium with iPhone 14 emulation (390×844 viewport, 3× scale, mobile user agent). SSL errors intentionally ignored — phishing pages routinely use bad certs. Waits for `networkidle`, 30s timeout. Returns JSON with screenshot path, final URL, title, status, and response headers.

- **`analyze-selenium.py`** — Mirrors `analyze.py` functionality using Selenium + Chrome DevTools Protocol mobile emulation. Use on systems where Playwright/Chromium has issues (added for Ubuntu 26.04).

- **`ai_analysis.py`** — Sends base64-encoded screenshot + URL metadata to Claude Opus 4.7. System prompt uses `cache_control: ephemeral` for prompt caching. Returns structured verdict: `verdict`, `confidence` (0–100), `brand_impersonated`, `risk_indicators`, `summary`, `recommended_action`. Falls back to `inconclusive` on any error.

- **`database.py`** — SQLite (`cases.db`). Schema auto-migrates on startup via `ALTER TABLE` calls that swallow `OperationalError` if columns already exist — no migration tool needed. All complex fields (headers, risk indicators, takedown data) stored as JSON strings.

- **`takedown.py`** — RDAP lookup via rdap.org (no auth required), IP/ASN lookup via ipinfo.io (no auth required), hardcoded `_ASN_ABUSE` dict mapping known CDN/cloud org names to their abuse email addresses. Generates pre-filled abuse report email.

### Authentication

Single-password, session-cookie auth. Cookies are signed (not encrypted) using `itsdangerous.URLSafeTimedSerializer`. All `/api/*` routes and `GET /` require a valid session cookie.

### Key Constraints

- Claude model is `claude-opus-4-7` (vision-capable, expensive) — do not downgrade without testing vision quality.
- SQLite is intentionally chosen (internal tool, single user); not suitable for concurrent writes.
- Takedown report is only auto-generated when verdict is `phishing` or `suspicious`.
- Screenshot paths are stored as absolute filesystem paths in the DB but served via `/screenshots/{filename}` URL.
