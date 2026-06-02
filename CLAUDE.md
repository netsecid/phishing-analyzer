# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Phishing Analyzer is an internal web tool for security investigations. It captures full-page mobile screenshots of suspicious URLs via headless Chromium, runs AI vision analysis to classify phishing/suspicious/legitimate/inconclusive, and generates takedown reports with registrar and hosting abuse contacts. Confirmed phishing cases can be reported to Google Safe Browsing with one click.

## Dependencies Policy

**Always use the latest stable versions of all dependencies.** When adding or updating packages:
- Prefer `>=` version pins in `requirements.txt` so `pip install -r requirements.txt` pulls the newest compatible release.
- Before adding a new package, check PyPI for the current latest version and use that as the minimum bound.
- Do not introduce version upper bounds (`<`, `!=`) unless a specific incompatibility is known and documented.

## Environment Setup

Create a `.env` file with these required variables:
```
APP_PASSWORD=your-login-password
SECRET_KEY=a-random-secret-for-signing-sessions

# AI provider (default: Anthropic)
MODEL_PROVIDER=anthropic
MODEL_NAME=claude-opus-4-7
ANTHROPIC_API_KEY=sk-ant-...

# OpenRouter (alternative free/multi-model provider)
# MODEL_PROVIDER=openrouter
# MODEL_NAME=google/gemini-2.0-flash-exp:free
# OPENROUTER_API_KEY=sk-or-...

# Optional: external intel APIs
# URLSCAN_API_KEY=...
# VIRUSTOTAL_API_KEY=...
# SHODAN_API_KEY=...
# CENSYS_API_ID=...
# CENSYS_API_SECRET=...
# GOOGLE_SAFE_BROWSING_API_KEY=...  # console.cloud.google.com → Safe Browsing API (free)
# OTX_API_KEY=...                   # otx.alienvault.com → API key in profile (free)
# ABUSEIPDB_API_KEY=...             # abuseipdb.com → API tab in account (free, 1k/day)
# PHISHTANK_API_KEY=...             # phishtank.com/api_register.php (optional, rate-limit increase)
```

Install dependencies:
```bash
pip install -r requirements.txt
playwright install chromium
# Linux only — do NOT run playwright install-deps on Ubuntu 24.04 (package names changed)
# Instead: sudo apt install libpango-1.0-0 libcairo2
```

## Running the Application

```bash
# Start the web server (dev with reload)
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# Run the CLI analyzer standalone
python analyze.py https://suspicious-site.example.com --json

# Selenium alternative (for environments where Playwright fails, e.g. Ubuntu 26.04)
python analyze-selenium.py https://suspicious-site.example.com --json
```

There is no formal test suite, linter configuration, or build system.

## Production Deployment

`deploy.sh` automates the full Ubuntu 24.04 production setup (system packages, venv, systemd service, Nginx, Let's Encrypt). Run as non-root: `bash deploy.sh`. See README.md for the manual step-by-step equivalent.

## Architecture

### Data Flow

```
POST /api/analyze
  → analyze.py (subprocess, 90s timeout)     # Chromium screenshot
  → database.py insert_case()                # SQLite case record
  → ai_analysis.py analyze_screenshot()      # AI vision → verdict
  → database.py update_case_ai_analysis()
  → takedown.py generate_takedown_report()   # only if phishing/suspicious
  → database.py update_case_takedown()
  → intel.py gather_intel()                  # async, non-blocking on failure
  → JSON response to frontend
```

### Module Responsibilities

- **`main.py`** — FastAPI entry point. Handles session auth (signed cookies via `itsdangerous`, 8-hour expiry, single shared `APP_PASSWORD`). Spawns `analyze.py` as a subprocess to isolate browser crashes from the server process. Mounts `/screenshots` as an auth-gated static file route (not a plain `StaticFiles` mount — individual files require a valid session cookie).

- **`analyze.py`** — Playwright headless Chromium with iPhone 14 emulation (390×844 viewport, 3× scale, mobile user agent). SSL errors intentionally ignored — phishing pages routinely use bad certs. Waits for `networkidle`, 30s timeout. Returns JSON with screenshot path, final URL, title, status, and response headers.

- **`analyze-selenium.py`** — Mirrors `analyze.py` functionality using Selenium + Chrome DevTools Protocol mobile emulation.

- **`ai_analysis.py`** — Sends base64-encoded screenshot + URL metadata to the configured AI provider. Entry point is `analyze_with_claude()` (name is historical — it routes to any configured provider). Supports four providers via `MODEL_PROVIDER`:
  - `anthropic` (default) — direct API; uses `cache_control: ephemeral` for prompt caching on the system prompt.
  - `bedrock` — Claude via AWS Bedrock; uses IAM credentials.
  - `openai` — GPT-4o / GPT-4 Turbo.
  - `openrouter` — 200+ models via OpenRouter's OpenAI-compatible API.
  Returns structured verdict: `verdict`, `confidence` (0–100), `brand_impersonated`, `risk_indicators`, `summary`, `recommended_action`. Falls back to `inconclusive` on any error.

- **`database.py`** — SQLite (`cases.db`). Schema auto-migrates on startup via `ALTER TABLE` calls that swallow `OperationalError` if columns already exist. All complex fields (headers, risk indicators, takedown data, intel) stored as JSON strings.

- **`takedown.py`** — RDAP lookup via rdap.org, IP/ASN lookup via ipinfo.io (both auth-free). Hardcoded `_ASN_ABUSE` dict maps known CDN/cloud org names to their abuse email addresses. Generates a pre-filled abuse report email. Only called when verdict is `phishing` or `suspicious`.

- **`intel.py`** — External threat intelligence aggregator. `gather_intel()` resolves the domain IP then fans out to **ten sources in parallel** using `ThreadPoolExecutor`: URLScan.io, VirusTotal, Shodan, Censys (all existing), plus Google Safe Browsing lookup, OTX AlienVault, AbuseIPDB, crt.sh (certificate transparency), URLhaus, and PhishTank. Sources with no API key configured return a structured error dict and do not block others. Also generates `pivot_suggestions` — a rule-based list of hunt pivots (IP, domain, CT logs, brand, nameserver, registrar, ASN, OSINT) with pre-built query URLs for third-party platforms. Called in the background pipeline before AI analysis; results written to DB independently of browser capture.

### Frontend — `static/index.html` and `static/login.html`

Single-file vanilla HTML/CSS/JS, no build step. Key UI details:

- **Takedown tab** — Shows registrar/hosting details and pre-filled abuse email. When verdict is `phishing`, a red **"🛡 Report to Google Safe Browsing"** button is shown.
- **Intel tab** — Displays URLScan, VirusTotal, Shodan, Censys results plus the pivot suggestion cards generated by `intel.py`.
- **Theme** — Dark/light toggle stored in `localStorage`. CSS custom properties drive all colors; both pages share the same variable names.
- **Duplicate check** — On URL submission, the frontend calls `GET /api/cases/check?url=<url>` before posting to `/api/analyze` to surface existing cases for the same domain.

### API Endpoints

All `/api/*` routes require a valid session cookie.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/analyze` | Submit URL for analysis (long-running, ~30–90s) |
| `GET` | `/api/cases` | List all cases; `?search=<term>` for filtered search |
| `GET` | `/api/cases/{id}` | Fetch single case |
| `GET` | `/api/cases/check?url=<url>` | Check for existing cases by domain |
| `GET` | `/api/stats` | Aggregate verdict counts |
| `POST` | `/api/cases/{id}/takedown` | Regenerate takedown report |
| `POST` | `/api/cases/{id}/intel` | Refresh intel data |
| `GET` | `/screenshots/{filename}` | Serve screenshot (auth-gated) |

### Authentication

Single-password, session-cookie auth. Cookies are signed (not encrypted) using `itsdangerous.URLSafeTimedSerializer`. All `/api/*` routes and `GET /` require a valid session cookie.

### Key Constraints

- The default model is `claude-opus-4-7` (vision-capable) — do not downgrade without testing vision quality.
- All configured providers must support image/vision inputs; text-only models will fail silently and return `inconclusive`.
- SQLite is intentionally chosen (internal tool, single user); not suitable for concurrent writes.
- Screenshot paths are stored as absolute filesystem paths in the DB but served via `/screenshots/{filename}` URL.
