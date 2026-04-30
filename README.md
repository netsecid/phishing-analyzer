# Phishing Analyzer

A web-based tool for investigating suspicious URLs. Captures full-page screenshots via a mobile-emulated headless browser, runs AI-powered phishing detection using Claude, and generates takedown reports with registrar/hosting intel.

## Features

- **Mobile-emulated screenshot capture** — iPhone 14 UA, 390×844 viewport, 3× device scale, SSL errors ignored
- **AI phishing detection** — Claude Opus 4.7 vision analysis: verdict, confidence score, brand impersonation, risk indicators
- **Takedown report generation** — RDAP/WHOIS registrar lookup, IP/ASN info, pre-filled abuse email templates
- **Case history** — every analysis persisted in SQLite with full audit trail
- **Session authentication** — signed cookie, 8-hour expiry, single shared password

## Architecture

```
FastAPI (main.py)
  ├── analyze.py       — Playwright headless Chromium subprocess
  ├── ai_analysis.py   — Claude API vision call (phishing verdict)
  ├── takedown.py      — RDAP + ipinfo.io lookups, email template
  └── database.py      — SQLite via sqlite3 (cases table)

static/
  ├── login.html       — Password login page
  └── index.html       — Dashboard: analysis form, results, case history
```

## Setup

### Prerequisites

- Python 3.10+
- An Anthropic API key

### Install

```bash
pip install -r requirements.txt

# Install Playwright's Chromium + system dependencies
playwright install chromium
playwright install-deps chromium
```

### Environment variables

Create a `.env` file (or export to your shell):

```bash
ANTHROPIC_API_KEY=sk-ant-...
APP_PASSWORD=your-login-password
SECRET_KEY=a-random-secret-for-signing-sessions
```

### Run

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

Then open `http://localhost:8000` in your browser.

## Usage

1. Log in with `APP_PASSWORD`.
2. Paste a suspicious URL and click **Analyze**.
3. The tool will:
   - Launch a headless Chromium browser (iPhone 14 emulation) and capture a full-page screenshot
   - Send the screenshot to Claude for phishing analysis
   - If verdict is `phishing` or `suspicious`, automatically look up registrar and hosting info and generate an abuse report email
4. Results display the AI verdict (with confidence bar and risk indicators), the screenshot, HTTP metadata, and takedown info.
5. Use the **Copy** buttons to copy the abuse email subject/body to your clipboard.
6. All cases are saved and browsable in the history table at the bottom.

## AI Verdict Categories

| Verdict | Meaning |
|---|---|
| `phishing` | High-confidence malicious page |
| `suspicious` | Potentially malicious, needs review |
| `legitimate` | No phishing indicators found |
| `inconclusive` | Cannot determine (page blocked, CAPTCHA, etc.) |

Recommended actions: `takedown`, `monitor`, or `dismiss`.

## `analyze.py` CLI (standalone)

The capture script can be run directly without the web server:

```bash
# Human-readable output
python analyze.py https://suspicious-site.example.com

# JSON output (for scripting)
python analyze.py https://suspicious-site.example.com --json
```

Output: full-page PNG in `screenshots/`, plus page title, final URL after redirects, HTTP status, and response headers.

## Notes

- SSL certificate errors are intentionally ignored — phishing pages often use self-signed or expired certs
- The Playwright subprocess has a 90-second hard timeout; screenshots are still returned on soft network-idle timeout
- Claude API calls use prompt caching (`cache_control: ephemeral`) on the system prompt
- RDAP lookups go through `rdap.org`; IP info through `ipinfo.io` (no API key required for basic usage)
- The database auto-migrates its schema on first startup
