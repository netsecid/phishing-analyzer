# Design: README + Docs Restructure

**Date:** 2026-06-02  
**Status:** Approved for implementation

---

## 1. Goals

1. Slim `README.md` down to a clean landing page serving both GitHub visitors and the internal team.
2. Move all operational detail (deployment, configuration, troubleshooting) to a single `docs/deployment.md`.
3. Add a **Use Cases** section to the README that explains the three concrete reasons to run this tool.
4. Leave `CLAUDE.md` unchanged.

---

## 2. `README.md` — target structure

Target length: ~80–90 lines. Contains only what a first-time reader needs to understand the tool and run it locally.

### Sections in order

**1. Header**
- Project name as H1
- One-sentence description: what it does (headless browser + AI verdict + intel aggregation + takedown helper)

**2. Use Cases**
Three concrete scenarios explaining when to reach for this tool over public alternatives:

- **Geo-targeted phishing** — Advanced phishing kits serve content only to visitors from a specific country or ISP. Running your own browser emulation from the right network/VPS bypasses this restriction. Public scanners (URLScan, VirusTotal) often see a blank page or a redirect when the kit detects a datacenter IP, so local capture is the only way to get the real page.

- **Privacy-first analysis** — Before submitting a URL to public threat intel services, run it locally first. Useful when the URL contains internal hostnames, victim credentials in the path, or indicators that could tip off the attacker if queried from a known scanner IP. The local AI analysis and intel gathering give you a verdict without leaving a trace in public scan logs.

- **Centralized SOC tooling** — SOC analysts working across timezones share one dedicated instance hosted in a controlled central location. This gives consistent tooling, a shared case history searchable by all analysts, and screenshot capture from a predictable vantage point — rather than each analyst running ad-hoc checks from their local machine.

**3. Features**
Bullet list:
- Full-page mobile screenshot via headless Chromium (iPhone 14 emulation)
- AI vision analysis — verdict: phishing / suspicious / legitimate / inconclusive
- 10 parallel threat intel sources (URLScan, VirusTotal, Shodan, Censys, Google Safe Browsing, OTX, AbuseIPDB, crt.sh, URLhaus, PhishTank)
- RDAP-based takedown report with registrar + hosting abuse contacts
- One-click Google Safe Browsing report for confirmed phishing
- Progressive results — intel appears while browser capture is still running
- Dark/light theme, searchable case history

**4. Tech stack**
One line: Python 3.12 · FastAPI · Playwright (Chromium) · SQLite · Claude API (or OpenAI / OpenRouter / AWS Bedrock)

**5. Quick start (local)**
Condensed to ~12 lines covering: clone, venv, pip install, playwright install chromium, create `.env` with 3 required vars, uvicorn.

**6. Documentation link**
Single line: `→ Full deployment guide, configuration reference, and troubleshooting: [docs/deployment.md](docs/deployment.md)`

---

## 3. `docs/deployment.md` — target structure

All operational content moved from `README.md`, kept verbatim where possible. New file header explains it is the full reference.

### Sections in order

1. Requirements (Python version, OS, domain name)
2. Environment Variables
   - Required (`APP_PASSWORD`, `SECRET_KEY`)
   - Model configuration (all providers: Anthropic, Bedrock, OpenAI, OpenRouter)
   - Provider examples (full `.env` snippets)
   - Vision requirement note
   - Corporate/enterprise deployment notice
   - External Intelligence APIs (all 10 sources including the 4 new ones: GSB, OTX, AbuseIPDB, PhishTank; note that crt.sh and URLhaus need no credentials)
3. Local Development (full steps)
4. Production Deployment (Ubuntu 24.04 + Nginx + Let's Encrypt)
   - System dependencies
   - Clone and install
   - Environment variables
   - Systemd service
   - Nginx config
   - HTTPS with Let's Encrypt
   - Verify
5. Updating the App
6. Useful Commands
7. Troubleshooting table

---

## 4. `CLAUDE.md` — unchanged

No changes. Already well-structured for Claude context. The `.env` example block and module descriptions were updated in a previous session.

---

## 5. Files changed

| File | Change |
|---|---|
| `README.md` | Rewritten to slim landing page with Use Cases section |
| `docs/deployment.md` | New file — all operational content from current README |
| `CLAUDE.md` | No change |
