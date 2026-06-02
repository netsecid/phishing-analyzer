# Phishing Analyzer

An internal web tool for security investigations. Capture full-page mobile screenshots of suspicious URLs via headless Chromium, get an AI verdict, aggregate threat intelligence from 10 sources in parallel, and generate takedown reports — all in one place.

## Use Cases

**Geo-targeted phishing** — Advanced phishing kits serve content only to visitors from a specific country or ISP. Running your own browser emulation from the right network or VPS bypasses this restriction. Public scanners like URLScan and VirusTotal often see a blank page or a redirect when the kit detects a datacenter IP, so local capture is the only way to see the real page.

**Privacy-first analysis** — Before submitting a URL to public threat intel services, analyze it locally first. Useful when the URL contains internal hostnames, victim credentials in the path, or indicators that could tip off the attacker if queried from a known scanner IP. The local AI analysis and intel gathering give you a verdict without leaving a trace in public scan logs.

**Centralized SOC tooling** — SOC analysts working across timezones share one dedicated instance hosted in a controlled central location. Consistent tooling, a shared case history searchable by all analysts, and screenshot capture from a predictable vantage point — rather than each analyst running ad-hoc checks from their local machine.

## Features

- Full-page mobile screenshot via headless Chromium (iPhone 14 emulation, 3× scale)
- AI vision analysis — verdict: phishing / suspicious / legitimate / inconclusive — with confidence score
- 10 parallel threat intel sources: URLScan, VirusTotal, Shodan, Censys, Google Safe Browsing, OTX AlienVault, AbuseIPDB, crt.sh, URLhaus, PhishTank
- RDAP-based takedown report with registrar and hosting abuse contacts pre-filled
- One-click Google Safe Browsing report for confirmed phishing cases
- Progressive results — threat intel appears while the browser capture is still running
- Searchable case history with dark/light theme

## Tech stack

Python 3.12 · FastAPI · Playwright (Chromium) · SQLite · Claude API (or OpenAI / OpenRouter / AWS Bedrock)

## Quick start

```bash
git clone https://github.com/netsecid/phishing-analyzer.git
cd phishing-analyzer
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
playwright install chromium

# Create .env with the three required variables
echo 'APP_PASSWORD=yourpassword' >> .env
echo "SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')" >> .env
echo 'ANTHROPIC_API_KEY=sk-ant-...' >> .env

uvicorn main:app --port 8000 --reload
# Open http://localhost:8000
```

→ Full deployment guide, configuration reference, and troubleshooting: [docs/deployment.md](docs/deployment.md)
