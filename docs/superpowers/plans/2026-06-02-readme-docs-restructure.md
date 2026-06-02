# README + Docs Restructure — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Slim README.md to a clean landing page with a Use Cases section, and move all operational detail into a new docs/deployment.md that reflects the current async pipeline and all 10 intel sources.

**Architecture:** Two-file documentation change. `docs/deployment.md` is created first (sourced from the existing README.md operational content, updated for recent features). `README.md` is then rewritten to the slim version. No code changes — verification is by line count and content grep.

**Tech Stack:** Markdown, git.

**Spec:** `docs/superpowers/specs/2026-06-02-readme-docs-restructure-design.md`

---

## File map

| File | Change |
|---|---|
| `docs/deployment.md` | **Create** — all operational content from current README, updated for async pipeline + 10 intel sources |
| `README.md` | **Rewrite** — slim landing page: header, use cases, features, tech stack, quick start, docs link |
| `CLAUDE.md` | No change |

---

## Task 1 — Create `docs/deployment.md`

**Files:**
- Create: `docs/deployment.md`

- [ ] **Step 1: Create `docs/deployment.md` with this exact content**

```bash
mkdir -p /path/to/repo/docs
```

Write the file at `docs/deployment.md`:

````markdown
# Phishing Analyzer — Deployment & Configuration Reference

Full guide for configuring, running locally, and deploying to production.  
For project overview and quick start, see [README.md](../README.md).

---

## Requirements

- Python 3.12+
- Ubuntu 24.04 (or compatible Linux)
- An Anthropic API key (or alternative — see Model Configuration below)
- A domain name (for HTTPS via Let's Encrypt in production)

---

## Environment Variables

### Required

| Variable | Description |
|----------|-------------|
| `APP_PASSWORD` | Password users enter on the login page |
| `SECRET_KEY` | Random string used to sign session cookies (never share this) |

Generate `SECRET_KEY`:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### Model Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MODEL_PROVIDER` | `anthropic` | AI provider: `anthropic`, `bedrock`, `openai`, or `openrouter` |
| `MODEL_NAME` | `claude-opus-4-7` | Model ID for the chosen provider |
| `ANTHROPIC_API_KEY` | — | Required when `MODEL_PROVIDER=anthropic` |
| `OPENAI_API_KEY` | — | Required when `MODEL_PROVIDER=openai` |
| `OPENROUTER_API_KEY` | — | Required when `MODEL_PROVIDER=openrouter` |
| `OPENROUTER_SITE_URL` | — | Optional: your site URL sent in OpenRouter headers |
| `OPENROUTER_SITE_NAME` | — | Optional: your app name sent in OpenRouter headers |
| `AWS_BEDROCK_REGION` | `us-east-1` | AWS region, when `MODEL_PROVIDER=bedrock` |
| `AWS_ACCESS_KEY_ID` | — | AWS credentials for Bedrock (or use IAM role) |
| `AWS_SECRET_ACCESS_KEY` | — | AWS credentials for Bedrock |

#### Supported providers

| Provider | `MODEL_PROVIDER` value | Key variable | Notes |
|----------|----------------------|--------------|-------|
| Anthropic (direct) | `anthropic` | `ANTHROPIC_API_KEY` | Best quality; uses prompt caching |
| AWS Bedrock | `bedrock` | IAM / `AWS_*` vars | Claude via your AWS account |
| OpenAI | `openai` | `OPENAI_API_KEY` | GPT-4o / GPT-4 Turbo |
| OpenRouter | `openrouter` | `OPENROUTER_API_KEY` | 200+ models, some free-tier |

#### Provider examples

```env
# Default — Anthropic direct API
MODEL_PROVIDER=anthropic
MODEL_NAME=claude-opus-4-7
ANTHROPIC_API_KEY=sk-ant-...

# AWS Bedrock (Claude via AWS)
MODEL_PROVIDER=bedrock
MODEL_NAME=anthropic.claude-opus-4-5-20241022-v1:0
AWS_BEDROCK_REGION=us-east-1
# Credentials via ~/.aws/credentials or IAM role — no key vars needed

# OpenAI
MODEL_PROVIDER=openai
MODEL_NAME=gpt-4o
OPENAI_API_KEY=sk-...

# OpenRouter — routes to 200+ models through one API key
MODEL_PROVIDER=openrouter
MODEL_NAME=google/gemini-2.0-flash-exp:free
OPENROUTER_API_KEY=sk-or-...
# Other vision-capable models on OpenRouter:
#   anthropic/claude-opus-4              (paid)
#   openai/gpt-4o                        (paid)
#   meta-llama/llama-3.2-90b-vision-instruct (paid)
#   google/gemini-2.0-flash-exp:free     (free, rate-limited)
#   mistralai/pixtral-large-2411         (paid)
```

> **Vision requirement:** The model must support image inputs. For OpenAI use `gpt-4o` or `gpt-4-turbo`. For Bedrock use a `claude-3`/`claude-opus` variant that supports vision. For OpenRouter, look for models tagged "multimodal" or "vision" at openrouter.ai/models.

#### Corporate / enterprise deployment notice

> **If deploying on a corporate or organizational network, consult your security, legal, and compliance teams before selecting an AI provider.** Screenshots of suspected phishing pages may contain sensitive information (brand assets, victim credentials, internal URLs). Anthropic and AWS Bedrock offer enterprise agreements with stronger data handling guarantees. Free-tier providers (e.g., some OpenRouter models) may log or use prompts for training.

### External Intelligence APIs

All fields are optional — the app works without any of them. Ten sources run in parallel on each analysis.

| Variable | Source | Free tier | Description |
|----------|--------|-----------|-------------|
| `URLSCAN_API_KEY` | urlscan.io | Yes (key increases rate limit) | Prior scans, verdicts, screenshot history |
| `VIRUSTOTAL_API_KEY` | virustotal.com | Yes (limited) | Multi-engine scan stats, threat names |
| `SHODAN_API_KEY` | shodan.io | No | Open ports, banners, vulnerability tags |
| `CENSYS_API_ID` + `CENSYS_API_SECRET` | censys.io | No | Host services, ASN, labels |
| `GOOGLE_SAFE_BROWSING_API_KEY` | console.cloud.google.com | Yes (free) | Phishing/malware lookup. Enable Safe Browsing API in Google Cloud Console. |
| `OTX_API_KEY` | otx.alienvault.com | Yes (free) | Domain/IP threat pulses. Find API key in OTX profile settings. |
| `ABUSEIPDB_API_KEY` | abuseipdb.com | Yes (1,000/day) | Hosting IP abuse confidence score. Find API key in account settings. |
| `PHISHTANK_API_KEY` | phishtank.com | Yes (optional) | Community phishing DB. Works without key but rate-limited. Register at phishtank.com/api_register.php. |

> **No credentials needed:** `crt.sh` (certificate transparency) and `URLhaus` (malware URL database) are queried automatically with no API key required.

---

## Local Development

```bash
# Clone
git clone https://github.com/netsecid/phishing-analyzer.git
cd phishing-analyzer

# Create venv
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install Playwright browser
playwright install chromium

# Set environment variables
cp /dev/null .env
echo 'APP_PASSWORD=yourpassword' >> .env
echo "SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')" >> .env
echo 'ANTHROPIC_API_KEY=sk-ant-...' >> .env

# Run
uvicorn main:app --port 8000 --reload
# Visit http://localhost:8000
```

### Analysis flow

`POST /api/analyze` returns a `case_id` immediately (< 1 s). The browser capture and all 10 threat intel sources then run in parallel in the background. Poll `GET /api/cases/{id}` to watch results arrive progressively:

- **~10 s** — intel tab populates (all 10 sources complete in parallel)
- **~30–120 s** — screenshot and page metadata arrive (Playwright nav timeout: 120 s)
- **~5 s after screenshot** — AI verdict and takedown report appear
- `status: "complete"` — all stages done

If the browser capture times out after 300 s, the AI still runs in text-only mode using the intel context, and the case is marked complete with whatever data was gathered.

---

## Production Deployment (Ubuntu 24.04 + Nginx + Let's Encrypt)

### 1. System dependencies

```bash
sudo apt update && sudo apt upgrade -y

sudo apt install -y \
  python3 python3-pip python3-venv \
  git nginx \
  certbot python3-certbot-nginx \
  libpango-1.0-0 libcairo2
```

> **Note:** Do NOT run `playwright install-deps` on Ubuntu 24.04 — it fails due to renamed packages. The two packages above (`libpango-1.0-0 libcairo2`) are sufficient.

### 2. Clone and install

```bash
cd /opt
sudo git clone https://github.com/netsecid/phishing-analyzer.git
sudo chown -R ubuntu:ubuntu /opt/phishing-analyzer
cd /opt/phishing-analyzer

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
playwright install chromium
deactivate
```

### 3. Environment variables

```bash
nano /opt/phishing-analyzer/.env
```
```env
# Required
APP_PASSWORD=your-login-password
SECRET_KEY=your-generated-secret-key

# Model provider (default: Anthropic)
MODEL_PROVIDER=anthropic
MODEL_NAME=claude-opus-4-7
ANTHROPIC_API_KEY=sk-ant-your-key-here

# Optional: external intel APIs
# URLSCAN_API_KEY=...
# VIRUSTOTAL_API_KEY=...
# SHODAN_API_KEY=...
# CENSYS_API_ID=...
# CENSYS_API_SECRET=...
# GOOGLE_SAFE_BROWSING_API_KEY=...
# OTX_API_KEY=...
# ABUSEIPDB_API_KEY=...
# PHISHTANK_API_KEY=...
```
```bash
chmod 600 /opt/phishing-analyzer/.env
```

### 4. Systemd service

```bash
sudo nano /etc/systemd/system/phishing-analyzer.service
```
```ini
[Unit]
Description=Phishing Analyzer FastAPI
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/opt/phishing-analyzer
EnvironmentFile=/opt/phishing-analyzer/.env
ExecStart=/opt/phishing-analyzer/venv/bin/uvicorn main:app \
    --host 127.0.0.1 \
    --port 8000 \
    --workers 2
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl daemon-reload
sudo systemctl enable phishing-analyzer
sudo systemctl start phishing-analyzer
```

### 5. Nginx

```bash
sudo nano /etc/nginx/sites-available/phishing-analyzer
```
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
        proxy_connect_timeout 10s;
    }

    location /static/ {
        alias /opt/phishing-analyzer/static/;
        expires 30d;
    }
}
```
```bash
sudo ln -sf /etc/nginx/sites-available/phishing-analyzer \
    /etc/nginx/sites-enabled/phishing-analyzer
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl restart nginx
sudo systemctl enable nginx
```

> **Timeout note:** `proxy_read_timeout 120s` is sufficient. Analysis now runs in the background — `POST /api/analyze` returns in under 1 second, and polling calls (`GET /api/cases/{id}`) complete instantly. The 120-second limit only applies to the "Refresh Intel" endpoint which may take up to ~15 s.

### 6. HTTPS with Let's Encrypt

```bash
sudo certbot --nginx -d your-domain.com
# When prompted, choose option 2 (Redirect HTTP to HTTPS)
```

SSL auto-renews via systemd timer — no manual action needed.

### 7. Verify

```bash
curl -I https://your-domain.com/
# Expect: HTTP/2 200 or redirect to /login

sudo systemctl status phishing-analyzer
# Expect: active (running)
```

---

## Updating the App

```bash
cd /opt/phishing-analyzer
git pull
sudo systemctl restart phishing-analyzer
```

---

## Useful Commands

```bash
# Live app logs
sudo journalctl -u phishing-analyzer -f

# Nginx error log
sudo tail -f /var/log/nginx/error.log

# Restart app
sudo systemctl restart phishing-analyzer

# Check SSL cert expiry
sudo certbot certificates
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| 502 Bad Gateway | App not running | `sudo systemctl restart phishing-analyzer` |
| Login not working | Missing `python-multipart` | `pip install python-multipart` |
| Session cookie errors | Missing `itsdangerous` | `pip install itsdangerous` |
| Playwright crashes | Missing system libs | `sudo apt install libpango-1.0-0 libcairo2` |
| Certbot fails | DNS not resolving yet | Wait for DNS propagation and retry |
| Screenshot dir error | Wrong permissions | `chown ubuntu:ubuntu /opt/phishing-analyzer/screenshots` |
| Analysis stuck on "running" | Background task crashed | Check `sudo journalctl -u phishing-analyzer -n 50` for traceback |
| Intel tab always empty | All API keys missing or network blocked | At least crt.sh and URLhaus work with no keys — check app logs |
````

- [ ] **Step 2: Verify the file exists and has the key sections**

```bash
wc -l docs/deployment.md
grep -n "^## " docs/deployment.md
```

Expected: ~180+ lines; section headers include Requirements, Environment Variables, Local Development, Production Deployment, Updating, Useful Commands, Troubleshooting.

Also verify all 4 new intel vars appear:
```bash
grep "GOOGLE_SAFE_BROWSING\|OTX_API_KEY\|ABUSEIPDB\|PHISHTANK" docs/deployment.md
```
Expected: 4 matches.

Verify the async flow note is present:
```bash
grep "case_id\|background\|parallel" docs/deployment.md
```
Expected: matches in the "Analysis flow" subsection.

- [ ] **Step 3: Commit**

```bash
git add docs/deployment.md
git commit -m "docs: add deployment.md with full operational reference"
```

---

## Task 2 — Rewrite `README.md`

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Replace README.md with the slim landing page**

Overwrite `README.md` with:

````markdown
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
````

- [ ] **Step 2: Verify the new README is concise and complete**

```bash
wc -l README.md
```
Expected: under 60 lines.

```bash
grep -n "^## " README.md
```
Expected: Use Cases, Features, Tech stack, Quick start — four sections.

```bash
grep "geo-targeted\|Privacy-first\|Centralized SOC\|deployment.md" README.md
```
Expected: all four strings found (three use case keywords + docs link).

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: slim README to landing page with use cases; move ops detail to docs/deployment.md"
```

---

## Self-review

- [x] **Spec coverage**
  - README slim landing page → Task 2 ✓
  - Use Cases section (all 3) → Task 2 ✓
  - Features bullet list → Task 2 ✓
  - Quick start (local only) → Task 2 ✓
  - Docs link → Task 2 ✓
  - `docs/deployment.md` created → Task 1 ✓
  - All env vars (required + model + 10 intel sources) → Task 1 ✓
  - 4 new intel vars (GSB, OTX, AbuseIPDB, PhishTank) → Task 1 ✓
  - crt.sh + URLhaus no-credentials note → Task 1 ✓
  - Async pipeline flow documented → Task 1 (Analysis flow subsection) ✓
  - Extended timeouts noted (120s nav, 300s subprocess) → Task 1 ✓
  - nginx proxy_read_timeout note updated → Task 1 ✓
  - New troubleshooting rows (stuck "running", empty intel tab) → Task 1 ✓
  - CLAUDE.md unchanged → no task needed ✓

- [x] **Placeholder scan:** No TBDs, no "add appropriate content" — all markdown is fully written out.

- [x] **Consistency:** docs link in README points to `docs/deployment.md` which is the exact file created in Task 1. Section names match between spec and plan.
