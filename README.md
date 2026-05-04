# Phishing Analyzer

## Project Overview

**Phishing Analyzer** analyzes suspected phishing URLs using a headless browser (Playwright, iPhone 14 emulation) and Claude AI verdict. Includes RDAP-based takedown helper.

- **Stack:** Python 3.12+, FastAPI, Playwright (Chromium), SQLite, Anthropic Claude API
- **Frontend:** Single-file vanilla HTML/CSS/JS (no framework)

## Requirements

- Python 3.12+
- Ubuntu 24.04 (or compatible Linux)
- An Anthropic API key
- A domain name (for HTTPS via Let's Encrypt)

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

> **Where to change:** Edit these variables in your `.env` file (or export them before running the server).

| Variable | Default | Description |
|----------|---------|-------------|
| `MODEL_PROVIDER` | `anthropic` | AI provider: `anthropic`, `bedrock`, or `openai` |
| `MODEL_NAME` | `claude-opus-4-7` | Model ID for the chosen provider |
| `ANTHROPIC_API_KEY` | — | Required when `MODEL_PROVIDER=anthropic` |
| `OPENAI_API_KEY` | — | Required when `MODEL_PROVIDER=openai` |
| `AWS_BEDROCK_REGION` | `us-east-1` | AWS region, when `MODEL_PROVIDER=bedrock` |
| `AWS_ACCESS_KEY_ID` | — | AWS credentials for Bedrock (or use IAM role) |
| `AWS_SECRET_ACCESS_KEY` | — | AWS credentials for Bedrock |

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
```

> **Vision requirement:** The model must support image inputs. For OpenAI use `gpt-4o` or `gpt-4-turbo`. For Bedrock use a `claude-3`/`claude-opus` variant that supports vision.

### External Intelligence APIs (optional)

| Variable | Source | Description |
|----------|--------|-------------|
| `URLSCAN_API_KEY` | urlscan.io | Increases rate limit; public results work without key |
| `VIRUSTOTAL_API_KEY` | virustotal.com | Required for VT URL lookups |
| `SHODAN_API_KEY` | shodan.io | Required for Shodan host lookups |
| `CENSYS_API_ID` | censys.io | Required for Censys host lookups |
| `CENSYS_API_SECRET` | censys.io | Required alongside `CENSYS_API_ID` |

All intel fields are optional — the app works without any of them.

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

# Set environment variables (PowerShell)
$env:ANTHROPIC_API_KEY = "sk-ant-..."
$env:APP_PASSWORD = "yourpassword"
$env:SECRET_KEY = "generate-with-command-above"

# Run
uvicorn main:app --port 8000 --reload
# Visit http://localhost:8000
```

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

> **Note:** Do NOT run `playwright install-deps` on Ubuntu 24.04 — it fails due to
> renamed packages (`libasound2`, `libicu70`, etc. no longer exist).
> The two packages above (`libpango-1.0-0 libcairo2`) are sufficient.

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
```
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

## Updating the App

```bash
cd /opt/phishing-analyzer
git pull
sudo systemctl restart phishing-analyzer
```

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

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| 502 Bad Gateway | App not running | `sudo systemctl restart phishing-analyzer` |
| Login not working | Missing `python-multipart` | `pip install python-multipart` |
| Session cookie errors | Missing `itsdangerous` | `pip install itsdangerous` |
| Playwright crashes | Missing system libs | `sudo apt install libpango-1.0-0 libcairo2` |
| Certbot fails | DNS not resolving yet | Wait for DNS propagation and retry |
| Screenshot dir error | Wrong permissions | `chown ubuntu:ubuntu /opt/phishing-analyzer/screenshots` |
