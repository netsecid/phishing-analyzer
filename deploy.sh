#!/bin/bash
set -e

# ── Phishing Analyzer — Production Deploy Script ──
# Tested on: Ubuntu 24.04
# Run as: ubuntu user (not root)
# Usage: bash deploy.sh

echo "🦑 Phishing Analyzer — Deploy Script"
echo "======================================"

# Guard: don't run as root
if [ "$EUID" -eq 0 ]; then
  echo "❌ Don't run this as root. Run as the ubuntu user."
  exit 1
fi

# ── Collect inputs ──
read -p "Enter your domain name (e.g. phishing.example.com): " DOMAIN
read -p "Enter your Anthropic API key: " ANTHROPIC_API_KEY
read -s -p "Enter your APP_PASSWORD (login password): " APP_PASSWORD
echo ""

# Generate SECRET_KEY
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

echo ""
echo "✅ Inputs collected. Starting deployment..."
echo ""

# ── Step 1: System packages ──
echo "📦 Step 1/7 — Installing system packages..."
sudo apt update -q
sudo apt install -y \
  python3 python3-pip python3-venv \
  git nginx \
  certbot python3-certbot-nginx \
  libpango-1.0-0 libcairo2

# ── Step 2: Clone repo ──
echo "📥 Step 2/7 — Cloning repository..."
sudo rm -rf /opt/phishing-analyzer
sudo git clone https://github.com/netsecid/phishing-analyzer.git /opt/phishing-analyzer
sudo chown -R ubuntu:ubuntu /opt/phishing-analyzer

# ── Step 3: Python venv + dependencies ──
echo "🐍 Step 3/7 — Setting up Python environment..."
cd /opt/phishing-analyzer
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q
playwright install chromium
deactivate

# ── Step 4: .env file ──
echo "🔑 Step 4/7 — Writing .env file..."
cat > /opt/phishing-analyzer/.env <<EOF
ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
APP_PASSWORD=${APP_PASSWORD}
SECRET_KEY=${SECRET_KEY}
EOF
chmod 600 /opt/phishing-analyzer/.env

# ── Step 5: Systemd service ──
echo "⚙️  Step 5/7 — Creating systemd service..."
sudo tee /etc/systemd/system/phishing-analyzer.service > /dev/null <<EOF
[Unit]
Description=Phishing Analyzer FastAPI
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/opt/phishing-analyzer
EnvironmentFile=/opt/phishing-analyzer/.env
ExecStart=/opt/phishing-analyzer/venv/bin/uvicorn main:app \\
    --host 127.0.0.1 \\
    --port 8000 \\
    --workers 2
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable phishing-analyzer
sudo systemctl start phishing-analyzer

# ── Step 6: Nginx ──
echo "🌐 Step 6/7 — Configuring Nginx..."
sudo tee /etc/nginx/sites-available/phishing-analyzer > /dev/null <<EOF
server {
    listen 80;
    server_name ${DOMAIN};

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 120s;
        proxy_connect_timeout 10s;
    }

    location /static/ {
        alias /opt/phishing-analyzer/static/;
        expires 30d;
    }
}
EOF

sudo ln -sf /etc/nginx/sites-available/phishing-analyzer \
    /etc/nginx/sites-enabled/phishing-analyzer
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl restart nginx
sudo systemctl enable nginx

# ── Step 7: HTTPS ──
echo "🔒 Step 7/7 — Getting SSL certificate..."
sudo certbot --nginx -d "${DOMAIN}" --non-interactive --agree-tos \
  --redirect -m "admin@${DOMAIN}"

# ── Done ──
echo ""
echo "✅ Deployment complete!"
echo "🌍 Visit: https://${DOMAIN}"
echo ""
echo "Useful commands:"
echo "  sudo journalctl -u phishing-analyzer -f   # live logs"
echo "  sudo systemctl restart phishing-analyzer  # restart app"
echo "  cd /opt/phishing-analyzer && git pull && sudo systemctl restart phishing-analyzer  # update"
