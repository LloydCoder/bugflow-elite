#!/bin/bash
# ============================================================
# BugFlow Elite v6 — Security Hardening Setup
# Configures:
#   1. UFW firewall (restrict port 8501 to your IP)
#   2. Basic auth on dashboard (nginx reverse proxy)
#   3. Cloudflare Access tunnel setup guide
# Run as root on your Contabo VPS
# Tinlance Limited | LloydCoder
# ============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
info() { echo -e "${BLUE}[i]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }

echo ""
echo "🛡️  BugFlow Elite v6 — Security Hardening"
echo "==========================================="
echo ""

# Get your IP
YOUR_IP=$(curl -s https://ifconfig.me 2>/dev/null || curl -s https://api.ipify.org)
info "Your current IP: ${YOUR_IP}"
echo ""
read -p "Is this your correct home/office IP? (y/n): " confirm
if [[ "$confirm" != "y" ]]; then
    read -p "Enter your correct IP: " YOUR_IP
fi

# ── STEP 1: UFW Firewall ──────────────────────────────────────────────────

log "Setting up UFW firewall..."

apt-get install -y ufw > /dev/null 2>&1

# Reset to defaults
ufw --force reset > /dev/null 2>&1

# Default deny
ufw default deny incoming > /dev/null
ufw default allow outgoing > /dev/null

# Allow SSH from anywhere (don't lock yourself out!)
ufw allow ssh
log "SSH allowed from anywhere"

# Allow dashboard ONLY from your IP
ufw allow from "${YOUR_IP}" to any port 8501
log "Dashboard port 8501 restricted to ${YOUR_IP}"

# Allow Ollama only internally (not exposed to internet)
# 11434 stays internal — Docker handles this

# Allow HTTP/HTTPS for Cloudflare tunnel (if using)
ufw allow 80/tcp
ufw allow 443/tcp

# Enable
ufw --force enable
log "UFW firewall enabled"

ufw status numbered
echo ""

# ── STEP 2: Basic Auth with Nginx ─────────────────────────────────────────

log "Setting up Nginx + Basic Auth..."

apt-get install -y nginx apache2-utils > /dev/null 2>&1

read -p "Enter dashboard username (default: bugflow): " DASH_USER
DASH_USER=${DASH_USER:-bugflow}

read -s -p "Enter dashboard password: " DASH_PASS
echo ""
if [ -z "$DASH_PASS" ]; then
    DASH_PASS=$(openssl rand -base64 16)
    warn "Generated password: ${DASH_PASS}"
    warn "Save this password — it won't be shown again!"
fi

# Create htpasswd file
htpasswd -bc /etc/nginx/.htpasswd "${DASH_USER}" "${DASH_PASS}"
log "Basic auth credentials created for user: ${DASH_USER}"

# Write Nginx config
cat > /etc/nginx/sites-available/bugflow << NGINX_CONF
server {
    listen 80;
    server_name _;

    # Redirect to HTTPS if using Cloudflare (optional)
    # return 301 https://\$host\$request_uri;

    location / {
        # Basic auth
        auth_basic "BugFlow Elite v6";
        auth_basic_user_file /etc/nginx/.htpasswd;

        # IP restriction (belt + suspenders with UFW)
        allow ${YOUR_IP};
        deny all;

        # Proxy to Streamlit
        proxy_pass http://127.0.0.1:8501;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 86400;
    }
}
NGINX_CONF

# Enable site
ln -sf /etc/nginx/sites-available/bugflow /etc/nginx/sites-enabled/bugflow
rm -f /etc/nginx/sites-enabled/default

# Test and reload
nginx -t && systemctl reload nginx
log "Nginx configured with basic auth"

# ── STEP 3: Update Docker Compose to bind Streamlit to localhost only ─────

log "Updating Docker Compose to bind Streamlit to localhost only..."

COMPOSE_FILE="/opt/bugflow-elite/docker-compose.yml"
if [ -f "$COMPOSE_FILE" ]; then
    # Change 0.0.0.0:8501 to 127.0.0.1:8501 so only nginx can reach it
    sed -i 's/"8501:8501"/"127.0.0.1:8501:8501"/g' "$COMPOSE_FILE"
    log "Streamlit now bound to localhost only (Nginx is the public face)"
fi

# ── STEP 4: Cloudflare Access (Optional) ──────────────────────────────────

echo ""
echo "========================================================"
echo "  OPTIONAL: Cloudflare Access (Zero Trust) Setup"
echo "========================================================"
echo ""
info "Cloudflare Access adds enterprise-grade auth on top of basic auth."
info "Free tier supports up to 50 users. Recommended if you share access."
echo ""
echo "To set up Cloudflare Access (do this manually in browser):"
echo ""
echo "  1. Go to: https://dash.cloudflare.com"
echo "  2. Add your VPS IP as an A record: bugflow.yourdomain.com → ${YOUR_IP}"
echo "  3. Go to: Zero Trust → Access → Applications → Add application"
echo "  4. Select: Self-hosted"
echo "  5. App name: BugFlow Elite, Domain: bugflow.yourdomain.com"
echo "  6. Add policy: Allow → Emails → your@email.com"
echo "  7. Save — Cloudflare now protects the dashboard with email OTP"
echo ""
echo "  Alternatively, install cloudflared tunnel (no open ports needed):"
echo "  curl -L https://pkg.cloudflare.com/cloudflare-main.gpg | apt-key add -"
echo "  apt-get install cloudflared"
echo "  cloudflared tunnel login"
echo "  cloudflared tunnel create bugflow"
echo "  cloudflared tunnel route dns bugflow bugflow.yourdomain.com"
echo ""

# ── STEP 5: Summary ───────────────────────────────────────────────────────

echo ""
echo "========================================================"
log "Security hardening complete!"
echo "========================================================"
echo ""
echo "  Dashboard access:"
echo "  URL:       http://${YOUR_IP}:80  (via Nginx + basic auth)"
echo "  Username:  ${DASH_USER}"
echo "  Password:  [what you entered above]"
echo ""
echo "  Firewall rules:"
ufw status | grep -E "8501|22|80|443"
echo ""
echo "  To restart everything:"
echo "  cd /opt/bugflow-elite && docker compose restart"
echo ""
warn "Keep your IP updated in UFW if it changes: ufw delete + ufw allow from NEW_IP to any port 8501"
