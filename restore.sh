#!/bin/bash
# ============================================================
# BugFlow Elite v6 — Full VPS Restore Script
# If your VPS dies, run this on a fresh Ubuntu VPS and
# everything is back in 15 minutes.
# Usage: bash restore.sh [github_repo_url] [backup_db_path]
# Example: bash restore.sh https://github.com/Tinlance/bugflow-elite
# Tinlance Limited | LloydCoder
# ============================================================

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
info() { echo -e "${BLUE}[i]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }

GITHUB_REPO="${1:-}"
BACKUP_DB="${2:-}"
INSTALL_DIR="/opt/bugflow-elite"

echo ""
echo "🛡️  BugFlow Elite v6 — Full Restore"
echo "======================================"
echo ""

if [ -z "${GITHUB_REPO}" ]; then
    read -p "GitHub repo URL (e.g. https://github.com/Tinlance/bugflow-elite): " GITHUB_REPO
fi

# ── Step 1: Install Docker ─────────────────────────────────
log "Installing Docker..."
apt-get update -qq
curl -fsSL https://get.docker.com | sh > /dev/null 2>&1
apt-get install -y docker-compose-plugin > /dev/null 2>&1
log "Docker installed"

# ── Step 2: Install dependencies ──────────────────────────
apt-get install -y git sqlite3 ufw nginx apache2-utils curl > /dev/null 2>&1
log "Dependencies installed"

# ── Step 3: Clone from GitHub ──────────────────────────────
if [ -d "${INSTALL_DIR}" ]; then
    warn "Directory exists — pulling latest instead of fresh clone"
    cd "${INSTALL_DIR}" && git pull
else
    git clone "${GITHUB_REPO}" "${INSTALL_DIR}"
    log "Cloned from GitHub"
fi

cd "${INSTALL_DIR}"

# ── Step 4: Restore .env ───────────────────────────────────
if [ ! -f ".env" ]; then
    cp .env.example .env
    warn ".env created from template — you must fill in your API keys!"
    warn "Edit: nano ${INSTALL_DIR}/.env"
    echo ""
    echo "Required keys to fill in:"
    echo "  H1_API_TOKEN"
    echo "  H1_USERNAME"
    echo "  TELEGRAM_BOT_TOKEN"
    echo "  TELEGRAM_CHAT_ID"
    echo "  GITHUB_TOKEN"
    echo ""
    read -p "Press Enter after filling in .env to continue..."
fi

# ── Step 5: Restore Database ───────────────────────────────
mkdir -p db

if [ -n "${BACKUP_DB}" ] && [ -f "${BACKUP_DB}" ]; then
    cp "${BACKUP_DB}" "db/bugflow.db"
    log "Database restored from: ${BACKUP_DB}"
    
    # Show what was recovered
    FINDINGS=$(sqlite3 db/bugflow.db "SELECT COUNT(*) FROM findings WHERE is_duplicate=0" 2>/dev/null || echo 0)
    ASSETS=$(sqlite3 db/bugflow.db "SELECT COUNT(*) FROM assets" 2>/dev/null || echo 0)
    PAYOUTS=$(sqlite3 db/bugflow.db "SELECT COALESCE(SUM(amount),0) FROM payouts" 2>/dev/null || echo 0)
    log "Recovered: ${FINDINGS} findings, ${ASSETS} assets, \$${PAYOUTS} payouts"
else
    warn "No backup DB provided — starting fresh"
    warn "To restore from backup: bash restore.sh REPO_URL backups/bugflow_TIMESTAMP.db"
fi

# ── Step 6: Restore Patterns ───────────────────────────────
mkdir -p output

# Find latest patterns backup if it exists
LATEST_PATTERNS=$(ls -t backups/patterns_*/fp_patterns.json 2>/dev/null | head -1)
if [ -n "${LATEST_PATTERNS}" ]; then
    PATTERNS_DIR=$(dirname "${LATEST_PATTERNS}")
    cp "${PATTERNS_DIR}"/*.json output/ 2>/dev/null || true
    log "Learned patterns restored"
fi

# ── Step 7: Deploy ─────────────────────────────────────────
log "Deploying BugFlow Elite v6..."

# Change Streamlit port to 8502 (don't conflict with trading bot)
sed -i 's/"8501:8501"/"8502:8501"/g' docker-compose.yml

docker compose up -d --build
log "Docker containers started"

# ── Step 8: Security ───────────────────────────────────────
log "Running security hardening..."
bash setup_security.sh

# ── Step 9: Setup backups cron ─────────────────────────────
CRON_JOB="0 */6 * * * cd ${INSTALL_DIR} && bash backup.sh >> ${INSTALL_DIR}/output/backup.log 2>&1"
(crontab -l 2>/dev/null | grep -v "backup.sh"; echo "${CRON_JOB}") | crontab -
log "Backup cron installed (every 6 hours)"

# ── Done ───────────────────────────────────────────────────
echo ""
echo "======================================"
log "Restore complete!"
echo "======================================"
echo ""
echo "  Dashboard: http://$(curl -s ifconfig.me):8502"
echo "  Send /status to your Telegram bot to verify"
echo ""
warn "If this is a fresh VPS, re-run: bash setup_security.sh"
