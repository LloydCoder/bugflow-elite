#!/bin/bash
# ============================================================
# BugFlow Elite v6 — GitHub Setup Script
# Sets up git, creates private repo, pushes all code.
# Run ONCE on your VPS after deploying.
# Tinlance Limited | LloydCoder
# ============================================================

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
info() { echo -e "${BLUE}[i]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

echo ""
echo "🛡️  BugFlow Elite v6 — GitHub Setup"
echo "======================================"
echo ""

# ── Get GitHub credentials ─────────────────────────────────
read -p "Your GitHub username (e.g. LloydCoder): " GH_USER
read -p "GitHub Personal Access Token (needs repo scope): " GH_TOKEN
read -p "Repo name (default: bugflow-elite): " REPO_NAME
REPO_NAME=${REPO_NAME:-bugflow-elite}
REPO_ORG="Tinlance"

info "Creating private repo: ${REPO_ORG}/${REPO_NAME}"

# ── Create GitHub repo via API ─────────────────────────────
HTTP_CODE=$(curl -s -o /tmp/gh_response.json -w "%{http_code}" \
    -X POST \
    -H "Authorization: token ${GH_TOKEN}" \
    -H "Accept: application/vnd.github.v3+json" \
    "https://api.github.com/orgs/${REPO_ORG}/repos" \
    -d "{
        \"name\": \"${REPO_NAME}\",
        \"description\": \"BugFlow Elite v6 — Autonomous Bug Bounty Platform\",
        \"private\": true,
        \"auto_init\": false
    }")

if [ "${HTTP_CODE}" = "201" ]; then
    log "Private repo created: github.com/${REPO_ORG}/${REPO_NAME}"
elif [ "${HTTP_CODE}" = "422" ]; then
    warn "Repo already exists — continuing with existing repo"
else
    # Try personal account if org fails
    HTTP_CODE=$(curl -s -o /tmp/gh_response.json -w "%{http_code}" \
        -X POST \
        -H "Authorization: token ${GH_TOKEN}" \
        -H "Accept: application/vnd.github.v3+json" \
        "https://api.github.com/user/repos" \
        -d "{
            \"name\": \"${REPO_NAME}\",
            \"description\": \"BugFlow Elite v6 — Autonomous Bug Bounty Platform\",
            \"private\": true
        }")
    if [ "${HTTP_CODE}" = "201" ]; then
        log "Private repo created under personal account: github.com/${GH_USER}/${REPO_NAME}"
        REPO_ORG="${GH_USER}"
    else
        warn "Could not create repo automatically. Create it manually at github.com/new"
        read -p "Enter your repo URL after creating it: " MANUAL_URL
    fi
fi

REPO_URL="${MANUAL_URL:-https://github.com/${REPO_ORG}/${REPO_NAME}.git}"

# ── Configure git ──────────────────────────────────────────
git config --global user.name "LloydCoder"
git config --global user.email "lloyd@tinlance.com"
git config --global init.defaultBranch main

# ── Initialize git if needed ───────────────────────────────
if [ ! -d ".git" ]; then
    git init
    log "Git initialized"
fi

# ── Store credentials ──────────────────────────────────────
git config credential.helper store
echo "https://${GH_USER}:${GH_TOKEN}@github.com" > ~/.git-credentials
chmod 600 ~/.git-credentials
log "GitHub credentials stored"

# ── Add remote ─────────────────────────────────────────────
git remote remove origin 2>/dev/null || true
git remote add origin "${REPO_URL}"
log "Remote added: ${REPO_URL}"

# ── Initial commit ─────────────────────────────────────────
git add -A
git commit -m "feat: BugFlow Elite v6 — Initial commit

51 Python modules | 128 tests | 16 pipeline stages
Tinlance Limited | LloydCoder @lloydambition"

# ── Push ───────────────────────────────────────────────────
git push -u origin main
log "Code pushed to GitHub"

# ── Setup automatic backup cron ────────────────────────────
CRON_JOB="0 */6 * * * cd ${SCRIPT_DIR} && bash backup.sh >> ${SCRIPT_DIR}/output/backup.log 2>&1"
(crontab -l 2>/dev/null | grep -v "backup.sh"; echo "${CRON_JOB}") | crontab -
log "Auto-backup cron installed (every 6 hours)"

# ── Create develop branch ──────────────────────────────────
git checkout -b develop
git push -u origin develop
git checkout main
log "Branch 'develop' created for safe testing"

echo ""
echo "======================================"
log "GitHub setup complete!"
echo "======================================"
echo ""
echo "  Repo:       ${REPO_URL}"
echo "  Branches:   main (production), develop (testing)"
echo "  Auto-backup: every 6 hours → commits to main"
echo ""
info "Next: Go to GitHub → Settings → Branches"
info "Add protection rule on 'main' branch"
