#!/bin/bash
# ============================================================
# BugFlow Elite v6 — Automated Backup Script
# Backs up:
#   1. SQLite database (all findings, assets, payouts)
#   2. Config files (scope, API key names — not values)
#   3. Learned patterns (FP tracker, program patterns)
#   4. Custom Nuclei templates
#   5. Pushes code changes to GitHub
# Run: bash backup.sh
# Schedule: added to crontab automatically
# Tinlance Limited | LloydCoder
# ============================================================

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="${SCRIPT_DIR}/backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
DATE=$(date +"%Y-%m-%d")

mkdir -p "${BACKUP_DIR}"

log "BugFlow Elite v6 — Backup starting at ${TIMESTAMP}"

# ── 1. Backup SQLite Database ─────────────────────────────
DB_PATH="${SCRIPT_DIR}/db/bugflow.db"
BACKUP_DB="${BACKUP_DIR}/bugflow_${TIMESTAMP}.db"

if [ -f "${DB_PATH}" ]; then
    # Use SQLite online backup (safe while running)
    sqlite3 "${DB_PATH}" ".backup '${BACKUP_DB}'"
    log "Database backed up: $(du -sh ${BACKUP_DB} | cut -f1)"
    
    # Also export findings as JSON for human-readable backup
    FINDINGS_JSON="${BACKUP_DIR}/findings_${DATE}.json"
    sqlite3 "${DB_PATH}" -json \
        "SELECT title, severity, vuln_type, ai_score, program, 
                h1_status, h1_draft_url, first_seen 
         FROM findings WHERE is_duplicate=0 
         ORDER BY ai_score DESC" > "${FINDINGS_JSON}" 2>/dev/null || true
    log "Findings exported to JSON"
    
    # Export payouts
    PAYOUTS_JSON="${BACKUP_DIR}/payouts_${DATE}.json"
    sqlite3 "${DB_PATH}" -json \
        "SELECT * FROM payouts ORDER BY paid_at DESC" \
        > "${PAYOUTS_JSON}" 2>/dev/null || true
    log "Payouts exported"
else
    warn "Database not found at ${DB_PATH} — skipping"
fi

# ── 2. Backup Learned Patterns ────────────────────────────
PATTERNS_DIR="${BACKUP_DIR}/patterns_${DATE}"
mkdir -p "${PATTERNS_DIR}"

for pattern_file in \
    "${SCRIPT_DIR}/output/fp_patterns.json" \
    "${SCRIPT_DIR}/output/program_patterns.json" \
    "${SCRIPT_DIR}/output/.scope_state.json" \
    "${SCRIPT_DIR}/output/.payout_last_check"; do
    if [ -f "${pattern_file}" ]; then
        cp "${pattern_file}" "${PATTERNS_DIR}/"
        log "Pattern backed up: $(basename ${pattern_file})"
    fi
done

# ── 3. Backup Custom Nuclei Templates ─────────────────────
TEMPLATES_DIR="${SCRIPT_DIR}/custom-templates"
if [ "$(ls -A ${TEMPLATES_DIR} 2>/dev/null | grep -v .gitkeep)" ]; then
    TEMPLATES_BACKUP="${BACKUP_DIR}/custom_templates_${DATE}.tar.gz"
    tar -czf "${TEMPLATES_BACKUP}" -C "${SCRIPT_DIR}" custom-templates/ 2>/dev/null
    log "Custom templates backed up: $(ls ${TEMPLATES_DIR} | wc -l) files"
fi

# ── 4. Rotate Old Backups (keep last 30 days) ─────────────
find "${BACKUP_DIR}" -name "bugflow_*.db" -mtime +30 -delete 2>/dev/null || true
find "${BACKUP_DIR}" -name "findings_*.json" -mtime +30 -delete 2>/dev/null || true
log "Old backups rotated (keeping 30 days)"

# ── 5. Push to GitHub ─────────────────────────────────────
cd "${SCRIPT_DIR}"

# Check if git is initialized
if [ ! -d ".git" ]; then
    warn "Git not initialized. Run setup_github.sh first."
else
    # Stage all changes
    git add -A
    
    # Check if there's anything to commit
    if git diff --staged --quiet; then
        log "No code changes to commit"
    else
        git commit -m "auto: backup ${TIMESTAMP} — $(git diff --staged --stat | tail -1)"
        
        # Push to GitHub
        if git push origin main 2>/dev/null; then
            log "Pushed to GitHub successfully"
        else
            warn "GitHub push failed — check your token. Files backed up locally."
        fi
    fi
fi

# ── 6. Backup Summary ─────────────────────────────────────
echo ""
log "Backup complete at ${TIMESTAMP}"
echo ""
echo "  Local backup: ${BACKUP_DIR}"
echo "  DB size:      $(du -sh ${BACKUP_DIR}/bugflow_${TIMESTAMP}.db 2>/dev/null | cut -f1 || echo 'N/A')"
echo "  GitHub:       $(git remote get-url origin 2>/dev/null || echo 'not configured')"
echo ""
