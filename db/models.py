"""
BugFlow Elite v6 — Database Models
SQLite schema for persistent state across all scan runs.
Tinlance Limited | LloydCoder
"""

import sqlite3
import logging
from pathlib import Path
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


SCHEMA = """
-- ── Assets ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS assets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    domain          TEXT NOT NULL,
    subdomain       TEXT NOT NULL UNIQUE,
    ip              TEXT,
    status_code     INTEGER,
    title           TEXT,
    tech_stack      TEXT,           -- JSON array of detected technologies
    ports           TEXT,           -- JSON array of open ports
    first_seen      DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen       DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_alive        BOOLEAN DEFAULT 1,
    content_hash    TEXT,           -- SHA256 of page content for change detection
    screenshot_path TEXT,
    source          TEXT            -- bbot | subfinder | amass | crtsh
);

CREATE INDEX IF NOT EXISTS idx_assets_domain ON assets(domain);
CREATE INDEX IF NOT EXISTS idx_assets_subdomain ON assets(subdomain);

-- ── URLs & Endpoints ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS endpoints (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id        INTEGER REFERENCES assets(id),
    url             TEXT NOT NULL UNIQUE,
    method          TEXT DEFAULT 'GET',
    status_code     INTEGER,
    content_type    TEXT,
    source          TEXT,           -- katana | gau | waymore | js_analysis
    params          TEXT,           -- JSON array of discovered params
    first_seen      DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen       DATETIME DEFAULT CURRENT_TIMESTAMP,
    content_hash    TEXT,
    is_interesting  BOOLEAN DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_endpoints_asset ON endpoints(asset_id);

-- ── JS Files ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS js_files (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id        INTEGER REFERENCES assets(id),
    url             TEXT NOT NULL UNIQUE,
    content_hash    TEXT,
    endpoints_found TEXT,           -- JSON array of endpoints found inside
    secrets_found   TEXT,           -- JSON array of potential secrets found
    first_seen      DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen       DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ── Findings ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS findings (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id            INTEGER REFERENCES assets(id),
    title               TEXT NOT NULL,
    severity            TEXT NOT NULL,  -- critical | high | medium | low | info
    vuln_type           TEXT,           -- nuclei | takeover | cloud | secret | c2 | custom
    template_id         TEXT,           -- Nuclei template ID if applicable
    description         TEXT,
    reproduction_steps  TEXT,
    proof_of_concept    TEXT,           -- Request/response evidence
    screenshot_paths    TEXT,           -- JSON array of screenshot paths
    ai_score            FLOAT,          -- AI exploitability score (0-10)
    ai_analysis         TEXT,           -- Full AI triage output
    is_duplicate        BOOLEAN DEFAULT 0,
    duplicate_score     FLOAT,          -- Similarity score to known findings
    threatfade_c2       BOOLEAN DEFAULT 0,  -- Flagged by ThreatFade
    mitre_ttps          TEXT,           -- JSON array of MITRE TTPs
    cvss_score          FLOAT,
    cve_id              TEXT,
    h1_report_id        TEXT,           -- HackerOne Report Intent ID
    h1_draft_url        TEXT,
    h1_status           TEXT DEFAULT 'pending',  -- pending | drafted | submitted | resolved
    first_seen          DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen           DATETIME DEFAULT CURRENT_TIMESTAMP,
    program             TEXT            -- Bug bounty program name
);

CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_score ON findings(ai_score);
CREATE INDEX IF NOT EXISTS idx_findings_duplicate ON findings(is_duplicate);
CREATE INDEX IF NOT EXISTS idx_findings_program ON findings(program);

-- ── Secrets ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS secrets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id        INTEGER REFERENCES assets(id),
    source_url      TEXT,
    secret_type     TEXT,           -- aws_key | github_token | api_key | jwt | etc
    raw_value       TEXT,           -- Hashed/truncated for safety
    is_verified     BOOLEAN DEFAULT 0,
    source_tool     TEXT,           -- trufflehog | githound | jshunter | jsluice
    first_seen      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ── Cloud Assets ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cloud_assets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    domain          TEXT,
    provider        TEXT,           -- aws | gcp | azure | digitalocean
    asset_type      TEXT,           -- s3_bucket | gcs_bucket | azure_blob
    asset_name      TEXT,
    is_public       BOOLEAN DEFAULT 0,
    permissions     TEXT,           -- JSON: {list, read, write, delete}
    files_found     INTEGER DEFAULT 0,
    finding_id      INTEGER REFERENCES findings(id),
    first_seen      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ── Subdomain Takeovers ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS takeovers (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    subdomain       TEXT NOT NULL,
    record_type     TEXT,           -- cname | ns | mx | spf | srv | a
    record_value    TEXT,
    provider        TEXT,           -- heroku | github | s3 | azure | etc
    takeover_type   TEXT,           -- dangling_cname | dangling_ns | stale_a
    is_verified     BOOLEAN DEFAULT 0,
    finding_id      INTEGER REFERENCES findings(id),
    first_seen      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ── Scan Runs ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type       TEXT,           -- incremental | full
    program         TEXT,
    target          TEXT,
    status          TEXT DEFAULT 'running',  -- running | completed | failed
    assets_found    INTEGER DEFAULT 0,
    findings_found  INTEGER DEFAULT 0,
    drafts_created  INTEGER DEFAULT 0,
    started_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at    DATETIME,
    duration_secs   INTEGER,
    ai_cost_usd     FLOAT DEFAULT 0.0
);

-- ── AI Cost Tracking ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ai_costs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    provider        TEXT,           -- ollama | grok | claude
    model           TEXT,
    tokens_in       INTEGER DEFAULT 0,
    tokens_out      INTEGER DEFAULT 0,
    estimated_usd   FLOAT DEFAULT 0.0,
    operation       TEXT,           -- triage | template_gen | report_gen
    timestamp       DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ── Scope Cache ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scope_cache (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    platform        TEXT,
    program         TEXT,
    scope_data      TEXT,           -- JSON
    fetched_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ── Payouts ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS payouts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id       TEXT NOT NULL UNIQUE,
    title           TEXT,
    severity        TEXT,
    amount          FLOAT DEFAULT 0.0,
    platform        TEXT DEFAULT 'hackerone',
    program         TEXT,
    h1_url          TEXT,
    paid_at         DATETIME,
    noted_at        DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_payouts_program ON payouts(program);
CREATE INDEX IF NOT EXISTS idx_payouts_paid_at ON payouts(paid_at);

-- ── Attack Surface Graph ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS attack_surface_nodes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    node_type       TEXT NOT NULL,
    canonical_key   TEXT NOT NULL,
    attributes      TEXT NOT NULL DEFAULT '{}',
    fingerprint     TEXT,
    first_seen      DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen       DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_active       BOOLEAN DEFAULT 1,
    UNIQUE(tenant_id, node_type, canonical_key)
);

CREATE INDEX IF NOT EXISTS idx_as_nodes_type ON attack_surface_nodes(tenant_id, node_type);
CREATE INDEX IF NOT EXISTS idx_as_nodes_active ON attack_surface_nodes(tenant_id, is_active);

CREATE TABLE IF NOT EXISTS attack_surface_edges (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    source_node_id  INTEGER NOT NULL REFERENCES attack_surface_nodes(id),
    target_node_id  INTEGER NOT NULL REFERENCES attack_surface_nodes(id),
    edge_type       TEXT NOT NULL,
    source          TEXT NOT NULL,
    evidence_id     TEXT,
    first_seen      DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen       DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_active       BOOLEAN DEFAULT 1,
    UNIQUE(tenant_id, source_node_id, target_node_id, edge_type, source)
);

CREATE INDEX IF NOT EXISTS idx_as_edges_source ON attack_surface_edges(tenant_id, source_node_id);
CREATE INDEX IF NOT EXISTS idx_as_edges_target ON attack_surface_edges(tenant_id, target_node_id);

CREATE TABLE IF NOT EXISTS attack_surface_changes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    node_id         INTEGER NOT NULL REFERENCES attack_surface_nodes(id),
    change_type     TEXT NOT NULL,
    old_fingerprint TEXT,
    new_fingerprint TEXT,
    detected_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    run_id          TEXT,
    reason          TEXT
);

CREATE INDEX IF NOT EXISTS idx_as_changes_node ON attack_surface_changes(tenant_id, node_id);
CREATE INDEX IF NOT EXISTS idx_as_changes_detected ON attack_surface_changes(tenant_id, detected_at);

-- ── Finding Intelligence History ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS finding_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    novelty_key     TEXT NOT NULL,
    vuln_type       TEXT,
    target          TEXT,
    fingerprint     TEXT NOT NULL,
    first_seen      DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen       DATETIME DEFAULT CURRENT_TIMESTAMP,
    observation_count INTEGER DEFAULT 1,
    last_status     TEXT,
    metadata        TEXT NOT NULL DEFAULT '{}',
    UNIQUE(tenant_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_finding_history_novelty ON finding_history(tenant_id, novelty_key);
CREATE INDEX IF NOT EXISTS idx_finding_history_last_seen ON finding_history(tenant_id, last_seen);

-- ── Governance Audit Log ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS governance_audit (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id       TEXT NOT NULL,
    event_id        TEXT NOT NULL UNIQUE,
    actor           TEXT NOT NULL,
    action          TEXT NOT NULL,
    resource_type   TEXT NOT NULL,
    resource_id     TEXT,
    decision        TEXT,
    metadata        TEXT NOT NULL DEFAULT '{}',
    previous_hash   TEXT,
    event_hash      TEXT NOT NULL,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_governance_audit_tenant_time
ON governance_audit(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_governance_audit_resource
ON governance_audit(tenant_id, resource_type, resource_id);

-- ── Content Changes ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS content_changes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id        INTEGER REFERENCES assets(id),
    url             TEXT,
    old_hash        TEXT,
    new_hash        TEXT,
    diff_summary    TEXT,
    detected_at     DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""


def init_db(db_path: str) -> sqlite3.Connection:
    """Initialize the SQLite database, create tables if not exist."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")      # Better concurrency
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA cache_size=10000")

    conn.executescript(SCHEMA)
    conn.commit()

    logger.info(f"Database initialized at {db_path}")
    return conn


def get_conn(db_path: str) -> sqlite3.Connection:
    """Get a database connection."""
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ── Asset helpers ──────────────────────────────────────────────────────────

def upsert_asset(conn, subdomain: str, domain: str, **kwargs) -> int:
    """Insert or update an asset, return its ID."""
    now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    existing = conn.execute(
        "SELECT id FROM assets WHERE subdomain = ?", (subdomain,)
    ).fetchone()

    if existing:
        fields = {k: v for k, v in kwargs.items() if v is not None}
        fields["last_seen"] = now
        set_clause = ", ".join(f"{k} = ?" for k in fields)
        conn.execute(
            f"UPDATE assets SET {set_clause} WHERE subdomain = ?",
            list(fields.values()) + [subdomain]
        )
        conn.commit()
        return existing["id"]
    else:
        cols = ["domain", "subdomain", "first_seen", "last_seen"] + list(kwargs.keys())
        vals = [domain, subdomain, now, now] + list(kwargs.values())
        placeholders = ", ".join("?" * len(cols))
        cur = conn.execute(
            f"INSERT INTO assets ({', '.join(cols)}) VALUES ({placeholders})", vals
        )
        conn.commit()
        return cur.lastrowid


def get_new_assets(conn, domain: str, known_subdomains: set) -> list:
    """Return assets for a domain that are not in the known set."""
    rows = conn.execute(
        "SELECT subdomain FROM assets WHERE domain = ?", (domain,)
    ).fetchall()
    db_subdomains = {r["subdomain"] for r in rows}
    return list(known_subdomains - db_subdomains)


def save_finding(conn, **kwargs) -> int:
    """Save a finding to the database, return its ID."""
    now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    kwargs.setdefault("first_seen", now)
    kwargs.setdefault("last_seen", now)
    cols = list(kwargs.keys())
    vals = list(kwargs.values())
    placeholders = ", ".join("?" * len(cols))
    cur = conn.execute(
        f"INSERT INTO findings ({', '.join(cols)}) VALUES ({placeholders})", vals
    )
    conn.commit()
    return cur.lastrowid


def get_findings_for_dashboard(conn, limit: int = 100) -> list:
    """Get latest findings for the Streamlit dashboard."""
    return conn.execute("""
        SELECT f.*, a.subdomain
        FROM findings f
        LEFT JOIN assets a ON f.asset_id = a.id
        WHERE f.is_duplicate = 0
        ORDER BY f.ai_score DESC, f.first_seen DESC
        LIMIT ?
    """, (limit,)).fetchall()


def save_scan_run(conn, **kwargs) -> int:
    """Log a scan run."""
    now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    kwargs.setdefault("started_at", now)
    cols = list(kwargs.keys())
    vals = list(kwargs.values())
    placeholders = ", ".join("?" * len(cols))
    cur = conn.execute(
        f"INSERT INTO scan_runs ({', '.join(cols)}) VALUES ({placeholders})", vals
    )
    conn.commit()
    return cur.lastrowid


def complete_scan_run(conn, run_id: int, **kwargs):
    """Mark a scan run as completed."""
    kwargs["completed_at"] = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    kwargs["status"] = kwargs.get("status", "completed")
    set_clause = ", ".join(f"{k} = ?" for k in kwargs)
    conn.execute(
        f"UPDATE scan_runs SET {set_clause} WHERE id = ?",
        list(kwargs.values()) + [run_id]
    )
    conn.commit()
