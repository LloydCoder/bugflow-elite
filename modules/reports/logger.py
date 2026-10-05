"""
BugFlow Elite v6 — Finding Logger
Structured logging for all pipeline events, findings, and scan runs.
Feeds the dashboard, generates weekly summaries, and provides
audit trail for every H1 report submitted.
Tinlance Limited | LloydCoder
"""

import json
import logging
import csv
from datetime import datetime
from pathlib import Path
from db.models import get_conn

logger = logging.getLogger(__name__)


class FindingLogger:
    """
    Structured logger that writes findings to:
    - SQLite DB (primary)
    - JSON log file (human-readable audit trail)
    - CSV export (for spreadsheet analysis)
    - Dashboard-ready summary
    """

    def __init__(self, config: dict):
        self.config = config
        self.db_path = config.get("general", {}).get("db_path", "./db/bugflow.db")
        self.log_dir = Path("./output/logs")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.json_log = self.log_dir / "findings.jsonl"
        self.csv_log = self.log_dir / "findings.csv"
        self._ensure_csv_header()

    def log_finding(self, finding: dict, scan_run_id: int = 0):
        """Log a finding to all output formats."""
        enriched = {
            **finding,
            "logged_at": datetime.utcnow().isoformat(),
            "scan_run_id": scan_run_id,
        }
        # JSON lines log
        try:
            with open(self.json_log, "a") as f:
                f.write(json.dumps(enriched) + "\n")
        except Exception as e:
            logger.debug(f"[Logger] JSON log error: {e}")

        # CSV log
        try:
            self._write_csv_row(enriched)
        except Exception as e:
            logger.debug(f"[Logger] CSV log error: {e}")

    def log_scan_start(self, domain: str, scan_type: str, run_id: int):
        """Log scan start event."""
        event = {
            "event": "scan_start",
            "domain": domain,
            "scan_type": scan_type,
            "run_id": run_id,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self._write_event_log(event)

    def log_scan_complete(self, run_id: int, stats: dict):
        """Log scan completion with statistics."""
        event = {
            "event": "scan_complete",
            "run_id": run_id,
            "timestamp": datetime.utcnow().isoformat(),
            **stats,
        }
        self._write_event_log(event)

    def get_weekly_summary(self) -> dict:
        """Generate a weekly summary from the DB."""
        conn = get_conn(self.db_path)
        try:
            from_date = (datetime.utcnow().replace(
                hour=0, minute=0, second=0
            ) - __import__("datetime").timedelta(days=7)).isoformat()

            total = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE first_seen > ? AND is_duplicate=0",
                (from_date,)
            ).fetchone()[0]

            by_severity = {}
            for row in conn.execute("""
                SELECT severity, COUNT(*) as cnt
                FROM findings
                WHERE first_seen > ? AND is_duplicate = 0
                GROUP BY severity
            """, (from_date,)).fetchall():
                by_severity[row["severity"]] = row["cnt"]

            drafts = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE h1_status='drafted' AND first_seen > ?",
                (from_date,)
            ).fetchone()[0]

            new_assets = conn.execute(
                "SELECT COUNT(*) FROM assets WHERE first_seen > ?",
                (from_date,)
            ).fetchone()[0]

            top_programs = conn.execute("""
                SELECT program, COUNT(*) as cnt
                FROM findings
                WHERE first_seen > ? AND is_duplicate = 0
                GROUP BY program
                ORDER BY cnt DESC
                LIMIT 5
            """, (from_date,)).fetchall()

            return {
                "period": "last_7_days",
                "total_findings": total,
                "by_severity": by_severity,
                "h1_drafts_created": drafts,
                "new_assets_discovered": new_assets,
                "top_programs": [
                    {"program": r["program"], "findings": r["cnt"]}
                    for r in top_programs
                ],
            }
        finally:
            conn.close()

    def export_csv(self, output_path: str = None) -> str:
        """Export all findings to CSV for spreadsheet analysis."""
        path = Path(output_path) if output_path else self.csv_log
        conn = get_conn(self.db_path)
        try:
            rows = conn.execute("""
                SELECT f.*, a.subdomain as target_host
                FROM findings f
                LEFT JOIN assets a ON f.asset_id = a.id
                WHERE f.is_duplicate = 0
                ORDER BY f.ai_score DESC, f.first_seen DESC
            """).fetchall()

            with open(path, "w", newline="") as f:
                if rows:
                    writer = csv.DictWriter(
                        f, fieldnames=dict(rows[0]).keys()
                    )
                    writer.writeheader()
                    for row in rows:
                        writer.writerow(dict(row))

            logger.info(f"[Logger] Exported {len(rows)} findings to {path}")
            return str(path)
        finally:
            conn.close()

    def _ensure_csv_header(self):
        """Create CSV file with header if it doesn't exist."""
        if not self.csv_log.exists():
            with open(self.csv_log, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "logged_at", "title", "severity", "vuln_type",
                    "target", "ai_score", "program", "h1_status",
                    "is_duplicate", "threatfade_c2", "tool"
                ])

    def _write_csv_row(self, finding: dict):
        """Append a finding to the CSV log."""
        with open(self.csv_log, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                finding.get("logged_at", ""),
                finding.get("title", ""),
                finding.get("severity", ""),
                finding.get("vuln_type", ""),
                finding.get("target", ""),
                finding.get("ai_score", 0),
                finding.get("program", ""),
                finding.get("h1_status", "pending"),
                finding.get("is_duplicate", False),
                finding.get("threatfade_c2", False),
                finding.get("tool", ""),
            ])

    def _write_event_log(self, event: dict):
        """Write a pipeline event to the event log."""
        event_log = self.log_dir / "events.jsonl"
        try:
            with open(event_log, "a") as f:
                f.write(json.dumps(event) + "\n")
        except Exception:
            pass
