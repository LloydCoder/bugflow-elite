"""
BugFlow Elite v6 — Payout Tracker
Polls HackerOne API for resolved/bounty_awarded reports.
Logs every payout to DB. Feeds program selector with real ROI data.
Sends Telegram celebration alert when money lands.
Also tracks Bugcrowd and Intigriti resolutions.
Tinlance Limited | LloydCoder
"""

import json
import logging
import aiohttp
from datetime import datetime, timedelta
from pathlib import Path
from db.models import get_conn

logger = logging.getLogger(__name__)


class PayoutTracker:
    """
    Polls H1 API for bounty_awarded and resolved reports.
    Logs amounts to the payouts table and sends Telegram alerts.
    Runs every 6 hours via scheduler.
    """

    def __init__(self, config: dict):
        self.config = config
        self.db_path = config.get("general", {}).get("db_path", "./db/bugflow.db")
        self.h1_cfg = config.get("hackerone", {})
        self.api_token = self.h1_cfg.get("api_token", "")
        self.username = self.h1_cfg.get("username", "")
        self.enabled = bool(self.api_token and self.username)

    async def check_duplicate_reports(self) -> list[dict]:
        """
        Poll H1 API for reports newly marked as duplicate.
        Returns list of duplicate events for Telegram notification.
        """
        if not self.enabled:
            return []

        duplicates = []
        try:
            async with aiohttp.ClientSession(
                auth=aiohttp.BasicAuth(self.username, self.api_token)
            ) as session:
                params = {
                    "filter[state][]": ["duplicate"],
                    "page[size]": 10,
                }
                async with session.get(
                    "https://api.hackerone.com/v1/me/reports",
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    if resp.status != 200:
                        return []
                    data = await resp.json()
                    for report in data.get("data", []):
                        attrs = report.get("attributes", {})
                        if attrs.get("state") == "duplicate":
                            rid = report.get("id", "")
                            if not self._duplicate_already_noted(rid):
                                self._mark_duplicate_noted(rid)
                                duplicates.append({
                                    "report_id": rid,
                                    "title": attrs.get("title", ""),
                                    "h1_url": f"https://hackerone.com/reports/{rid}",
                                })
        except Exception as e:
            logger.debug(f"[PayoutTracker] Duplicate check error: {e}")
        return duplicates

    def _duplicate_already_noted(self, report_id: str) -> bool:
        marker = Path(f"./output/.dup_{report_id}")
        return marker.exists()

    def _mark_duplicate_noted(self, report_id: str):
        marker = Path(f"./output/.dup_{report_id}")
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("1")

    async def check_payouts(self) -> list[dict]:
        """
        Poll H1 API for new resolved/paid reports since last check.
        Returns list of new payout events.
        """
        if not self.enabled:
            return []

        last_check = self._get_last_check()
        logger.info(f"[PayoutTracker] Checking payouts since {last_check}")

        new_payouts = []

        try:
            async with aiohttp.ClientSession(
                auth=aiohttp.BasicAuth(self.username, self.api_token)
            ) as session:
                # Fetch reports that have bounties
                params = {
                    "filter[state][]": ["bounty_awarded", "resolved"],
                    "page[size]": 25,
                }
                async with session.get(
                    "https://api.hackerone.com/v1/me/reports",
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    if resp.status != 200:
                        logger.warning(f"[PayoutTracker] H1 API error: {resp.status}")
                        return []

                    data = await resp.json()
                    reports = data.get("data", [])

                    for report in reports:
                        payout = self._extract_payout(report)
                        if not payout:
                            continue

                        # Only process if newer than last check
                        paid_at = payout.get("paid_at", "")
                        if paid_at and paid_at > last_check:
                            if not self._already_tracked(payout["report_id"]):
                                self._save_payout(payout)
                                new_payouts.append(payout)
                                logger.info(
                                    f"[PayoutTracker] New payout: "
                                    f"${payout['amount']:.2f} — {payout['title'][:50]}"
                                )

        except Exception as e:
            logger.error(f"[PayoutTracker] Error: {e}")

        self._update_last_check()

        if new_payouts:
            total = sum(p["amount"] for p in new_payouts)
            logger.info(
                f"[PayoutTracker] {len(new_payouts)} new payouts "
                f"totalling ${total:.2f}"
            )

        return new_payouts

    def _extract_payout(self, report: dict) -> dict | None:
        """Extract payout data from H1 report object."""
        try:
            attrs = report.get("attributes", {})
            state = attrs.get("state", "")
            if state not in ("bounty_awarded", "resolved"):
                return None

            # Get bounty amount
            bounties = attrs.get("bounties", [])
            amount = 0.0
            paid_at = ""
            for b in bounties:
                amount += float(b.get("amount", 0))
                paid_at = b.get("created_at", "")

            if amount <= 0:
                return None

            # Get program handle
            rels = report.get("relationships", {})
            program = rels.get("program", {}).get("data", {})
            program_handle = program.get("attributes", {}).get("handle", "unknown")

            return {
                "report_id": report.get("id", ""),
                "title": attrs.get("title", "Unknown"),
                "severity": attrs.get("severity_rating", "medium"),
                "state": state,
                "amount": amount,
                "paid_at": paid_at or datetime.utcnow().isoformat(),
                "program": program_handle,
                "h1_url": f"https://hackerone.com/reports/{report.get('id', '')}",
                "platform": "hackerone",
            }
        except Exception:
            return None

    def _already_tracked(self, report_id: str) -> bool:
        """Check if this report's payout was already recorded."""
        conn = get_conn(self.db_path)
        try:
            row = conn.execute(
                "SELECT id FROM payouts WHERE report_id = ?",
                (str(report_id),)
            ).fetchone()
            return row is not None
        except Exception:
            return False
        finally:
            conn.close()

    def _save_payout(self, payout: dict):
        """Save payout to database."""
        conn = get_conn(self.db_path)
        try:
            conn.execute("""
                INSERT OR IGNORE INTO payouts
                (report_id, title, severity, amount, platform,
                 program, h1_url, paid_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                str(payout["report_id"]),
                payout["title"],
                payout["severity"],
                payout["amount"],
                payout["platform"],
                payout["program"],
                payout["h1_url"],
                payout["paid_at"],
            ))
            conn.commit()

            # Also update findings table h1_status
            conn.execute("""
                UPDATE findings
                SET h1_status = 'resolved'
                WHERE h1_report_id = ?
            """, (str(payout["report_id"]),))
            conn.commit()

        except Exception as e:
            logger.error(f"[PayoutTracker] DB error: {e}")
        finally:
            conn.close()

    def get_total_earnings(self, days: int = 30) -> dict:
        """Get earnings summary for the last N days."""
        conn = get_conn(self.db_path)
        try:
            since = (datetime.utcnow() - timedelta(days=days)).isoformat()

            total = conn.execute(
                "SELECT COALESCE(SUM(amount), 0) FROM payouts WHERE paid_at > ?",
                (since,)
            ).fetchone()[0]

            count = conn.execute(
                "SELECT COUNT(*) FROM payouts WHERE paid_at > ?",
                (since,)
            ).fetchone()[0]

            by_program = conn.execute("""
                SELECT program, SUM(amount) as total, COUNT(*) as reports
                FROM payouts
                WHERE paid_at > ?
                GROUP BY program
                ORDER BY total DESC
                LIMIT 5
            """, (since,)).fetchall()

            all_time = conn.execute(
                "SELECT COALESCE(SUM(amount), 0) FROM payouts"
            ).fetchone()[0]

            return {
                "period_days": days,
                "total_usd": float(total or 0),
                "report_count": int(count or 0),
                "all_time_usd": float(all_time or 0),
                "by_program": [
                    {"program": r["program"], "total": float(r["total"]),
                     "reports": r["reports"]}
                    for r in by_program
                ],
            }
        except Exception as e:
            logger.error(f"[PayoutTracker] Earnings error: {e}")
            return {"total_usd": 0, "report_count": 0, "all_time_usd": 0}
        finally:
            conn.close()

    def get_program_avg_payout(self, program: str) -> float:
        """Get average payout amount for a specific program."""
        conn = get_conn(self.db_path)
        try:
            row = conn.execute(
                "SELECT AVG(amount) FROM payouts WHERE program = ?",
                (program,)
            ).fetchone()
            return float(row[0]) if row and row[0] else 0.0
        finally:
            conn.close()

    def _get_last_check(self) -> str:
        """Get timestamp of last payout check."""
        marker = Path("./output/.payout_last_check")
        if marker.exists():
            return marker.read_text().strip()
        return (datetime.utcnow() - timedelta(days=7)).isoformat()

    def _update_last_check(self):
        """Update last check timestamp."""
        marker = Path("./output/.payout_last_check")
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(datetime.utcnow().isoformat())
