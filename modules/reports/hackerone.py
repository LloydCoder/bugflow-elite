"""
BugFlow Elite v6 — HackerOne Report Intent Module
Creates DRAFT reports only via official H1 API. Never auto-submits.
Every draft requires manual human review before submission.
Tinlance Limited | LloydCoder
"""

import json
import logging
import aiohttp
from typing import Optional
from db.models import get_conn

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "info":     "none",
}

WEAKNESS_MAP = {
    "xss":                  89,    # Cross-site Scripting (XSS)
    "sqli":                 89,    # SQL Injection
    "sql_injection":        89,
    "ssrf":                 918,   # SSRF
    "open_redirect":        601,
    "idor":                 639,   # Authorization Bypass
    "takeover":             1007,  # Subdomain Takeover-like
    "cloud_misconfiguration": 200, # Information Exposure
    "secret":               200,   # Information Exposure
    "rce":                  78,    # OS Command Injection
    "path_traversal":       22,
    "xxe":                  611,
    "ssti":                 94,
    "csrf":                 352,
    "cors":                 346,
    "default":              200,   # Generic information exposure
}


class HackerOneClient:
    """
    HackerOne API client for creating Report Intents (drafts).
    CRITICAL SAFETY RULE: auto_submit is hardcoded to False.
    All reports require human review before they are ever submitted.
    """

    BASE_URL = "https://api.hackerone.com/v1"

    def __init__(self, config: dict):
        self.config = config
        self.h1_cfg = config.get("hackerone", {})
        self.db_path = config.get("general", {}).get("db_path", "./db/bugflow.db")

        self.api_token = self.h1_cfg.get("api_token", "")
        self.username = self.h1_cfg.get("username", "")
        self.enabled = bool(self.api_token and self.username)

        # Safety: auto_submit is ALWAYS False regardless of config
        # This line is intentional and must never be changed.
        self.auto_submit = False

        self.min_score = config.get("ai", {}).get("scoring", {}).get(
            "min_score_for_draft", 7.0
        )
        self.min_severity = self.h1_cfg.get("min_severity_for_draft", "medium")

    async def create_draft(self, finding: dict, program_handle: str) -> Optional[dict]:
        """
        Create a HackerOne Report Intent (draft) from a finding.
        Returns the draft report data including URL for manual review.
        """
        if not self.enabled:
            logger.warning("[H1] API credentials not configured — skipping draft")
            return None

        if not self._should_draft(finding):
            logger.info(
                f"[H1] Skipping draft (score {finding.get('ai_score', 0):.1f} "
                f"or severity too low): {finding.get('title', '')}"
            )
            return None

        # Build the report payload
        payload = self._build_payload(finding, program_handle)
        if not payload:
            return None

        try:
            async with aiohttp.ClientSession(
                auth=aiohttp.BasicAuth(self.username, self.api_token)
            ) as session:
                async with session.post(
                    f"{self.BASE_URL}/reports",
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    if resp.status in (200, 201):
                        data = await resp.json()
                        report_id = data.get("data", {}).get("id", "")
                        report_url = (
                            f"https://hackerone.com/reports/{report_id}"
                            if report_id else ""
                        )
                        logger.info(
                            f"[H1] Draft created: {report_url} — "
                            f"AWAITING MANUAL REVIEW"
                        )
                        # Update DB with draft info
                        await self._update_finding_draft(
                            finding.get("id"), report_id, report_url
                        )
                        return {
                            "report_id": report_id,
                            "report_url": report_url,
                            "status": "draft",
                            "requires_manual_review": True,
                        }
                    else:
                        body = await resp.text()
                        logger.error(f"[H1] Draft creation failed ({resp.status}): {body[:300]}")
                        return None

        except aiohttp.ClientError as e:
            logger.error(f"[H1] API connection error: {e}")
            return None

    def _should_draft(self, finding: dict) -> bool:
        """Check if a finding meets the threshold for draft creation."""
        score = float(finding.get("ai_score", 0))
        severity = finding.get("severity", "info")

        # Block duplicates
        if finding.get("is_duplicate"):
            return False

        # Score threshold
        if score < self.min_score:
            return False

        # Severity threshold
        severity_order = ["info", "low", "medium", "high", "critical"]
        min_idx = severity_order.index(self.min_severity) if self.min_severity in severity_order else 2
        sev_idx = severity_order.index(severity) if severity in severity_order else 0
        if sev_idx < min_idx:
            return False

        return True

    def _build_payload(self, finding: dict, program_handle: str) -> Optional[dict]:
        """Build the HackerOne API payload from a finding."""
        try:
            ai_data = json.loads(finding.get("ai_analysis", "{}")) or {}
        except (json.JSONDecodeError, TypeError):
            ai_data = {}

        title = finding.get("title") or ai_data.get("title", "Security Finding")
        severity = finding.get("severity", "medium")
        vuln_type = finding.get("vuln_type", "default").lower()
        weakness_id = WEAKNESS_MAP.get(vuln_type, WEAKNESS_MAP["default"])

        # Build rich report body
        report_body = self._build_report_body(finding, ai_data)

        payload = {
            "data": {
                "type": "report",
                "attributes": {
                    "team_handle": program_handle,
                    "title": title,
                    "vulnerability_information": report_body,
                    "severity_rating": SEVERITY_MAP.get(severity, "medium"),
                    "impact": ai_data.get("impact", "See vulnerability details above."),
                    "weakness_id": weakness_id,
                }
            }
        }
        return payload

    async def _attach_screenshots(
        self, report_id: str, screenshot_paths: str, token: str, username: str
    ):
        """Attach screenshot files to H1 report as evidence."""
        import os, json
        try:
            paths = json.loads(screenshot_paths) if screenshot_paths.startswith("[") else [screenshot_paths]
        except Exception:
            paths = [screenshot_paths] if screenshot_paths else []

        for path in paths[:3]:  # Max 3 screenshots
            if not path or not os.path.exists(path):
                continue
            try:
                import aiofiles
                async with aiofiles.open(path, "rb") as f:
                    file_data = await f.read()
                filename = os.path.basename(path)
                form = aiohttp.FormData()
                form.add_field("report_id", report_id)
                form.add_field(
                    "file", file_data,
                    filename=filename,
                    content_type="image/png"
                )
                async with aiohttp.ClientSession(
                    auth=aiohttp.BasicAuth(username, token)
                ) as session:
                    await session.post(
                        "https://api.hackerone.com/v1/reports/"
                        f"{report_id}/attachments",
                        data=form,
                        timeout=aiohttp.ClientTimeout(total=30)
                    )
                logger.info(f"[H1] Attached screenshot: {filename}")
            except Exception as e:
                logger.debug(f"[H1] Screenshot attach error: {e}")

    def _build_report_body(self, finding: dict, ai_data: dict) -> str:
        """Build a professional, structured report body."""
        lines = []

        lines.append("## Summary")
        summary = ai_data.get("report_summary") or finding.get("description", "")
        lines.append(summary)
        lines.append("")

        lines.append("## Vulnerability Details")
        lines.append(f"**Type:** {finding.get('vuln_type', 'Unknown').replace('_', ' ').title()}")
        lines.append(f"**Target:** {finding.get('target', 'See steps below')}")
        lines.append(f"**Severity:** {finding.get('severity', 'medium').upper()}")
        if finding.get("cvss_score"):
            lines.append(f"**CVSS Score:** {finding['cvss_score']}")
        lines.append("")

        steps = ai_data.get("reproduction_steps") or finding.get("reproduction_steps", "")
        if steps:
            lines.append("## Steps to Reproduce")
            lines.append(steps)
            lines.append("")

        impact = ai_data.get("attack_scenario") or ai_data.get("impact", "")
        if impact:
            lines.append("## Impact")
            lines.append(impact)
            lines.append("")

        poc = finding.get("proof_of_concept", "")
        if poc:
            lines.append("## Proof of Concept")
            lines.append("```")
            lines.append(poc[:2000])
            lines.append("```")
            lines.append("")

        ttps = finding.get("mitre_ttps", "")
        if ttps:
            if isinstance(ttps, str):
                try:
                    ttps = json.loads(ttps)
                except Exception:
                    ttps = [ttps]
            if ttps:
                lines.append(f"**MITRE ATT&CK TTPs:** {', '.join(ttps)}")
                lines.append("")

        lines.append("---")
        lines.append("*Report generated by BugFlow Elite v6 | Tinlance Limited*")
        lines.append("*⚠️ DRAFT — REQUIRES MANUAL REVIEW BEFORE SUBMISSION*")

        return "\n".join(lines)

    async def _update_finding_draft(
        self, finding_id: Optional[int], report_id: str, report_url: str
    ):
        """Update the finding in DB with H1 draft info."""
        if not finding_id:
            return
        conn = get_conn(self.db_path)
        try:
            conn.execute("""
                UPDATE findings
                SET h1_report_id = ?, h1_draft_url = ?, h1_status = 'drafted'
                WHERE id = ?
            """, (report_id, report_url, finding_id))
            conn.commit()
        finally:
            conn.close()

    async def get_program_handle(self, domain: str) -> Optional[str]:
        """
        Try to find the HackerOne program handle for a domain.
        Uses the bounty-targets-data scope cache.
        """
        conn = get_conn(self.db_path)
        try:
            row = conn.execute("""
                SELECT scope_data FROM scope_cache
                WHERE platform = 'all'
                ORDER BY fetched_at DESC LIMIT 1
            """).fetchone()
            if row:
                scope_data = json.loads(row["scope_data"])
                h1_programs = scope_data.get("hackerone", [])
                for prog in h1_programs:
                    targets = prog.get("targets", {}).get("in_scope", [])
                    for target in targets:
                        identifier = target.get("asset_identifier", "")
                        if domain in identifier or identifier in domain:
                            return prog.get("handle", "")
        except Exception as e:
            logger.error(f"[H1] Handle lookup error: {e}")
        finally:
            conn.close()
        return None
