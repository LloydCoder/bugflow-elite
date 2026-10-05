"""
BugFlow Elite v6 — Multi-Platform Report Client
Supports ALL major bug bounty platforms:
  - HackerOne (H1) — full API draft creation
  - Bugcrowd — API draft creation
  - Intigriti — API draft creation
  - YesWeHack — API draft creation
  - Synack — manual export (no public API)
  - Private programs — markdown export
auto_submit is ALWAYS False on every platform. Manual review required.
Tinlance Limited | LloydCoder
"""

import json
import logging
import aiohttp
from datetime import datetime
from pathlib import Path
from typing import Optional
from db.models import get_conn

logger = logging.getLogger(__name__)

# Severity mapping per platform
SEVERITY_MAP = {
    "hackerone":  {"critical": "critical", "high": "high", "medium": "medium", "low": "low"},
    "bugcrowd":   {"critical": "p1", "high": "p2", "medium": "p3", "low": "p4"},
    "intigriti":  {"critical": "critical", "high": "high", "medium": "medium", "low": "low"},
    "yeswehack":  {"critical": "critical", "high": "high", "medium": "medium", "low": "low"},
    "synack":     {"critical": "critical", "high": "high", "medium": "medium", "low": "low"},
}


class PlatformClient:
    """
    Universal bug bounty platform client.
    Routes finding reports to the correct platform API.
    Always creates drafts only — never auto-submits.
    """

    # Safety constant — never changes
    AUTO_SUBMIT = False

    def __init__(self, config: dict):
        self.config = config
        self.db_path = config.get("general", {}).get("db_path", "./db/bugflow.db")
        self.output_dir = Path("./output/reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Load platform configs
        self.h1_cfg = config.get("hackerone", {})
        self.bc_cfg = config.get("bugcrowd", {})
        self.int_cfg = config.get("intigriti", {})
        self.ywh_cfg = config.get("yeswehack", {})

    async def create_draft(
        self, finding: dict, program: str, platform: str
    ) -> Optional[dict]:
        """
        Route finding to the correct platform for draft creation.
        Returns draft result with URL for manual review.
        """
        platform = platform.lower()
        logger.info(
            f"[Platform] Creating draft on {platform}: "
            f"{finding.get('title', '')[:50]}"
        )

        if platform == "hackerone":
            return await self._h1_create_draft(finding, program)
        elif platform == "bugcrowd":
            return await self._bugcrowd_create_draft(finding, program)
        elif platform == "intigriti":
            return await self._intigriti_create_draft(finding, program)
        elif platform == "yeswehack":
            return await self._ywh_create_draft(finding, program)
        elif platform in ("synack", "private"):
            return await self._export_markdown(finding, program, platform)
        else:
            logger.warning(f"[Platform] Unknown platform: {platform}")
            return await self._export_markdown(finding, program, "private")

    # ── HackerOne ──────────────────────────────────────────────────────────

    async def _h1_create_draft(
        self, finding: dict, program_handle: str
    ) -> Optional[dict]:
        """Create H1 Report Intent (draft)."""
        token = self.h1_cfg.get("api_token", "")
        username = self.h1_cfg.get("username", "")
        if not token or not username:
            logger.warning("[H1] API credentials not configured")
            return None

        payload = {
            "data": {
                "type": "report",
                "attributes": {
                    "team_handle": program_handle,
                    "title": finding.get("title", "Security Finding"),
                    "vulnerability_information": self._build_report_body(finding),
                    "severity_rating": SEVERITY_MAP["hackerone"].get(
                        finding.get("severity", "medium"), "medium"
                    ),
                    "impact": finding.get("impact", "See report details"),
                }
            }
        }

        try:
            async with aiohttp.ClientSession(
                auth=aiohttp.BasicAuth(username, token)
            ) as session:
                async with session.post(
                    "https://api.hackerone.com/v1/reports",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    if resp.status in (200, 201):
                        data = await resp.json()
                        report_id = data.get("data", {}).get("id", "")
                        url = f"https://hackerone.com/reports/{report_id}"
                        await self._update_finding_status(
                            finding.get("id"), report_id, url, "hackerone"
                        )
                        return {
                            "platform": "hackerone",
                            "report_id": report_id,
                            "draft_url": url,
                            "status": "draft",
                            "auto_submitted": False,
                        }
                    else:
                        body = await resp.text()
                        logger.error(f"[H1] Draft failed ({resp.status}): {body[:200]}")
        except Exception as e:
            logger.error(f"[H1] Error: {e}")
        return None

    # ── Bugcrowd ───────────────────────────────────────────────────────────

    async def _bugcrowd_create_draft(
        self, finding: dict, program: str
    ) -> Optional[dict]:
        """Create Bugcrowd submission draft."""
        token = self.bc_cfg.get("api_token", "")
        if not token:
            return await self._export_markdown(finding, program, "bugcrowd")

        priority = SEVERITY_MAP["bugcrowd"].get(
            finding.get("severity", "medium"), "p3"
        )

        payload = {
            "submission": {
                "title": finding.get("title", ""),
                "description": self._build_report_body(finding),
                "severity": priority,
                "vrt_id": self._get_bugcrowd_vrt(
                    finding.get("vuln_type", "")
                ),
                "target": {"name": program},
            }
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://api.bugcrowd.com/submissions",
                    json=payload,
                    headers={
                        "Authorization": f"Token {token}",
                        "Accept": "application/vnd.bugcrowd+json; version=1",
                        "Content-Type": "application/json",
                    },
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    if resp.status in (200, 201, 202):
                        data = await resp.json()
                        ref = data.get("submission", {}).get("reference", "")
                        url = f"https://bugcrowd.com/submissions/{ref}"
                        return {
                            "platform": "bugcrowd",
                            "report_id": ref,
                            "draft_url": url,
                            "status": "draft",
                            "auto_submitted": False,
                        }
        except Exception as e:
            logger.debug(f"[Bugcrowd] API error: {e}")

        # Fallback to markdown export
        return await self._export_markdown(finding, program, "bugcrowd")

    # ── Intigriti ──────────────────────────────────────────────────────────

    async def _intigriti_create_draft(
        self, finding: dict, program: str
    ) -> Optional[dict]:
        """Create Intigriti submission draft."""
        token = self.int_cfg.get("api_token", "")
        if not token:
            return await self._export_markdown(finding, program, "intigriti")

        severity_map = {
            "critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1
        }

        payload = {
            "programId": program,
            "title": finding.get("title", ""),
            "description": self._build_report_body(finding),
            "severity": {
                "id": severity_map.get(finding.get("severity", "medium"), 3)
            },
            "type": {"id": self._get_intigriti_type(finding.get("vuln_type", ""))},
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://api.intigriti.com/external/researcher/v1/submission",
                    json=payload,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json",
                    },
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    if resp.status in (200, 201):
                        data = await resp.json()
                        sub_id = data.get("id", "")
                        url = f"https://app.intigriti.com/researcher/submissions/{sub_id}"
                        return {
                            "platform": "intigriti",
                            "report_id": sub_id,
                            "draft_url": url,
                            "status": "draft",
                            "auto_submitted": False,
                        }
        except Exception as e:
            logger.debug(f"[Intigriti] API error: {e}")

        return await self._export_markdown(finding, program, "intigriti")

    # ── YesWeHack ──────────────────────────────────────────────────────────

    async def _ywh_create_draft(
        self, finding: dict, program: str
    ) -> Optional[dict]:
        """Create YesWeHack report draft."""
        token = self.ywh_cfg.get("api_token", "")
        if not token:
            return await self._export_markdown(finding, program, "yeswehack")

        payload = {
            "title": finding.get("title", ""),
            "description": self._build_report_body(finding),
            "cvss": finding.get("cvss_score", 5.0),
            "bug_type": {"id": self._get_ywh_type(finding.get("vuln_type", ""))},
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"https://api.yeswehack.com/programs/{program}/reports",
                    json=payload,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json",
                    },
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    if resp.status in (200, 201):
                        data = await resp.json()
                        report_id = data.get("id", "")
                        url = f"https://yeswehack.com/reports/{report_id}"
                        return {
                            "platform": "yeswehack",
                            "report_id": str(report_id),
                            "draft_url": url,
                            "status": "draft",
                            "auto_submitted": False,
                        }
        except Exception as e:
            logger.debug(f"[YesWeHack] API error: {e}")

        return await self._export_markdown(finding, program, "yeswehack")

    # ── Markdown Export (Synack / Private) ─────────────────────────────────

    async def _export_markdown(
        self, finding: dict, program: str, platform: str
    ) -> dict:
        """
        Export finding as formatted Markdown report.
        Used for Synack and private programs.
        """
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        title_slug = finding.get("title", "finding")[:40].replace(" ", "_")
        filename = f"{platform}_{title_slug}_{timestamp}.md"
        path = self.output_dir / filename

        report = self._build_report_body(finding, markdown=True)
        path.write_text(report)

        return {
            "platform": platform,
            "report_id": timestamp,
            "draft_url": str(path),
            "status": "exported",
            "auto_submitted": False,
            "note": f"Saved to {path} — copy into {platform} manually",
        }

    # ── Helpers ────────────────────────────────────────────────────────────

    def _build_report_body(
        self, finding: dict, markdown: bool = False
    ) -> str:
        """Build professional report body."""
        title = finding.get("title", "Security Finding")
        severity = finding.get("severity", "medium").upper()
        target = finding.get("target", "")
        desc = finding.get("description", "")
        steps = finding.get("reproduction_steps", "")
        poc = finding.get("proof_of_concept", "")
        impact = finding.get("impact", "")

        sep = "---" if markdown else "---"
        lines = [
            f"# {title}" if markdown else f"## {title}",
            "",
            f"**Severity:** {severity}",
            f"**Target:** {target}",
            "",
            "## Summary",
            desc,
            "",
            "## Steps to Reproduce",
            steps,
            "",
        ]
        if poc:
            lines += ["## Proof of Concept", "```", poc[:1500], "```", ""]
        if impact:
            lines += ["## Impact", impact, ""]

        lines += [
            sep,
            "*Report generated by BugFlow Elite v6 | Tinlance Limited*",
            "*⚠️ DRAFT — Requires manual review before submission*",
        ]
        return "\n".join(lines)

    def _get_bugcrowd_vrt(self, vuln_type: str) -> str:
        """Map BugFlow vuln type to Bugcrowd VRT ID."""
        vrt_map = {
            "xss": "cross_site_scripting_xss-reflected",
            "sqli": "injection-sql_injection",
            "ssrf": "server_side_request_forgery_ssrf",
            "idor": "broken_access_control-idor",
            "takeover": "subdomain_takeover",
            "secret": "sensitive_data_exposure",
            "rce": "injection-remote_code_execution",
        }
        return vrt_map.get(vuln_type, "other")

    def _get_intigriti_type(self, vuln_type: str) -> int:
        """Map BugFlow vuln type to Intigriti type ID."""
        type_map = {
            "xss": 1, "sqli": 2, "ssrf": 3, "idor": 4,
            "takeover": 5, "rce": 6, "secret": 7,
        }
        return type_map.get(vuln_type, 99)

    def _get_ywh_type(self, vuln_type: str) -> str:
        """Map BugFlow vuln type to YesWeHack bug type."""
        ywh_map = {
            "xss": "xss", "sqli": "sqli", "ssrf": "ssrf",
            "idor": "bac", "takeover": "subdomain-takeover",
            "rce": "rce", "secret": "information-disclosure",
        }
        return ywh_map.get(vuln_type, "other")

    async def _update_finding_status(
        self,
        finding_id: Optional[int],
        report_id: str,
        url: str,
        platform: str,
    ):
        """Update finding with report draft info."""
        if not finding_id:
            return
        conn = get_conn(self.db_path)
        try:
            conn.execute("""
                UPDATE findings
                SET h1_report_id=?, h1_draft_url=?, h1_status='drafted'
                WHERE id=?
            """, (report_id, url, finding_id))
            conn.commit()
        finally:
            conn.close()
