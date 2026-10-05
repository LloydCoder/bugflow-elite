"""
BugFlow Elite v6 — SQLmap Runner
Confirms SQL injection findings discovered by Nuclei.
Converts unconfirmed SQLi into verified critical findings with DB evidence.
DETECTION ONLY — extracts DB name/version only, never dumps tables.
Tinlance Limited | LloydCoder
"""

import json
import logging
import asyncio
import subprocess
import tempfile
import os
from pathlib import Path
from typing import Optional
from modules.scope.scope_enforcer import ScopeEnforcer
from db.models import get_conn, save_finding

logger = logging.getLogger(__name__)


class SQLmapRunner:
    """
    Runs sqlmap against suspected SQLi endpoints.
    Level 2 / Risk 1 only — safe for bug bounty use.
    Extracts: DB name, DB version, current user — no table dumps.
    """

    def __init__(self, config: dict, scope: ScopeEnforcer):
        self.config = config
        self.scope = scope
        self.db_path = config.get("general", {}).get("db_path", "./db/bugflow.db")
        self.output_dir = Path("./output/sqlmap")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.stealth = config.get("stealth", {})

    async def verify_sqli(
        self, url: str, param: str = "", program: str = ""
    ) -> Optional[dict]:
        """
        Run sqlmap to confirm SQLi on a specific URL/param.
        Returns structured result if confirmed, None if not injectable.
        """
        self.scope.assert_in_scope(url)

        if not self._sqlmap_installed():
            logger.warning("[SQLmap] Not installed — skip. Install: pip install sqlmap")
            return None

        logger.info(f"[SQLmap] Testing: {url}" + (f" param={param}" if param else ""))

        output_dir = self.output_dir / url.replace("://", "_").replace("/", "_")[:80]
        output_dir.mkdir(parents=True, exist_ok=True)

        cmd = self._build_command(url, param, str(output_dir))

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=300
            )
            output = stdout.decode(errors="ignore")

            result = self._parse_output(output, url, param)
            if result:
                if program:
                    result["program"] = program
                await self._save_finding(result, program)
                logger.info(
                    f"[SQLmap] ✅ CONFIRMED SQLi: {url} "
                    f"({result.get('db_type', 'unknown')})"
                )
            else:
                logger.info(f"[SQLmap] Not injectable: {url}")

            return result

        except asyncio.TimeoutError:
            logger.warning(f"[SQLmap] Timeout on {url}")
            return None
        except Exception as e:
            logger.error(f"[SQLmap] Error: {e}")
            return None

    async def batch_verify(
        self, sqli_findings: list[dict], program: str = ""
    ) -> list[dict]:
        """Verify multiple SQLi findings concurrently (max 3 at once)."""
        semaphore = asyncio.Semaphore(3)
        confirmed = []

        async def verify_one(finding: dict):
            async with semaphore:
                url = finding.get("target", "")
                if not url:
                    return
                result = await self.verify_sqli(url, program=program)
                if result:
                    confirmed.append(result)
                await asyncio.sleep(2)  # Rate limiting

        await asyncio.gather(*[verify_one(f) for f in sqli_findings])
        logger.info(
            f"[SQLmap] Confirmed {len(confirmed)}/{len(sqli_findings)} SQLi findings"
        )
        return confirmed

    def _build_command(self, url: str, param: str, output_dir: str) -> list[str]:
        """Build safe sqlmap command for bug bounty use."""
        cmd = [
            "sqlmap",
            "-u", url,
            "--batch",                    # Non-interactive
            "--level=2",                  # Safe level
            "--risk=1",                   # Safe risk
            "--technique=BEUSTQ",         # All techniques
            "--dbms=all",                 # Try all DBMS
            "--output-dir", output_dir,
            "--json-session",
            "--no-escape",
            "--fresh-queries",
        ]

        # Add specific param if known
        if param:
            cmd += ["-p", param]

        # Stealth settings
        delay = self.stealth.get("min_delay_seconds", 1.5)
        cmd += [f"--delay={int(delay)}"]

        rate = self.stealth.get("rate_limit_per_minute", 20)
        cmd += [f"--safe-freq={max(1, rate // 10)}"]

        # Get DB info only — no table dumps
        cmd += ["--dbs", "--current-user", "--current-db", "--banner"]

        return cmd

    def _parse_output(self, output: str, url: str, param: str) -> Optional[dict]:
        """Parse sqlmap output for confirmed injection."""
        if "sqlmap identified the following injection point" not in output.lower():
            return None

        # Extract details
        db_type = "unknown"
        db_name = ""
        db_version = ""
        db_user = ""
        technique = ""
        payloads = []

        for line in output.split("\n"):
            line = line.strip()
            if "back-end DBMS:" in line:
                db_type = line.split("back-end DBMS:")[-1].strip()
            elif "current database:" in line.lower():
                db_name = line.split(":")[-1].strip().strip("'")
            elif "current user:" in line.lower():
                db_user = line.split(":")[-1].strip().strip("'")
            elif "web server operating system:" in line.lower():
                pass
            elif "payload:" in line.lower():
                payloads.append(line.split("payload:")[-1].strip())
            elif "type:" in line.lower() and "sql" in output.lower():
                technique = line.split("type:")[-1].strip()

        poc = f"URL: {url}\n"
        if param:
            poc += f"Parameter: {param}\n"
        poc += f"DB Type: {db_type}\n"
        poc += f"DB Name: {db_name}\n"
        poc += f"DB User: {db_user}\n"
        if payloads:
            poc += f"Sample Payload: {payloads[0][:200]}\n"

        return {
            "title": f"SQL Injection Confirmed: {url[:80]}",
            "severity": "critical",
            "vuln_type": "sqli",
            "target": url,
            "db_type": db_type,
            "db_name": db_name,
            "db_user": db_user,
            "db_version": db_version,
            "technique": technique,
            "payloads": payloads[:3],
            "description": (
                f"SQL injection confirmed by sqlmap on {url}.\n"
                f"Database: {db_type} — {db_name}\n"
                f"Current user: {db_user}\n"
                f"Injection technique: {technique}"
            ),
            "reproduction_steps": (
                f"1. Navigate to: {url}\n"
                f"2. Inject into parameter: {param or 'auto-detected'}\n"
                f"3. Use payload: {payloads[0] if payloads else 'see sqlmap output'}\n"
                f"4. Confirm DB extraction: {db_name}"
            ),
            "proof_of_concept": poc,
            "ai_score": 9.5,
            "tool": "sqlmap",
        }

    async def _save_finding(self, result: dict, program: str):
        """Save confirmed SQLi to database."""
        conn = get_conn(self.db_path)
        try:
            save_finding(
                conn,
                title=result["title"],
                severity="critical",
                vuln_type="sqli",
                description=result["description"],
                reproduction_steps=result["reproduction_steps"],
                proof_of_concept=result["proof_of_concept"],
                ai_score=9.5,
                program=program,
            )
            conn.commit()
        finally:
            conn.close()

    def _sqlmap_installed(self) -> bool:
        try:
            subprocess.run(
                ["sqlmap", "--version"],
                capture_output=True, check=True
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
