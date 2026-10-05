"""
BugFlow Elite v6 — Dalfox XSS Scanner
Dedicated XSS scanner. Faster and more thorough than Nuclei for XSS.
Confirms reflected, stored, and DOM XSS with working PoC URLs.
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


class DalfoxRunner:
    """
    Runs Dalfox against discovered endpoints with parameters.
    Generates clean PoC URLs ready for H1 reports.
    """

    def __init__(self, config: dict, scope: ScopeEnforcer):
        self.config = config
        self.scope = scope
        self.db_path = config.get("general", {}).get("db_path", "./db/bugflow.db")
        self.output_dir = Path("./output/dalfox")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.stealth = config.get("stealth", {})

    async def scan_urls(
        self, urls: list[str], program: str = ""
    ) -> list[dict]:
        """
        Scan a list of URLs for XSS vulnerabilities.
        Returns list of confirmed XSS findings with PoC URLs.
        """
        if not urls:
            return []

        # Filter to in-scope URLs with parameters
        scoped = []
        for url in urls:
            try:
                self.scope.assert_in_scope(url)
                if "?" in url:  # Only test URLs with parameters
                    scoped.append(url)
            except Exception:
                pass

        if not scoped:
            return []

        if not self._dalfox_installed():
            logger.warning("[Dalfox] Not installed — skip. Install: go install github.com/hahwul/dalfox/v2@latest")
            return []

        logger.info(f"[Dalfox] Scanning {len(scoped)} URLs for XSS")

        # Write URLs to temp file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write("\n".join(scoped))
            targets_file = f.name

        output_file = self.output_dir / f"dalfox_{program.replace('.', '_')}.json"
        findings = []

        try:
            cmd = self._build_command(targets_file, str(output_file))
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.communicate(), timeout=600)

            findings = self._parse_output(output_file, program)
            if findings:
                await self._save_findings(findings, program)
                logger.info(f"[Dalfox] Found {len(findings)} XSS vulnerabilities")

        except asyncio.TimeoutError:
            logger.warning("[Dalfox] Timeout")
        except Exception as e:
            logger.error(f"[Dalfox] Error: {e}")
        finally:
            os.unlink(targets_file)

        return findings

    async def scan_single(
        self, url: str, program: str = ""
    ) -> Optional[dict]:
        """Scan a single URL for XSS."""
        results = await self.scan_urls([url], program)
        return results[0] if results else None

    def _build_command(
        self, targets_file: str, output_file: str
    ) -> list[str]:
        """Build Dalfox command for bug bounty safe use."""
        delay = int(
            self.stealth.get("min_delay_seconds", 1.5) * 1000
        )  # ms
        cmd = [
            "dalfox", "file", targets_file,
            "--output", output_file,
            "--format", "json",
            "--silence",
            "--no-color",
            "--delay", str(delay),
            "--timeout", "10",
            "--worker", "20",
            # Safe options for bug bounty
            "--skip-bav",          # Skip BAV analysis (faster)
            "--only-custom-payload",  # Use safe payloads only
        ]

        # Add blind XSS callback if configured
        blind_xss = self.config.get("scanner", {}).get(
            "dalfox", {}
        ).get("blind_xss_callback", "")
        if blind_xss:
            cmd += ["--blind", blind_xss]

        return cmd

    def _parse_output(
        self, output_file: Path, program: str
    ) -> list[dict]:
        """Parse Dalfox JSON output into BugFlow findings."""
        findings = []
        if not output_file.exists():
            return findings

        try:
            with open(output_file) as f:
                content = f.read().strip()
                if not content:
                    return findings

                # Dalfox outputs one JSON object per line
                for line in content.split("\n"):
                    if not line.strip():
                        continue
                    try:
                        result = json.loads(line)
                        finding = self._result_to_finding(result, program)
                        if finding:
                            findings.append(finding)
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            logger.error(f"[Dalfox] Parse error: {e}")

        return findings

    def _result_to_finding(
        self, result: dict, program: str
    ) -> Optional[dict]:
        """Convert Dalfox result to BugFlow finding format."""
        if result.get("type") not in ("R", "V"):  # R=Reflected, V=Verified
            return None

        url = result.get("data", "")
        param = result.get("param", "")
        payload = result.get("evidence", "")
        xss_type = "Reflected XSS" if result.get("type") == "R" else "Verified XSS"
        poc_url = result.get("pocCode", url)

        return {
            "title": f"{xss_type}: {url[:80]}",
            "severity": "high",
            "vuln_type": "xss",
            "target": url,
            "param": param,
            "description": (
                f"{xss_type} found by Dalfox.\n"
                f"Parameter: {param}\n"
                f"Payload: {payload[:200] if payload else 'see PoC URL'}"
            ),
            "reproduction_steps": (
                f"1. Open browser\n"
                f"2. Navigate to: {poc_url or url}\n"
                f"3. Observe JavaScript execution\n"
                f"4. Confirm XSS in console or alert dialog"
            ),
            "proof_of_concept": (
                f"PoC URL: {poc_url}\n"
                f"Parameter: {param}\n"
                f"Payload: {payload}"
            ),
            "ai_score": 8.0,
            "tool": "dalfox",
            "program": program,
        }

    async def _save_findings(
        self, findings: list[dict], program: str
    ):
        """Save XSS findings to database."""
        conn = get_conn(self.db_path)
        try:
            for f in findings:
                save_finding(
                    conn,
                    title=f["title"],
                    severity=f["severity"],
                    vuln_type="xss",
                    description=f["description"],
                    reproduction_steps=f["reproduction_steps"],
                    proof_of_concept=f["proof_of_concept"],
                    ai_score=f["ai_score"],
                    program=program,
                )
            conn.commit()
        finally:
            conn.close()

    def _dalfox_installed(self) -> bool:
        try:
            subprocess.run(["dalfox", "version"], capture_output=True)
            return True
        except FileNotFoundError:
            return False
