"""
BugFlow Elite v6 — BBOT Recursive Recon Engine
Primary asset discovery layer. Finds 20-50% more subdomains than
single-tool approaches through recursive, real-time OSINT chaining.
Tinlance Limited | LloydCoder
"""

import json
import logging
import asyncio
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional
from modules.scope.scope_enforcer import ScopeEnforcer, ScopeViolationError
from db.models import upsert_asset, get_conn

logger = logging.getLogger(__name__)


class BBOTEngine:
    """
    Wraps BBOT for recursive subdomain enumeration + cloud enum + web scanning.
    Falls back to Subfinder + Amass if BBOT is not installed.
    """

    def __init__(self, config: dict, scope: ScopeEnforcer):
        self.config = config
        self.scope = scope
        self.db_path = config.get("general", {}).get("db_path", "./db/bugflow.db")
        self.bbot_cfg = config.get("recon", {}).get("bbot", {})
        self.output_dir = Path(self.bbot_cfg.get("output_dir", "./output/bbot"))
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def run(self, domain: str, scan_type: str = "incremental") -> list[str]:
        """
        Run BBOT against a domain. Returns list of discovered subdomains.
        scan_type: 'incremental' (subdomain-enum only) or 'full' (all presets)
        """
        # Hard scope check before anything runs
        self.scope.assert_in_scope(domain)

        logger.info(f"[BBOT] Starting {scan_type} recon on {domain}")

        if not self._bbot_installed():
            logger.warning("[BBOT] Not installed — falling back to Subfinder")
            return await self._fallback_subfinder(domain)

        presets = self._get_presets(scan_type)
        cmd = self._build_command(domain, presets)

        try:
            result = await self._run_command(cmd)
            subdomains = self._parse_output(result, domain)
            # Filter through scope enforcer
            subdomains = self.scope.filter_in_scope(subdomains)
            await self._save_to_db(subdomains, domain)
            logger.info(f"[BBOT] Found {len(subdomains)} in-scope subdomains for {domain}")
            return subdomains
        except Exception as e:
            logger.error(f"[BBOT] Error: {e}")
            return await self._fallback_subfinder(domain)

    def _bbot_installed(self) -> bool:
        try:
            subprocess.run(["bbot", "--version"], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def _get_presets(self, scan_type: str) -> list[str]:
        """Return appropriate BBOT presets based on scan type."""
        if scan_type == "incremental":
            return ["subdomain-enum"]
        else:
            configured = self.bbot_cfg.get("presets", ["subdomain-enum"])
            return configured

    def _build_command(self, domain: str, presets: list[str]) -> list[str]:
        """Build the BBOT CLI command."""
        cmd = [
            "bbot",
            "-t", domain,
            "-o", str(self.output_dir / domain),
            "--json",
            "--ignore-failed-deps",
        ]
        for preset in presets:
            cmd += ["-p", preset]

        # Inject API keys from config
        api_keys = self.bbot_cfg.get("api_keys", {})
        for key_name, key_val in api_keys.items():
            if key_val:
                cmd += ["-c", f"modules.{key_name}.api_key={key_val}"]

        # Stealth: never allow deadly modes in bug bounty
        if self.bbot_cfg.get("allow_deadly", False):
            logger.warning("[BBOT] allow_deadly is True — keeping False for safety")

        return cmd

    async def _run_command(self, cmd: list[str]) -> str:
        """Run BBOT command asynchronously."""
        logger.debug(f"[BBOT] Running: {' '.join(cmd)}")
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            logger.warning(f"[BBOT] Exit code {proc.returncode}: {stderr.decode()[:500]}")
        return stdout.decode()

    def _parse_output(self, output: str, domain: str) -> list[str]:
        """Parse BBOT JSON output and extract DNS_NAME events."""
        subdomains = set()
        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                if event.get("type") == "DNS_NAME":
                    host = event.get("data", "").lower().strip()
                    if host and domain in host:
                        subdomains.add(host)
            except json.JSONDecodeError:
                # Some BBOT lines are not JSON (status messages)
                pass

        # Also check BBOT output file
        output_file = self.output_dir / domain / "output.json"
        if output_file.exists():
            try:
                with open(output_file) as f:
                    for line in f:
                        event = json.loads(line)
                        if event.get("type") == "DNS_NAME":
                            host = event.get("data", "").lower().strip()
                            if host and domain in host:
                                subdomains.add(host)
            except Exception as e:
                logger.debug(f"[BBOT] Output file parse error: {e}")

        return list(subdomains)

    async def _save_to_db(self, subdomains: list[str], domain: str):
        """Save discovered subdomains to the database."""
        conn = get_conn(self.db_path)
        for sub in subdomains:
            upsert_asset(conn, subdomain=sub, domain=domain, source="bbot")
        conn.close()

    async def _fallback_subfinder(self, domain: str) -> list[str]:
        """Fallback to Subfinder when BBOT is not available."""
        logger.info(f"[Subfinder] Running fallback recon on {domain}")

        if not self._tool_installed("subfinder"):
            logger.error("[Subfinder] Not installed either — no recon possible")
            return []

        cmd = [
            "subfinder",
            "-d", domain,
            "-silent",
            "-all",
            "-json",
        ]

        # Add recursive flag if configured
        subfinder_cfg = self.config.get("recon", {}).get("subfinder", {})
        if subfinder_cfg.get("recursive"):
            cmd.append("-recursive")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()

            subdomains = set()
            for line in stdout.decode().strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    host = data.get("host", "").lower().strip()
                    if host:
                        subdomains.add(host)
                except json.JSONDecodeError:
                    if domain in line.lower():
                        subdomains.add(line.strip().lower())

            result = self.scope.filter_in_scope(list(subdomains))
            await self._save_to_db(result, domain)
            logger.info(f"[Subfinder] Found {len(result)} subdomains")
            return result

        except Exception as e:
            logger.error(f"[Subfinder] Error: {e}")
            return []

    async def run_crtsh(self, domain: str) -> list[str]:
        """
        Query crt.sh for certificate transparency subdomain data.
        Completely passive — no active scanning.
        """
        self.scope.assert_in_scope(domain)
        import aiohttp

        url = f"https://crt.sh/?q=%.{domain}&output=json"
        subdomains = set()

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        for entry in data:
                            names = entry.get("name_value", "")
                            for name in names.split("\n"):
                                name = name.strip().lower().lstrip("*.")
                                if name and domain in name:
                                    subdomains.add(name)
            result = self.scope.filter_in_scope(list(subdomains))
            logger.info(f"[crt.sh] Found {len(result)} subdomains for {domain}")
            return result
        except Exception as e:
            logger.error(f"[crt.sh] Error: {e}")
            return []

    def _tool_installed(self, tool: str) -> bool:
        try:
            subprocess.run([tool, "--version"], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
