"""
BugFlow Elite v6 — reconFTW Integration Engine
Runs reconFTW alongside BBOT. Parses ALL reconFTW output files
and feeds subdomains, takeovers, nuclei hits, and secrets
directly into BugFlow's AI triage pipeline.
Tinlance Limited | LloydCoder
"""

import json
import logging
import asyncio
import subprocess
from pathlib import Path
from typing import Optional
from modules.scope.scope_enforcer import ScopeEnforcer
from db.models import get_conn, upsert_asset

logger = logging.getLogger(__name__)


class ReconFTWEngine:
    """
    Wraps reconFTW and parses its full output directory.
    Merges findings into BugFlow's unified pipeline so everything
    gets AI triage, dedup, and H1 draft generation automatically.
    """

    def __init__(self, config: dict, scope: ScopeEnforcer):
        self.config = config
        self.scope = scope
        self.db_path = config.get("general", {}).get("db_path", "./db/bugflow.db")

        # Auto-detect reconFTW location
        self.reconftw_path = self._find_reconftw()
        self.config_path = Path.home() / "reconftw" / "reconftw.cfg"
        self.output_dir = Path("./output/reconftw")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.enabled = self.reconftw_path is not None
        if self.enabled:
            logger.info(f"[reconFTW] Found at {self.reconftw_path}")
        else:
            logger.info("[reconFTW] Not installed — skipping reconFTW stage")

    def _find_reconftw(self) -> Optional[Path]:
        """Auto-detect reconFTW installation path."""
        candidates = [
            Path.home() / "reconftw" / "reconftw.sh",
            Path("/opt/reconftw/reconftw.sh"),
            Path("/root/reconftw/reconftw.sh"),
            Path("./reconftw/reconftw.sh"),
        ]
        for path in candidates:
            if path.exists():
                return path
        # Try which command
        try:
            result = subprocess.run(
                ["which", "reconftw.sh"],
                capture_output=True, text=True
            )
            if result.returncode == 0 and result.stdout.strip():
                return Path(result.stdout.strip())
        except Exception:
            pass
        return None

    async def run(self, domain: str, scan_type: str = "incremental") -> dict:
        """
        Run reconFTW and return all parsed findings as a structured dict.
        Returns:
            {
                "subdomains": [...],
                "takeovers": [...],
                "nuclei_findings": [...],
                "secrets": [...],
                "live_hosts": [...],
                "endpoints": [...],
                "vulnerabilities": [...],
            }
        """
        empty = {
            "subdomains": [], "takeovers": [], "nuclei_findings": [],
            "secrets": [], "live_hosts": [], "endpoints": [], "vulnerabilities": []
        }

        if not self.enabled:
            return empty

        # Hard scope check before running anything
        self.scope.assert_in_scope(domain)

        mode_flag = self._get_mode_flag(scan_type)
        domain_output = self.output_dir / domain
        domain_output.mkdir(parents=True, exist_ok=True)

        cmd = self._build_command(domain, mode_flag, domain_output)
        logger.info(f"[reconFTW] Starting {scan_type} scan on {domain}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._get_env()
            )
            # reconFTW full scans can take 30-120 minutes
            timeout = 7200 if scan_type == "full" else 3600
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
                if proc.returncode != 0:
                    logger.warning(
                        f"[reconFTW] Exit code {proc.returncode}: "
                        f"{stderr.decode()[:300]}"
                    )
            except asyncio.TimeoutError:
                logger.warning(f"[reconFTW] Timeout after {timeout//60}min — parsing partial results")
                proc.kill()

        except FileNotFoundError:
            logger.error(f"[reconFTW] Cannot execute {self.reconftw_path}")
            return empty
        except Exception as e:
            logger.error(f"[reconFTW] Error: {e}")
            return empty

        # Parse all output files
        results = await self._parse_all_outputs(domain, domain_output)

        # Save subdomains to DB
        await self._save_subdomains(results["subdomains"], domain)

        total = sum(len(v) for v in results.values())
        logger.info(
            f"[reconFTW] Parsed: {len(results['subdomains'])} subdomains, "
            f"{len(results['nuclei_findings'])} nuclei hits, "
            f"{len(results['takeovers'])} takeovers, "
            f"{len(results['secrets'])} secrets"
        )
        return results

    def _get_mode_flag(self, scan_type: str) -> str:
        """Map BugFlow scan_type to reconFTW flag."""
        return {
            "incremental": "-p",    # passive only — safe, fast
            "full":        "-r",    # full recon
            "passive":     "-p",
        }.get(scan_type, "-p")

    def _build_command(
        self, domain: str, mode_flag: str, output_dir: Path
    ) -> list[str]:
        """Build reconFTW CLI command."""
        cmd = [
            "bash", str(self.reconftw_path),
            "-d", domain,
            mode_flag,
            "-o", str(output_dir) + "/",
        ]
        # Use custom config if it exists
        if self.config_path.exists():
            cmd += ["-f", str(self.config_path)]
        return cmd

    def _get_env(self) -> dict:
        """Build environment variables for reconFTW."""
        import os
        env = os.environ.copy()
        # Pass API keys from BugFlow config into reconFTW
        api_keys = self.config.get("recon", {}).get("bbot", {}).get("api_keys", {})
        key_map = {
            "github":           "GITHUB_TOKEN",
            "shodan":           "SHODAN_API_KEY",
            "virustotal":       "VIRUSTOTAL_API_KEY",
            "securitytrails":   "SECURITYTRAILS_API_KEY",
            "chaos":            "CHAOS_KEY",
        }
        for cfg_key, env_key in key_map.items():
            val = api_keys.get(cfg_key, "")
            if val:
                env[env_key] = val
        return env

    async def _parse_all_outputs(self, domain: str, output_dir: Path) -> dict:
        """
        Parse every reconFTW output file into structured BugFlow findings.
        reconFTW writes to a predictable directory structure.
        """
        results = {
            "subdomains": [],
            "takeovers": [],
            "nuclei_findings": [],
            "secrets": [],
            "live_hosts": [],
            "endpoints": [],
            "vulnerabilities": [],
        }

        # ── Subdomains ─────────────────────────────────────────
        for fname in ["subdomains.txt", "subdomains_alive.txt"]:
            subs = self._read_lines(output_dir / "subdomains" / fname)
            results["subdomains"].extend(subs)

        results["subdomains"] = list(set(
            self.scope.filter_in_scope(results["subdomains"])
        ))

        # ── Live Hosts ─────────────────────────────────────────
        live = self._read_lines(output_dir / "subdomains" / "subdomains_alive.txt")
        results["live_hosts"] = list(set(live))

        # ── Subdomain Takeovers ────────────────────────────────
        takeover_file = output_dir / "subdomains" / "takeovers.txt"
        for sub in self._read_lines(takeover_file):
            if sub.strip():
                results["takeovers"].append({
                    "subdomain": sub.strip(),
                    "title": f"Subdomain Takeover: {sub.strip()}",
                    "severity": "high",
                    "vuln_type": "takeover",
                    "target": sub.strip(),
                    "description": (
                        f"reconFTW detected a potential subdomain takeover "
                        f"on {sub.strip()}. The subdomain appears to have a "
                        f"dangling DNS record pointing to an unclaimed service."
                    ),
                    "reproduction_steps": (
                        f"1. Run: dig CNAME {sub.strip()}\n"
                        f"2. Identify the target service from the CNAME value\n"
                        f"3. Attempt to claim the service at that provider\n"
                        f"4. If claimable, document and report"
                    ),
                    "ai_score": 8.0,
                    "tool": "reconftw",
                    "program": domain,
                })

        # ── Nuclei Findings ────────────────────────────────────
        for fname in ["nuclei.txt", "nuclei_critical.txt", "nuclei_high.txt"]:
            nuclei_file = output_dir / "vulns" / fname
            for line in self._read_lines(nuclei_file):
                parsed = self._parse_nuclei_line(line, domain)
                if parsed:
                    results["nuclei_findings"].append(parsed)

        # Also check JSON format
        nuclei_json = output_dir / "vulns" / "nuclei.json"
        if nuclei_json.exists():
            for line in self._read_lines(nuclei_json):
                try:
                    data = json.loads(line)
                    info = data.get("info", {})
                    results["nuclei_findings"].append({
                        "title": info.get("name", "Nuclei Finding"),
                        "severity": info.get("severity", "info"),
                        "vuln_type": "nuclei",
                        "target": data.get("host", ""),
                        "template_id": data.get("template-id", ""),
                        "description": info.get("description", ""),
                        "proof_of_concept": json.dumps({
                            "matched_at": data.get("matched-at", ""),
                            "extracted": data.get("extracted-results", []),
                        }),
                        "tool": "reconftw_nuclei",
                        "program": domain,
                    })
                except json.JSONDecodeError:
                    pass

        # ── Secrets / Leaked Credentials ──────────────────────
        for fname in ["secrets.txt", "gitleaks.txt", "trufflehog.txt"]:
            secret_file = output_dir / "vulns" / fname
            for line in self._read_lines(secret_file):
                if line.strip():
                    results["secrets"].append({
                        "title": f"Leaked Secret Detected",
                        "severity": "high",
                        "vuln_type": "secret",
                        "target": domain,
                        "description": f"reconFTW detected a potential secret: {line[:200]}",
                        "ai_score": 7.5,
                        "tool": "reconftw_secrets",
                        "program": domain,
                    })

        # ── Endpoints / URLs ───────────────────────────────────
        for fname in ["urls.txt", "endpoints.txt", "parameters.txt"]:
            ep_file = output_dir / "urls" / fname
            endpoints = self._read_lines(ep_file)
            results["endpoints"].extend(endpoints[:500])  # Cap

        # ── Other Vulnerabilities (XSS, SQLi, etc.) ───────────
        vuln_files = {
            "xss.txt":          ("Cross-Site Scripting (XSS)", "high",   "xss"),
            "sqli.txt":         ("SQL Injection",               "critical","sqli"),
            "ssrf.txt":         ("Server-Side Request Forgery", "high",   "ssrf"),
            "open_redirect.txt":("Open Redirect",               "medium", "open_redirect"),
            "cors.txt":         ("CORS Misconfiguration",        "medium", "cors"),
            "lfi.txt":          ("Local File Inclusion",         "high",   "lfi"),
            "ssti.txt":         ("Server-Side Template Injection","critical","ssti"),
            "idor.txt":         ("Insecure Direct Object Reference","high","idor"),
        }
        for fname, (title, severity, vuln_type) in vuln_files.items():
            for line in self._read_lines(output_dir / "vulns" / fname):
                if line.strip():
                    results["vulnerabilities"].append({
                        "title": f"{title}: {line.strip()[:80]}",
                        "severity": severity,
                        "vuln_type": vuln_type,
                        "target": line.strip(),
                        "description": (
                            f"reconFTW detected a potential {title} vulnerability "
                            f"at {line.strip()}"
                        ),
                        "reproduction_steps": f"1. Visit: {line.strip()}\n2. Verify manually",
                        "tool": f"reconftw_{vuln_type}",
                        "program": domain,
                    })

        return results

    def _parse_nuclei_line(self, line: str, domain: str) -> Optional[dict]:
        """Parse a single nuclei text output line."""
        if not line.strip():
            return None

        # reconFTW nuclei format: [template-id] [severity] target
        severity = "info"
        for sev in ["critical", "high", "medium", "low", "info"]:
            if f"[{sev}]" in line.lower():
                severity = sev
                break

        return {
            "title": f"Nuclei: {line.strip()[:120]}",
            "severity": severity,
            "vuln_type": "nuclei",
            "target": domain,
            "description": line.strip(),
            "proof_of_concept": line.strip(),
            "tool": "reconftw_nuclei",
            "program": domain,
        }

    def _read_lines(self, path: Path) -> list[str]:
        """Safely read a file and return non-empty lines."""
        if not path.exists():
            return []
        try:
            return [
                l.strip() for l in path.read_text(errors="ignore").splitlines()
                if l.strip() and not l.startswith("#")
            ]
        except Exception:
            return []

    async def _save_subdomains(self, subdomains: list[str], domain: str):
        """Persist discovered subdomains to BugFlow database."""
        conn = get_conn(self.db_path)
        try:
            for sub in subdomains:
                upsert_asset(conn, subdomain=sub, domain=domain, source="reconftw")
            conn.commit()
        finally:
            conn.close()
