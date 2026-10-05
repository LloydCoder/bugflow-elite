"""
BugFlow Elite v6 — Subdomain Takeover Hunter
High-payout, low-competition bug class. Detects dangling CNAME, NS,
MX, SPF, SRV records, stale A records, and AXFR zone transfer leaks.
Tools: BadDNS + subjack
Tinlance Limited | LloydCoder
"""

import json
import logging
import asyncio
import subprocess
from pathlib import Path
from typing import Optional
from modules.scope.scope_enforcer import ScopeEnforcer
from db.models import get_conn, save_finding

logger = logging.getLogger(__name__)

# Known takeover-vulnerable services and their fingerprints
TAKEOVER_FINGERPRINTS = {
    "heroku":       ["There is no app configured at that hostname", "No such app"],
    "github":       ["There isn't a GitHub Pages site here", "404 There is nothing here"],
    "shopify":      ["Sorry, this shop is currently unavailable"],
    "fastly":       ["Fastly error: unknown domain"],
    "azure":        ["404 Web Site not found", "The resource you are looking for has been removed"],
    "aws_s3":       ["The specified bucket does not exist", "NoSuchBucket"],
    "netlify":      ["Not Found - Request ID"],
    "surge":        ["project not found"],
    "tumblr":       ["Whatever you were looking for doesn't currently exist"],
    "wordpress":    ["Do you want to register"],
    "zendesk":      ["Help Center Closed"],
    "bitbucket":    ["Repository not found"],
    "ghost":        ["The thing you were looking for is no longer here"],
    "helpjuice":    ["We could not find what you're looking for"],
    "readme":       ["Project doesnt exist... yet"],
    "uservoice":    ["This UserVoice subdomain is currently available"],
    "statuspage":   ["You are being redirected"],
    "smartjobboard":["This job board website is either expired"],
    "tilda":        ["Domain is not connected"],
    "strikingly":   ["This domain is available on Strikingly"],
    "feedpress":    ["The feed has not been found"],
    "kajabi":       ["The page you were looking for doesn't exist"],
}


class TakeoverHunter:
    """
    Scans all discovered subdomains for subdomain takeover vulnerabilities.
    Uses BadDNS for comprehensive DNS record analysis and subjack for
    multi-vector takeover detection including AXFR, SPF, and MX records.
    """

    def __init__(self, config: dict, scope: ScopeEnforcer):
        self.config = config
        self.scope = scope
        self.db_path = config.get("general", {}).get("db_path", "./db/bugflow.db")
        self.takeover_cfg = config.get("scanner", {}).get("takeover", {})
        self.output_dir = Path("./output/takeovers")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def run(self, subdomains: list[str], program: str = "") -> list[dict]:
        """
        Full takeover scan on a list of subdomains.
        Returns list of confirmed/suspected takeover findings.
        """
        if not subdomains:
            return []

        # Scope filter first
        subdomains = self.scope.filter_in_scope(subdomains)
        logger.info(f"[Takeover] Scanning {len(subdomains)} subdomains")

        findings = []

        # Run BadDNS
        if self.takeover_cfg.get("baddns", {}).get("enabled"):
            baddns_findings = await self._run_baddns(subdomains)
            findings.extend(baddns_findings)

        # Run subjack
        if self.takeover_cfg.get("subjack", {}).get("enabled"):
            subjack_findings = await self._run_subjack(subdomains)
            findings.extend(subjack_findings)

        # HTTP fingerprint check for undetected takeovers
        fp_findings = await self._http_fingerprint_check(subdomains)
        findings.extend(fp_findings)

        # Deduplicate by subdomain
        seen = set()
        unique_findings = []
        for f in findings:
            key = f.get("subdomain", "")
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        if unique_findings:
            await self._save_findings(unique_findings, program)
            logger.info(f"[Takeover] Found {len(unique_findings)} potential takeovers")

        return unique_findings

    async def _run_baddns(self, subdomains: list[str]) -> list[dict]:
        """Run BadDNS for comprehensive DNS record analysis."""
        if not self._tool_installed("baddns"):
            logger.warning("[Takeover] BadDNS not installed")
            return []

        findings = []
        modules = self.takeover_cfg.get("baddns", {}).get(
            "modules", ["cname", "ns", "mx", "references"]
        )

        # Write subdomains to temp file
        input_file = self.output_dir / "baddns_input.txt"
        with open(input_file, "w") as f:
            f.write("\n".join(subdomains))

        for module in modules:
            try:
                output_file = self.output_dir / f"baddns_{module}.json"
                cmd = [
                    "baddns",
                    "-t", str(input_file),
                    "-m", module,
                    "-o", str(output_file),
                    "--json"
                ]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await asyncio.wait_for(proc.communicate(), timeout=300)

                if output_file.exists():
                    with open(output_file) as f:
                        try:
                            results = json.load(f)
                            for result in results:
                                if result.get("vulnerable"):
                                    findings.append({
                                        "subdomain": result.get("host", ""),
                                        "record_type": module.upper(),
                                        "record_value": result.get("cname", result.get("value", "")),
                                        "provider": result.get("provider", "unknown"),
                                        "takeover_type": f"dangling_{module}",
                                        "is_verified": True,
                                        "tool": "baddns",
                                        "evidence": json.dumps(result),
                                    })
                        except json.JSONDecodeError:
                            pass

            except asyncio.TimeoutError:
                logger.warning(f"[BadDNS] Timeout on {module} module")
            except Exception as e:
                logger.error(f"[BadDNS] Error on {module} module: {e}")

        logger.info(f"[BadDNS] Found {len(findings)} potential takeovers")
        return findings

    async def _run_subjack(self, subdomains: list[str]) -> list[dict]:
        """
        Run subjack for multi-vector takeover detection:
        CNAME chains, NS delegations, stale A records, AXFR, SPF, MX.
        """
        if not self._tool_installed("subjack"):
            logger.warning("[Takeover] subjack not installed")
            return []

        input_file = self.output_dir / "subjack_input.txt"
        output_file = self.output_dir / "subjack_results.json"

        with open(input_file, "w") as f:
            f.write("\n".join(subdomains))

        subjack_cfg = self.takeover_cfg.get("subjack", {})
        cmd = ["subjack", "-w", str(input_file), "-o", str(output_file)]

        if subjack_cfg.get("ssl"):
            cmd.append("-ssl")
        if subjack_cfg.get("axfr"):
            cmd.append("-axfr")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.communicate(), timeout=600)
        except asyncio.TimeoutError:
            logger.warning("[subjack] Timeout")
            return []
        except Exception as e:
            logger.error(f"[subjack] Error: {e}")
            return []

        findings = []
        if output_file.exists():
            try:
                with open(output_file) as f:
                    results = json.load(f)
                    if isinstance(results, list):
                        for result in results:
                            subdomain = result.get("subdomain", "")
                            if not subdomain:
                                continue
                            status = result.get("status", "")
                            findings.append({
                                "subdomain": subdomain,
                                "record_type": result.get("record_type", "CNAME"),
                                "record_value": result.get("cname", ""),
                                "provider": result.get("service", "unknown"),
                                "takeover_type": status.lower().replace(" ", "_"),
                                "is_verified": "vulnerable" in status.lower(),
                                "tool": "subjack",
                                "evidence": json.dumps(result),
                            })
            except Exception as e:
                logger.error(f"[subjack] Output parse error: {e}")

        logger.info(f"[subjack] Found {len(findings)} potential takeovers")
        return findings

    async def _http_fingerprint_check(self, subdomains: list[str]) -> list[dict]:
        """
        HTTP response fingerprint check against known takeover signatures.
        Catches takeovers that DNS tools miss (custom error pages, etc).
        """
        import aiohttp
        findings = []
        semaphore = asyncio.Semaphore(20)

        async def check_one(subdomain: str):
            async with semaphore:
                for scheme in ["https", "http"]:
                    url = f"{scheme}://{subdomain}"
                    try:
                        async with aiohttp.ClientSession() as session:
                            async with session.get(
                                url,
                                timeout=aiohttp.ClientTimeout(total=8),
                                allow_redirects=True,
                                ssl=False
                            ) as resp:
                                body = await resp.text(errors="ignore")
                                for provider, signatures in TAKEOVER_FINGERPRINTS.items():
                                    for sig in signatures:
                                        if sig.lower() in body.lower():
                                            findings.append({
                                                "subdomain": subdomain,
                                                "record_type": "HTTP_FINGERPRINT",
                                                "record_value": url,
                                                "provider": provider,
                                                "takeover_type": "fingerprint_match",
                                                "is_verified": True,
                                                "tool": "http_fingerprint",
                                                "evidence": f"Matched: '{sig}' in response",
                                            })
                                            return
                        break  # Don't try http if https worked
                    except Exception:
                        continue

        await asyncio.gather(*[check_one(s) for s in subdomains[:200]])
        return findings

    async def _save_findings(self, findings: list[dict], program: str):
        """Save takeover findings to database as high-severity findings."""
        conn = get_conn(self.db_path)
        try:
            for finding in findings:
                if not finding.get("is_verified"):
                    continue
                save_finding(
                    conn,
                    title=f"Subdomain Takeover: {finding['subdomain']}",
                    severity="high",
                    vuln_type="takeover",
                    description=(
                        f"Subdomain {finding['subdomain']} has a dangling "
                        f"{finding['record_type']} record pointing to "
                        f"{finding['provider']}. The service is no longer "
                        f"provisioned and can be claimed by an attacker."
                    ),
                    reproduction_steps=(
                        f"1. Verify: dig {finding['record_type']} {finding['subdomain']}\n"
                        f"2. Confirm target service ({finding['provider']}) is unclaimed\n"
                        f"3. Document the CNAME/NS value and HTTP response"
                    ),
                    proof_of_concept=finding.get("evidence", ""),
                    ai_score=8.5,  # Takeovers are always high-value
                    program=program,
                )
            conn.commit()
        finally:
            conn.close()

    def _tool_installed(self, tool: str) -> bool:
        try:
            subprocess.run([tool], capture_output=True)
            return True
        except FileNotFoundError:
            return False
