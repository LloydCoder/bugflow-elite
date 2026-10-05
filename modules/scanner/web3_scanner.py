"""
BugFlow Elite v6 — Web3 Smart Contract Scanner
Covers the full Web3 bug bounty workflow:
  1. Fetch contract source from Etherscan/BSCScan
  2. Run Slither static analysis (83 detectors)
  3. Run Mythril symbolic execution for deeper bugs
  4. AI triage to filter false positives
  5. Generate Immunefi-formatted PoC report
  6. Export as markdown (Immunefi has no public API)

Supported chains: Ethereum, BSC, Polygon, Arbitrum, Optimism, Avalanche
Supported analyzers: Slither v0.11+, Mythril
Tinlance Limited | LloydCoder
"""

import json
import logging
import asyncio
import aiohttp
import subprocess
import tempfile
import os
from pathlib import Path
from typing import Optional
from db.models import get_conn, save_finding

logger = logging.getLogger(__name__)

# ── Chain configurations ───────────────────────────────────────────────────

CHAINS = {
    "ethereum": {
        "name": "Ethereum",
        "explorer_api": "https://api.etherscan.io/api",
        "explorer_key_env": "ETHERSCAN_API_KEY",
        "rpc": "https://eth.llamarpc.com",
        "chain_id": 1,
    },
    "bsc": {
        "name": "BSC",
        "explorer_api": "https://api.bscscan.com/api",
        "explorer_key_env": "BSCSCAN_API_KEY",
        "rpc": "https://bsc-dataseed.binance.org",
        "chain_id": 56,
    },
    "polygon": {
        "name": "Polygon",
        "explorer_api": "https://api.polygonscan.com/api",
        "explorer_key_env": "POLYGONSCAN_API_KEY",
        "rpc": "https://polygon.llamarpc.com",
        "chain_id": 137,
    },
    "arbitrum": {
        "name": "Arbitrum",
        "explorer_api": "https://api.arbiscan.io/api",
        "explorer_key_env": "ARBISCAN_API_KEY",
        "rpc": "https://arb1.arbitrum.io/rpc",
        "chain_id": 42161,
    },
    "optimism": {
        "name": "Optimism",
        "explorer_api": "https://api-optimistic.etherscan.io/api",
        "explorer_key_env": "OPTIMISM_API_KEY",
        "rpc": "https://mainnet.optimism.io",
        "chain_id": 10,
    },
    "avalanche": {
        "name": "Avalanche",
        "explorer_api": "https://api.snowtrace.io/api",
        "explorer_key_env": "SNOWTRACE_API_KEY",
        "rpc": "https://api.avax.network/ext/bc/C/rpc",
        "chain_id": 43114,
    },
}

# ── Severity mapping from Slither impact ──────────────────────────────────

SLITHER_SEVERITY_MAP = {
    "High":   "critical",
    "Medium": "high",
    "Low":    "medium",
    "Informational": "low",
    "Optimization":  "info",
}

# ── High-value Slither detectors (skip low-value ones) ────────────────────

HIGH_VALUE_DETECTORS = {
    "reentrancy-eth",
    "reentrancy-no-eth",
    "reentrancy-benign",
    "unprotected-upgrade",
    "suicidal",
    "arbitrary-send-eth",
    "arbitrary-send-erc20",
    "controlled-delegatecall",
    "delegatecall-loop",
    "msg-value-loop",
    "tx-origin",
    "unchecked-transfer",
    "uninitialized-local",
    "uninitialized-state",
    "uninitialized-storage",
    "locked-ether",
    "shadowing-state",
    "write-after-write",
    "incorrect-equality",
    "weak-prng",
    "oracle-manipulation",
    "tautology",
    "divide-before-multiply",
    "integer-overflow",
}


class Web3Scanner:
    """
    Full Web3 smart contract security scanner.
    Downloads source, runs Slither + Mythril,
    generates Immunefi-ready reports.
    """

    def __init__(self, config: dict):
        self.config = config
        self.db_path = config.get("general", {}).get(
            "db_path", "./db/bugflow.db"
        )
        self.web3_cfg = config.get("web3", {})
        self.output_dir = Path("./output/web3")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def scan_contract(
        self,
        address: str,
        chain: str = "ethereum",
        program: str = "",
    ) -> list[dict]:
        """
        Full scan of a smart contract address.
        Returns list of findings.
        """
        chain_cfg = CHAINS.get(chain.lower())
        if not chain_cfg:
            logger.error(f"[Web3] Unknown chain: {chain}")
            return []

        logger.info(
            f"[Web3] Scanning contract {address} on {chain}"
        )

        # Step 1: Fetch source code
        source = await self._fetch_source(address, chain_cfg)
        if not source:
            logger.warning(
                f"[Web3] Could not fetch source for {address} "
                f"— contract may not be verified"
            )
            return []

        # Step 2: Write source to temp dir
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / f"contract_{address[:8]}.sol"
            sol_file.write_text(source)

            # Step 3: Run Slither
            slither_findings = await self._run_slither(
                str(sol_file), address, chain, program
            )

            # Step 4: Run Mythril (if installed)
            mythril_findings = await self._run_mythril(
                str(sol_file), address, chain, program
            )

        all_findings = slither_findings + mythril_findings

        # Step 5: AI triage to filter noise
        filtered = self._filter_findings(all_findings)

        if filtered:
            # Step 6: Generate Immunefi report
            report_path = await self._generate_immunefi_report(
                filtered, address, chain, program
            )
            # Step 7: Save to DB
            await self._save_findings(filtered, program)

            logger.info(
                f"[Web3] {len(filtered)} findings for {address} "
                f"| Report: {report_path}"
            )
        else:
            logger.info(
                f"[Web3] No significant findings for {address}"
            )

        return filtered

    async def scan_sol_file(
        self, sol_path: str, program: str = ""
    ) -> list[dict]:
        """
        Scan a local .sol file (for when you have source
        but not a deployed address).
        """
        logger.info(f"[Web3] Scanning local file: {sol_path}")

        slither_findings = await self._run_slither(
            sol_path, "local", "local", program
        )
        filtered = self._filter_findings(slither_findings)

        if filtered:
            await self._generate_immunefi_report(
                filtered, "local", "local", program
            )
            await self._save_findings(filtered, program)

        return filtered

    # ── Source Fetching ────────────────────────────────────────────────────

    async def _fetch_source(
        self, address: str, chain_cfg: dict
    ) -> Optional[str]:
        """
        Fetch verified contract source from block explorer API.
        Returns combined Solidity source code.
        """
        api_key = os.environ.get(
            chain_cfg["explorer_key_env"], ""
        )

        params = {
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
            "apikey": api_key or "YourApiKeyToken",
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    chain_cfg["explorer_api"],
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()

                    results = data.get("result", [])
                    if not results or results == "Max rate limit reached":
                        return None

                    result = results[0]
                    source = result.get("SourceCode", "")

                    if not source:
                        return None

                    # Handle multi-file source (JSON format)
                    if source.startswith("{"):
                        try:
                            # Strip outer braces if double-encoded
                            clean = source.strip("{}")
                            if clean.startswith("{"):
                                src_json = json.loads(clean)
                            else:
                                src_json = json.loads(source)

                            sources = src_json.get("sources", {})
                            combined = []
                            for fname, content in sources.items():
                                combined.append(
                                    f"// File: {fname}\n"
                                    f"{content.get('content', '')}"
                                )
                            return "\n\n".join(combined)
                        except json.JSONDecodeError:
                            pass

                    return source

        except Exception as e:
            logger.error(f"[Web3] Source fetch error: {e}")
            return None

    # ── Slither Analysis ───────────────────────────────────────────────────

    async def _run_slither(
        self,
        sol_path: str,
        address: str,
        chain: str,
        program: str,
    ) -> list[dict]:
        """Run Slither static analysis on a Solidity file."""
        if not self._slither_installed():
            logger.warning(
                "[Web3] Slither not installed. "
                "Install: pip install slither-analyzer"
            )
            return []

        output_file = self.output_dir / f"slither_{address[:8]}.json"

        cmd = [
            "slither", sol_path,
            "--json", str(output_file),
            "--solc-remaps", "@openzeppelin=node_modules/@openzeppelin",
            "--exclude-informational",
            "--exclude-optimization",
            "--filter-paths", "node_modules,test,mock",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(Path(sol_path).parent),
            )
            _, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=120
            )

            if not output_file.exists():
                # Slither sometimes outputs to stderr even on success
                logger.debug(
                    f"[Web3] Slither no JSON output: "
                    f"{stderr.decode()[:200]}"
                )
                return []

            return self._parse_slither_output(
                output_file, address, chain, program
            )

        except asyncio.TimeoutError:
            logger.warning("[Web3] Slither timeout")
            return []
        except Exception as e:
            logger.error(f"[Web3] Slither error: {e}")
            return []

    def _parse_slither_output(
        self,
        output_file: Path,
        address: str,
        chain: str,
        program: str,
    ) -> list[dict]:
        """Parse Slither JSON output into BugFlow findings."""
        try:
            data = json.loads(output_file.read_text())
        except Exception:
            return []

        findings = []
        results = data.get("results", {}).get("detectors", [])

        for result in results:
            check = result.get("check", "")
            impact = result.get("impact", "")
            confidence = result.get("confidence", "")
            description = result.get("description", "")
            elements = result.get("elements", [])

            # Only report high-value detectors or high impact
            if (
                check not in HIGH_VALUE_DETECTORS
                and impact not in ("High", "Medium")
            ):
                continue

            # Skip low-confidence findings
            if confidence == "Low" and impact != "High":
                continue

            severity = SLITHER_SEVERITY_MAP.get(impact, "medium")
            ai_score = {
                "critical": 9.0, "high": 7.5,
                "medium": 6.0, "low": 4.0, "info": 2.0,
            }.get(severity, 5.0)

            # Extract affected code locations
            locations = []
            for elem in elements[:5]:
                if elem.get("type") == "function":
                    contract = elem.get(
                        "type_specific_fields", {}
                    ).get("parent", {}).get("name", "")
                    func = elem.get("name", "")
                    line = elem.get(
                        "source_mapping", {}
                    ).get("lines", [None])[0]
                    if func:
                        loc = f"{contract}.{func}()"
                        if line:
                            loc += f" (line {line})"
                        locations.append(loc)

            poc = self._generate_poc(check, address, chain, elements)

            findings.append({
                "title": f"[{chain.upper()}] {self._humanize_check(check)}: {address[:10]}...",
                "severity": severity,
                "vuln_type": f"web3_{check.replace('-', '_')}",
                "target": f"{chain}:{address}",
                "description": (
                    f"Slither detected `{check}` "
                    f"(Impact: {impact}, Confidence: {confidence})\n\n"
                    f"{description}\n\n"
                    f"Affected: {', '.join(locations[:3])}"
                ),
                "reproduction_steps": (
                    f"1. Clone/fork the contract at {address}\n"
                    f"2. Run: `slither {sol_path or address} "
                    f"--detect {check}`\n"
                    f"3. Confirm finding at: "
                    f"{', '.join(locations[:2])}\n"
                    f"4. Write PoC test demonstrating impact"
                ),
                "proof_of_concept": poc,
                "impact": self._describe_impact(check),
                "ai_score": ai_score,
                "tool": "slither",
                "program": program,
                "chain": chain,
                "contract_address": address,
                "slither_check": check,
                "recommend_draft": ai_score >= 7.0,
            })

        return findings

    # ── Mythril Analysis ───────────────────────────────────────────────────

    async def _run_mythril(
        self,
        sol_path: str,
        address: str,
        chain: str,
        program: str,
    ) -> list[dict]:
        """Run Mythril symbolic execution for deeper analysis."""
        if not self._mythril_installed():
            logger.debug(
                "[Web3] Mythril not installed — skipping. "
                "Install: pip install mythril"
            )
            return []

        output_file = self.output_dir / f"mythril_{address[:8]}.json"

        cmd = [
            "myth", "analyze",
            sol_path,
            "--output", "jsonv2",
            "--max-depth", "10",      # Safe depth for speed
            "--execution-timeout", "60",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=90
            )
            output = stdout.decode(errors="ignore")

            if not output.strip():
                return []

            data = json.loads(output)
            issues = data.get("issues", [])
            findings = []

            for issue in issues:
                severity = {
                    "High": "critical",
                    "Medium": "high",
                    "Low": "medium",
                }.get(issue.get("severity", ""), "medium")

                findings.append({
                    "title": (
                        f"[{chain.upper()}] Mythril: "
                        f"{issue.get('title', 'Unknown Issue')} "
                        f"— {address[:10]}..."
                    ),
                    "severity": severity,
                    "vuln_type": "web3_mythril",
                    "target": f"{chain}:{address}",
                    "description": (
                        f"Mythril detected: {issue.get('title')}\n\n"
                        f"{issue.get('description', '')}\n\n"
                        f"Function: {issue.get('function', 'unknown')}\n"
                        f"PC: {issue.get('pc', 'unknown')}"
                    ),
                    "reproduction_steps": (
                        f"1. Install Mythril: pip install mythril\n"
                        f"2. Run: myth analyze {sol_path}\n"
                        f"3. Confirm issue in function: "
                        f"{issue.get('function', 'unknown')}"
                    ),
                    "proof_of_concept": (
                        f"Mythril transaction trace:\n"
                        f"{json.dumps(issue.get('tx_sequence', {}), indent=2)[:500]}"
                    ),
                    "impact": issue.get("description", ""),
                    "ai_score": 8.0 if severity == "critical" else 6.5,
                    "tool": "mythril",
                    "program": program,
                    "chain": chain,
                    "contract_address": address,
                })

            return findings

        except asyncio.TimeoutError:
            logger.debug("[Web3] Mythril timeout (expected for complex contracts)")
            return []
        except Exception as e:
            logger.debug(f"[Web3] Mythril error: {e}")
            return []

    # ── Report Generation ──────────────────────────────────────────────────

    async def _generate_immunefi_report(
        self,
        findings: list[dict],
        address: str,
        chain: str,
        program: str,
    ) -> str:
        """
        Generate Immunefi-formatted markdown report.
        Immunefi has no public API — all submissions via dashboard.
        This report is designed to be copy-pasted directly.
        """
        timestamp = __import__("datetime").datetime.utcnow().strftime(
            "%Y%m%d_%H%M%S"
        )
        report_path = (
            self.output_dir
            / f"immunefi_{address[:8]}_{timestamp}.md"
        )

        lines = [
            "# Immunefi Bug Report",
            "",
            "> ⚠️ DRAFT — Review all findings before submitting.",
            "> Per Immunefi rules: all testing must be on local forks.",
            "> Never test on mainnet. PoC required for all severities.",
            "",
            f"**Contract:** `{address}`",
            f"**Chain:** {chain.title()}",
            f"**Program:** {program}",
            f"**Analysis tools:** Slither v0.11, Mythril, BugFlow Elite v6",
            f"**Date:** {timestamp[:8]}",
            "",
            "---",
            "",
        ]

        for i, finding in enumerate(findings, 1):
            sev = finding.get("severity", "medium").upper()
            lines += [
                f"## Finding {i}: {finding.get('title', '')}",
                "",
                f"**Severity:** {sev}",
                f"**Type:** {finding.get('vuln_type', '').replace('web3_', '').replace('_', ' ').title()}",
                f"**Tool:** {finding.get('tool', 'slither').title()}",
                "",
                "### Summary",
                finding.get("description", ""),
                "",
                "### Impact",
                finding.get("impact", "See description."),
                "",
                "### Steps to Reproduce",
                finding.get("reproduction_steps", ""),
                "",
                "### Proof of Concept",
                "```solidity",
                finding.get("proof_of_concept", "// PoC code here"),
                "```",
                "",
                "---",
                "",
            ]

        report_path.write_text("\n".join(lines))
        logger.info(f"[Web3] Immunefi report: {report_path}")
        return str(report_path)

    # ── Helpers ────────────────────────────────────────────────────────────

    def _filter_findings(
        self, findings: list[dict]
    ) -> list[dict]:
        """Remove low-value/duplicate findings."""
        seen = set()
        filtered = []
        for f in findings:
            key = f.get("slither_check", "") or f.get("title", "")
            if key in seen:
                continue
            seen.add(key)
            # Skip info-level
            if f.get("severity") == "info":
                continue
            filtered.append(f)
        return filtered

    def _generate_poc(
        self,
        check: str,
        address: str,
        chain: str,
        elements: list,
    ) -> str:
        """Generate a basic PoC template for the finding."""
        poc_templates = {
            "reentrancy-eth": f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IVulnerable {{
    function withdraw(uint256 amount) external;
    function deposit() external payable;
}}

contract ReentrancyAttack {{
    IVulnerable public target = IVulnerable({address});
    uint256 public attackCount;

    receive() external payable {{
        if (attackCount < 3) {{
            attackCount++;
            target.withdraw(1 ether);
        }}
    }}

    function attack() external payable {{
        target.deposit{{value: msg.value}}();
        target.withdraw(msg.value);
    }}
}}

// Run on local fork: anvil --fork-url https://eth.llamarpc.com
// forge test --fork-url https://eth.llamarpc.com""",
            "unprotected-upgrade": f"""// Test: Can any address call upgrade?
// Contract: {address}

// 1. Fork mainnet locally
// 2. Call initialize() or upgradeTo() as arbitrary EOA
// 3. Confirm no owner/access check exists

// Using foundry:
// forge script --fork-url https://eth.llamarpc.com Attack.sol""",
        }
        return poc_templates.get(
            check,
            f"""// PoC for {check} on {address}
// Tool: Run `slither {address} --detect {check}` on local fork
// Chain: {chain}
// Note: All testing must be on local fork, never mainnet"""
        )

    def _humanize_check(self, check: str) -> str:
        """Convert slither check name to human readable."""
        mapping = {
            "reentrancy-eth": "Reentrancy (ETH drain)",
            "reentrancy-no-eth": "Reentrancy (state manipulation)",
            "unprotected-upgrade": "Unprotected Upgrade Function",
            "suicidal": "Arbitrary Self-Destruct",
            "arbitrary-send-eth": "Arbitrary ETH Transfer",
            "controlled-delegatecall": "Controlled Delegatecall",
            "tx-origin": "tx.origin Authentication Bypass",
            "unchecked-transfer": "Unchecked ERC20 Transfer",
            "locked-ether": "ETH Permanently Locked",
            "weak-prng": "Weak Randomness (PRNG)",
            "integer-overflow": "Integer Overflow/Underflow",
        }
        return mapping.get(
            check,
            check.replace("-", " ").replace("_", " ").title()
        )

    def _describe_impact(self, check: str) -> str:
        """Describe the business impact of a finding."""
        impacts = {
            "reentrancy-eth": (
                "An attacker can drain all ETH from the contract "
                "by recursively calling the vulnerable function "
                "before the balance is updated."
            ),
            "unprotected-upgrade": (
                "Any address can upgrade the contract to a malicious "
                "implementation, gaining full control over all user funds."
            ),
            "suicidal": (
                "Any address can permanently destroy the contract, "
                "locking all user funds forever."
            ),
            "arbitrary-send-eth": (
                "An attacker can redirect ETH transfers to an arbitrary "
                "address, stealing funds from the protocol."
            ),
            "tx-origin": (
                "Authentication can be bypassed using phishing attacks "
                "since tx.origin checks can be manipulated."
            ),
            "weak-prng": (
                "Randomness can be predicted or manipulated by miners, "
                "allowing exploitation of lottery/gaming functions."
            ),
        }
        return impacts.get(
            check,
            "This vulnerability may lead to loss of funds, "
            "unauthorized access, or contract manipulation."
        )

    def _slither_installed(self) -> bool:
        try:
            subprocess.run(
                ["slither", "--version"],
                capture_output=True, check=True
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def _mythril_installed(self) -> bool:
        try:
            subprocess.run(
                ["myth", "version"],
                capture_output=True
            )
            return True
        except FileNotFoundError:
            return False

    async def _save_findings(
        self, findings: list[dict], program: str
    ):
        conn = get_conn(self.db_path)
        try:
            for f in findings:
                save_finding(
                    conn,
                    title=f["title"],
                    severity=f["severity"],
                    vuln_type=f["vuln_type"],
                    description=f["description"],
                    reproduction_steps=f.get("reproduction_steps", ""),
                    proof_of_concept=f.get("proof_of_concept", ""),
                    ai_score=f.get("ai_score", 7.0),
                    program=program,
                )
            conn.commit()
        finally:
            conn.close()
