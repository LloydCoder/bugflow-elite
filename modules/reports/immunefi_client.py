"""
BugFlow Elite v6 — Immunefi Platform Client
Immunefi has no public submission API.
All reports submitted manually via dashboard.
This module:
  - Fetches active programs from Immunefi's public API
  - Scores programs by ROI (reward size × asset count)
  - Generates copy-paste-ready report markdown
  - Manages Immunefi-specific scope (contract addresses)
Tinlance Limited | LloydCoder
"""

import json
import logging
import aiohttp
from pathlib import Path
from typing import Optional
from db.models import get_conn

logger = logging.getLogger(__name__)

IMMUNEFI_PROGRAMS_API = "https://immunefi.com/api/bounty/all/"


class ImmunefiBountyClient:
    """
    Manages Immunefi bug bounty programs.
    Fetches active programs, scores by ROI,
    generates submission-ready reports.
    """

    def __init__(self, config: dict):
        self.config = config
        self.db_path = config.get("general", {}).get(
            "db_path", "./db/bugflow.db"
        )
        self.output_dir = Path("./output/immunefi")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def fetch_active_programs(self) -> list[dict]:
        """
        Fetch all active Immunefi programs from their public API.
        Returns programs sorted by maximum bounty descending.
        """
        logger.info("[Immunefi] Fetching active programs")
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    IMMUNEFI_PROGRAMS_API,
                    timeout=aiohttp.ClientTimeout(total=30),
                    headers={"User-Agent": "Mozilla/5.0"},
                ) as resp:
                    if resp.status != 200:
                        logger.warning(
                            f"[Immunefi] API returned {resp.status}"
                        )
                        return []
                    data = await resp.json(content_type=None)
                    programs = data if isinstance(data, list) else (
                        data.get("data", []) or []
                    )

            # Parse and score programs
            scored = []
            for prog in programs:
                parsed = self._parse_program(prog)
                if parsed:
                    scored.append(parsed)

            # Sort by max bounty descending
            scored.sort(
                key=lambda p: p.get("max_bounty_usd", 0),
                reverse=True,
            )

            logger.info(
                f"[Immunefi] {len(scored)} active programs found"
            )
            return scored

        except Exception as e:
            logger.error(f"[Immunefi] Fetch error: {e}")
            return []

    def _parse_program(self, raw: dict) -> Optional[dict]:
        """Parse raw Immunefi program data."""
        try:
            name = raw.get("project", raw.get("name", ""))
            if not name:
                return None

            # Extract bounty amounts
            max_bounty = 0
            bounty_table = raw.get("bountyTable", {}) or {}
            for category in bounty_table.values():
                if isinstance(category, dict):
                    for level in category.values():
                        if isinstance(level, dict):
                            amt = level.get("amount", 0)
                            if amt and isinstance(amt, (int, float)):
                                max_bounty = max(
                                    max_bounty, int(amt)
                                )

            # Also check top-level reward field
            top_reward = raw.get("maxBounty", raw.get("reward", 0))
            if isinstance(top_reward, (int, float)):
                max_bounty = max(max_bounty, int(top_reward))

            # Extract contract addresses
            assets = raw.get("assets", []) or []
            contract_addresses = []
            for asset in assets:
                if isinstance(asset, dict):
                    addr = asset.get("address", "")
                    chain = asset.get("network", asset.get("chain", "ethereum"))
                    if addr and addr.startswith("0x"):
                        contract_addresses.append({
                            "address": addr,
                            "chain": chain.lower() if chain else "ethereum",
                            "name": asset.get("name", ""),
                        })

            return {
                "name": name,
                "handle": raw.get("id", raw.get("slug", name.lower().replace(" ", "-"))),
                "platform": "immunefi",
                "max_bounty_usd": max_bounty,
                "contract_count": len(contract_addresses),
                "contracts": contract_addresses,
                "url": f"https://immunefi.com/bug-bounty/{raw.get('id', '')}/",
                "tvl": raw.get("tvl", raw.get("totalValueLocked", 0)),
                "is_active": raw.get("active", True),
                "kyc_required": raw.get("kycRequired", False),
            }
        except Exception:
            return None

    async def recommend_programs(
        self, limit: int = 10
    ) -> list[dict]:
        """
        Recommend top Immunefi programs ranked by ROI.
        Score = max_bounty × contract_count (more targets = more chances).
        """
        programs = await self.fetch_active_programs()
        if not programs:
            return []

        # Score by bounty size and number of contracts
        for prog in programs:
            bounty = prog.get("max_bounty_usd", 0)
            contracts = prog.get("contract_count", 0)
            tvl = prog.get("tvl", 0) or 0

            # Higher bounty + more contracts + more TVL = better ROI
            roi_score = (
                (bounty / 10000)         # Normalize to 0-100 range
                + (contracts * 2)        # Each contract is an opportunity
                + (min(tvl, 1e9) / 1e7)  # TVL up to $1B, normalized
            )
            prog["roi_score"] = roi_score

        scored = sorted(
            programs,
            key=lambda p: p.get("roi_score", 0),
            reverse=True,
        )
        return scored[:limit]

    def get_scope_for_program(self, program_name: str) -> list[dict]:
        """
        Get contract addresses in scope for an Immunefi program.
        Used to configure Web3Scanner targets.
        """
        conn = get_conn(self.db_path)
        try:
            rows = conn.execute("""
                SELECT scope_data FROM scope_cache
                WHERE platform='immunefi'
                AND program_name=?
                ORDER BY fetched_at DESC LIMIT 1
            """, (program_name,)).fetchone()

            if rows:
                data = json.loads(rows["scope_data"])
                return data.get("contracts", [])
        except Exception:
            pass
        finally:
            conn.close()
        return []

    async def export_submission_checklist(
        self, finding: dict
    ) -> str:
        """
        Generate an Immunefi submission checklist.
        Reminds you of everything Immunefi requires
        before you submit.
        """
        report_name = (
            f"immunefi_checklist_"
            f"{finding.get('contract_address', 'unknown')[:8]}"
            f"_{__import__('datetime').datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
            f".md"
        )
        path = self.output_dir / report_name

        content = f"""# Immunefi Submission Checklist

## Finding
**Title:** {finding.get('title', '')}
**Severity:** {finding.get('severity', '').upper()}
**Contract:** {finding.get('contract_address', '')}
**Chain:** {finding.get('chain', '')}

---

## Pre-Submission Checklist

### ✅ Required
- [ ] PoC demonstrates the bug on a **local fork** (not mainnet)
- [ ] PoC includes step-by-step reproduction
- [ ] Finding is NOT in previous audit reports
- [ ] Finding is NOT a known/duplicate issue
- [ ] Tested using Foundry/Hardhat local fork
- [ ] Report includes exact contract function name
- [ ] Report includes exact line number(s)
- [ ] Severity accurately reflects actual impact

### ✅ Submission Form Fields
- [ ] **Project:** Select correct project
- [ ] **Asset type:** Smart Contract
- [ ] **Asset address:** `{finding.get('contract_address', '')}`
- [ ] **Impact:** Select from dropdown (matches severity)
- [ ] **Vulnerability:** Select category from dropdown
- [ ] **PoC:** Attach foundry test or transaction trace

### ⚠️ Immunefi Rules Reminder
- Testing on mainnet = **BANNED**
- Contact project directly = **BANNED**
- Public disclosure before fix = **BANNED**
- Incomplete report without PoC = **REJECTED**
- Rate limit applies to submissions

### 📋 PoC Requirements
All PoC must:
1. Be runnable on a local fork
2. Show funds at risk OR access control bypass
3. Be reproducible by the triage team
4. Not cause real damage

### 💰 Payout Info
- Paid in **USDC on Ethereum**
- KYC required for critical findings
- Payment after project confirms fix
- Contact: bugs.immunefi.com

---

## Report Draft

{finding.get('description', '')}

### Reproduction Steps
{finding.get('reproduction_steps', '')}

### Proof of Concept
```solidity
{finding.get('proof_of_concept', '// Add PoC here')}
```

### Impact
{finding.get('impact', '')}
"""
        path.write_text(content)
        logger.info(f"[Immunefi] Checklist: {path}")
        return str(path)
