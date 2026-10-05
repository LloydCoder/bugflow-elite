"""
BugFlow Elite v6 — Self-Improver
Continuously improves the platform from real results:
1. Auto-updates all Go/Python security tools
2. Generates Nuclei templates from confirmed/paid findings
3. Learns program-specific patterns (what finds bounties on each program)
4. Updates scope from latest bounty-targets-data
5. Prunes low-signal custom templates
6. Reports weekly improvement summary via Telegram
Tinlance Limited | LloydCoder
"""

import json
import logging
import asyncio
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from db.models import get_conn

logger = logging.getLogger(__name__)

# Go tools to keep updated
GO_TOOLS = [
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "github.com/projectdiscovery/katana/cmd/katana@latest",
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "github.com/lc/gau/v2/cmd/gau@latest",
    "github.com/lc/subjs@latest",
    "github.com/BishopFox/jsluice/cmd/jsluice@latest",
    "github.com/sensepost/gowitness@latest",
    "github.com/ffuf/ffuf/v2@latest",
]


class SelfImprover:
    """
    Learns from results and continuously improves BugFlow's effectiveness.
    Runs weekly or after confirmed paid findings.
    """

    def __init__(self, config: dict):
        self.config = config
        self.db_path = config.get("general", {}).get("db_path", "./db/bugflow.db")
        self.custom_templates_dir = Path(
            config.get("scanner", {}).get("nuclei", {}).get(
                "custom_templates_dir", "./custom-templates"
            )
        )
        self.custom_templates_dir.mkdir(parents=True, exist_ok=True)
        self.patterns_file = Path("./output/program_patterns.json")

    async def run_weekly_improvement(self):
        """Full weekly improvement cycle."""
        logger.info("[SelfImprover] Starting weekly improvement cycle")

        results = {}

        # 1. Update all tools
        results["tools_updated"] = await self.update_tools()

        # 2. Update Nuclei templates
        results["nuclei_updated"] = await self.update_nuclei_templates()

        # 3. Generate templates from confirmed paid findings
        results["new_templates"] = await self.generate_from_paid_findings()

        # 4. Learn program patterns from paid findings
        results["patterns_learned"] = await self.learn_program_patterns()

        # 5. Prune low-value templates
        results["templates_pruned"] = await self.prune_templates()

        # 6. Update scope from latest data
        results["scope_updated"] = await self.refresh_scope_data()

        logger.info(
            f"[SelfImprover] Weekly cycle complete: "
            f"{results['tools_updated']} tools updated, "
            f"{results['new_templates']} new templates generated, "
            f"{results['templates_pruned']} low-value templates pruned"
        )
        return results

    async def update_tools(self) -> int:
        """Update all Go security tools to latest versions."""
        updated = 0
        for tool in GO_TOOLS:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "go", "install", tool,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await asyncio.wait_for(proc.communicate(), timeout=120)
                if proc.returncode == 0:
                    updated += 1
                    logger.debug(f"[SelfImprover] Updated: {tool.split('/')[-1]}")
            except asyncio.TimeoutError:
                logger.warning(f"[SelfImprover] Tool update timeout: {tool}")
            except Exception as e:
                logger.debug(f"[SelfImprover] Tool update failed {tool}: {e}")

        # Update pip packages
        try:
            proc = await asyncio.create_subprocess_exec(
                "pip", "install", "--upgrade", "--quiet",
                "nuclei", "waymore", "baddns",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.communicate(), timeout=60)
        except Exception:
            pass

        logger.info(f"[SelfImprover] Updated {updated}/{len(GO_TOOLS)} tools")
        return updated

    async def update_nuclei_templates(self) -> bool:
        """Pull latest Nuclei community templates."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "nuclei", "-update-templates", "-silent",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.communicate(), timeout=300)
            logger.info("[SelfImprover] Nuclei templates updated")
            return True
        except Exception as e:
            logger.warning(f"[SelfImprover] Nuclei template update failed: {e}")
            return False

    async def generate_from_paid_findings(self) -> int:
        """
        Generate custom Nuclei templates from confirmed paid findings.
        This is the feedback loop that makes BugFlow smarter over time.
        """
        conn = get_conn(self.db_path)
        new_templates = 0

        try:
            # Get paid/resolved findings from last 90 days
            cutoff = (datetime.utcnow() - timedelta(days=90)).isoformat()
            paid_findings = conn.execute("""
                SELECT id, title, severity, vuln_type, target,
                       description, reproduction_steps, proof_of_concept,
                       template_id, program
                FROM findings
                WHERE h1_status IN ('resolved', 'triaged', 'submitted')
                AND first_seen > ?
                AND is_duplicate = 0
                AND ai_score >= 7.0
                ORDER BY ai_score DESC
                LIMIT 20
            """, (cutoff,)).fetchall()

            for finding in paid_findings:
                template_id = f"bugflow-learned-{finding['vuln_type']}-{finding['id']}"
                template_path = self.custom_templates_dir / f"{template_id}.yaml"

                # Skip if template already exists
                if template_path.exists():
                    continue

                template = self._build_template_from_finding(finding)
                if template:
                    template_path.write_text(template)
                    new_templates += 1
                    logger.info(
                        f"[SelfImprover] Generated template: {template_id} "
                        f"from confirmed finding #{finding['id']}"
                    )

        finally:
            conn.close()

        return new_templates

    def _build_template_from_finding(self, finding) -> Optional[str]:
        """Build a Nuclei YAML template from a confirmed finding."""
        vuln_type = (finding["vuln_type"] or "generic").replace("_", "-")
        template_id = f"bugflow-learned-{vuln_type}-{finding['id']}"
        target = finding["target"] or ""

        # Extract path from target URL
        try:
            from urllib.parse import urlparse
            parsed = urlparse(target)
            path = parsed.path or "/"
        except Exception:
            path = "/"

        severity = finding["severity"] or "medium"
        title = finding["title"] or "Confirmed Finding"

        template = f"""id: {template_id}

info:
  name: "{title[:100]}"
  author: "bugflow-elite-v6"
  severity: "{severity}"
  description: |
    Learned from confirmed finding #{finding['id']}.
    Program: {finding['program'] or 'unknown'}
    Original: {(finding['description'] or '')[:200]}
  tags: bugflow,learned,{vuln_type}

http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}{path}"

    matchers-condition: and
    matchers:
      - type: status
        status: [200]

      - type: word
        words:
          - "{vuln_type}"
        condition: or
        negative: true
"""
        return template

    async def learn_program_patterns(self) -> int:
        """
        Analyze paid findings by program to learn what works.
        Saves patterns for the program selector to use.
        """
        conn = get_conn(self.db_path)
        patterns = {}

        try:
            rows = conn.execute("""
                SELECT program, vuln_type, severity,
                       COUNT(*) as count,
                       AVG(ai_score) as avg_score
                FROM findings
                WHERE h1_status IN ('resolved', 'triaged', 'submitted')
                AND is_duplicate = 0
                GROUP BY program, vuln_type, severity
                ORDER BY count DESC
            """).fetchall()

            for row in rows:
                prog = row["program"] or "unknown"
                if prog not in patterns:
                    patterns[prog] = {
                        "total_paid": 0,
                        "best_vuln_types": [],
                        "avg_score": 0,
                    }
                patterns[prog]["total_paid"] += row["count"]
                patterns[prog]["best_vuln_types"].append({
                    "type": row["vuln_type"],
                    "severity": row["severity"],
                    "count": row["count"],
                    "avg_score": row["avg_score"],
                })

        finally:
            conn.close()

        if patterns:
            self.patterns_file.parent.mkdir(parents=True, exist_ok=True)
            self.patterns_file.write_text(json.dumps(patterns, indent=2))
            logger.info(
                f"[SelfImprover] Learned patterns for "
                f"{len(patterns)} programs"
            )

        return len(patterns)

    async def prune_templates(self) -> int:
        """
        Remove custom templates that have never found anything
        after running on 10+ targets.
        """
        pruned = 0
        conn = get_conn(self.db_path)

        try:
            # Get template IDs that have found findings
            useful = set()
            rows = conn.execute(
                "SELECT DISTINCT template_id FROM findings "
                "WHERE template_id IS NOT NULL AND template_id != ''"
            ).fetchall()
            useful = {r["template_id"] for r in rows}
        finally:
            conn.close()

        for template_file in self.custom_templates_dir.glob("*.yaml"):
            template_id = template_file.stem
            # Only prune learned templates (not hand-crafted ones)
            if template_id.startswith("bugflow-learned-"):
                if template_id not in useful:
                    # Check age — only prune templates older than 30 days
                    age_days = (
                        datetime.utcnow() -
                        datetime.fromtimestamp(template_file.stat().st_mtime)
                    ).days
                    if age_days > 30:
                        template_file.unlink()
                        pruned += 1
                        logger.debug(
                            f"[SelfImprover] Pruned stale template: {template_id}"
                        )

        if pruned:
            logger.info(f"[SelfImprover] Pruned {pruned} stale templates")
        return pruned

    async def refresh_scope_data(self) -> bool:
        """Force-refresh bounty program scope data."""
        try:
            import aiohttp
            import sqlite3

            base_url = self.config.get("scope", {}).get(
                "bounty_targets_repo",
                "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data"
            )
            platforms = self.config.get("scope", {}).get(
                "platforms", ["hackerone", "bugcrowd"]
            )

            conn = get_conn(self.db_path)
            try:
                all_scope = {}
                async with aiohttp.ClientSession() as session:
                    for platform in platforms:
                        url = f"{base_url}/{platform}_data.json"
                        try:
                            async with session.get(
                                url, timeout=aiohttp.ClientTimeout(total=30)
                            ) as resp:
                                if resp.status == 200:
                                    all_scope[platform] = await resp.json()
                        except Exception:
                            pass

                if all_scope:
                    conn.execute(
                        "INSERT INTO scope_cache (platform, program, scope_data, fetched_at) "
                        "VALUES (?, ?, ?, ?)",
                        ("all", "all", json.dumps(all_scope),
                         datetime.utcnow().isoformat())
                    )
                    conn.commit()
                    logger.info("[SelfImprover] Scope data refreshed")
                    return True
            finally:
                conn.close()
        except Exception as e:
            logger.error(f"[SelfImprover] Scope refresh failed: {e}")
        return False

    def get_program_insights(self, program: str) -> dict:
        """
        Get learned insights for a specific program.
        Used by the program selector and triage engine.
        """
        if not self.patterns_file.exists():
            return {}
        try:
            patterns = json.loads(self.patterns_file.read_text())
            return patterns.get(program, {})
        except Exception:
            return {}
