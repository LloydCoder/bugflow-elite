"""
BugFlow Elite v6 — Smart Program Selector
Automatically ranks and selects the best bug bounty programs to target.
Scoring factors:
- Program age (newer = less competition)
- Scope breadth (more assets = more findings)
- Payout speed (response time from H1 data)
- Asset types (wildcards score higher)
- Your past success rate per program
- Bounty table (minimum/maximum payouts)
- Recent activity (last updated scope)
Tinlance Limited | LloydCoder
"""

import json
import logging
import aiohttp
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from db.models import get_conn

logger = logging.getLogger(__name__)


class ProgramSelector:
    """
    Analyzes all programs in bounty-targets-data and ranks them
    by estimated value for YOUR specific setup and skill set.
    """

    def __init__(self, config: dict):
        self.config = config
        self.db_path = config.get("general", {}).get("db_path", "./db/bugflow.db")
        self.patterns_file = Path("./output/program_patterns.json")

    async def get_top_programs(self, limit: int = 10) -> list[dict]:
        """
        Return the top N programs ranked by estimated ROI.
        """
        programs = await self._load_all_programs()
        if not programs:
            logger.warning("[ProgramSelector] No programs found in scope cache")
            return []

        scored = []
        for prog in programs:
            score = self._score_program(prog)
            if score > 0:
                scored.append({**prog, "selector_score": score})

        scored.sort(key=lambda x: x["selector_score"], reverse=True)
        top = scored[:limit]

        logger.info(
            f"[ProgramSelector] Top {len(top)} programs from "
            f"{len(programs)} available"
        )
        for p in top[:3]:
            logger.info(
                f"  {p.get('name', '?')}: score={p['selector_score']:.2f}"
            )
        return top

    async def _load_all_programs(self) -> list[dict]:
        """Load programs from scope cache DB."""
        conn = get_conn(self.db_path)
        try:
            row = conn.execute(
                "SELECT scope_data FROM scope_cache "
                "WHERE platform='all' ORDER BY fetched_at DESC LIMIT 1"
            ).fetchone()
            if not row:
                return []
            scope_data = json.loads(row["scope_data"])
            programs = []
            for platform, prog_list in scope_data.items():
                if isinstance(prog_list, list):
                    for p in prog_list:
                        p["platform"] = platform
                        programs.append(p)
            return programs
        except Exception as e:
            logger.error(f"[ProgramSelector] Load error: {e}")
            return []
        finally:
            conn.close()

    def _score_program(self, prog: dict) -> float:
        """Score a program 0-100 based on estimated ROI."""
        score = 0.0
        targets = prog.get("targets", {})
        in_scope = targets.get("in_scope", [])

        if not in_scope:
            return 0.0

        # ── Scope breadth ──────────────────────────────────────
        wildcard_count = sum(
            1 for t in in_scope
            if "*" in t.get("asset_identifier", "")
        )
        url_count = sum(
            1 for t in in_scope
            if t.get("asset_type") in ("URL", "WILDCARD", "DOMAIN")
        )
        score += min(wildcard_count * 8, 30)   # Max 30 for wildcards
        score += min(url_count * 2, 15)         # Max 15 for URLs

        # ── Bounty table ───────────────────────────────────────
        offers_bounty = prog.get("offers_bounty", False)
        if offers_bounty:
            score += 20

        min_bounty = prog.get("min_bounty", 0) or 0
        max_bounty = prog.get("max_bounty", 0) or 0
        if max_bounty >= 10000:
            score += 15
        elif max_bounty >= 5000:
            score += 10
        elif max_bounty >= 1000:
            score += 5

        # ── Response efficiency ────────────────────────────────
        # HackerOne provides response_efficiency_percentage
        efficiency = prog.get("response_efficiency_percentage") or 0
        score += min(efficiency * 0.1, 10)  # Max 10

        # ── Your past success rate ─────────────────────────────
        if self.patterns_file.exists():
            try:
                patterns = json.loads(self.patterns_file.read_text())
                prog_name = prog.get("handle") or prog.get("name", "")
                past = patterns.get(prog_name, {})
                past_paid = past.get("total_paid", 0)
                score += min(past_paid * 5, 20)  # Max 20 for past success
            except Exception:
                pass

        # ── Penalize very large programs (high competition) ────
        if url_count > 100:
            score *= 0.7  # Large scope = crowded

        # ── Penalize programs with very restricted scope ───────
        out_scope_count = len(targets.get("out_of_scope", []))
        if out_scope_count > 20:
            score *= 0.85

        return round(score, 2)

    async def recommend_daily_target(self) -> Optional[dict]:
        """
        Pick the single best program to run a full scan on today.
        Avoids repeating the same program too frequently.
        """
        top = await self.get_top_programs(limit=20)
        if not top:
            return None

        conn = get_conn(self.db_path)
        try:
            # Don't scan same program within last 24h
            recent_scans = conn.execute("""
                SELECT DISTINCT program FROM scan_runs
                WHERE started_at > ?
                AND scan_type = 'full'
            """, ((datetime.utcnow() - timedelta(hours=24)).isoformat(),)
            ).fetchall()
            recent = {r["program"] for r in recent_scans}

            for prog in top:
                name = prog.get("handle") or prog.get("name", "")
                if name not in recent:
                    logger.info(
                        f"[ProgramSelector] Recommended: {name} "
                        f"(score: {prog['selector_score']:.2f})"
                    )
                    return prog

        finally:
            conn.close()

        return top[0] if top else None
