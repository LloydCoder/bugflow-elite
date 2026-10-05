"""
BugFlow Elite v6 — Scope Change Monitor
Checks daily for new domains added to programs you already scan.
New scope = fresh attack surface = first-mover advantage.
Sends Telegram alert immediately when scope expands.
Tinlance Limited | LloydCoder
"""

import json
import logging
import hashlib
from datetime import datetime
from pathlib import Path
from db.models import get_conn

logger = logging.getLogger(__name__)


class ScopeMonitor:
    """
    Compares current scope against previously seen scope.
    When a program adds new domains, triggers an immediate scan
    and sends a Telegram alert before other hunters notice.
    """

    def __init__(self, config: dict):
        self.config = config
        self.db_path = config.get("general", {}).get("db_path", "./db/bugflow.db")
        self.state_file = Path("./output/.scope_state.json")
        self.state_file.parent.mkdir(parents=True, exist_ok=True)

    async def check_for_changes(self) -> list[dict]:
        """
        Compare latest scope data against saved state.
        Returns list of change events (new domains, new programs, removed domains).
        """
        current_scope = self._load_current_scope()
        if not current_scope:
            logger.debug("[ScopeMonitor] No scope data to compare")
            return []

        previous_scope = self._load_previous_state()

        if not previous_scope:
            # First run — just save state, no changes to report
            self._save_state(current_scope)
            logger.info("[ScopeMonitor] Initial scope state saved")
            return []

        changes = self._diff_scope(previous_scope, current_scope)

        if changes:
            self._save_state(current_scope)
            logger.info(
                f"[ScopeMonitor] {len(changes)} scope changes detected"
            )
        return changes

    def _load_current_scope(self) -> dict:
        """Load current scope from DB scope_cache."""
        conn = get_conn(self.db_path)
        try:
            row = conn.execute(
                "SELECT scope_data FROM scope_cache "
                "WHERE platform='all' ORDER BY fetched_at DESC LIMIT 1"
            ).fetchone()
            if not row:
                return {}
            return json.loads(row["scope_data"])
        except Exception as e:
            logger.debug(f"[ScopeMonitor] Load error: {e}")
            return {}
        finally:
            conn.close()

    def _load_previous_state(self) -> dict:
        """Load previously saved scope state."""
        if not self.state_file.exists():
            return {}
        try:
            return json.loads(self.state_file.read_text())
        except Exception:
            return {}

    def _save_state(self, scope: dict):
        """Save current scope as new baseline."""
        try:
            self.state_file.write_text(json.dumps(scope))
        except Exception as e:
            logger.error(f"[ScopeMonitor] Save error: {e}")

    def _diff_scope(self, previous: dict, current: dict) -> list[dict]:
        """Find differences between two scope snapshots."""
        changes = []

        for platform, programs in current.items():
            if not isinstance(programs, list):
                continue

            prev_programs = {
                p.get("handle", p.get("name", "")): p
                for p in previous.get(platform, [])
                if isinstance(p, dict)
            }

            for prog in programs:
                if not isinstance(prog, dict):
                    continue

                prog_name = prog.get("handle") or prog.get("name", "")
                targets = prog.get("targets", {})
                current_in_scope = set(
                    t.get("asset_identifier", "")
                    for t in targets.get("in_scope", [])
                    if t.get("asset_identifier")
                )

                if prog_name not in prev_programs:
                    # Entirely new program
                    if current_in_scope:
                        changes.append({
                            "type": "new_program",
                            "platform": platform,
                            "program": prog_name,
                            "new_domains": list(current_in_scope),
                            "severity": "high",
                            "detected_at": datetime.utcnow().isoformat(),
                        })
                        logger.info(
                            f"[ScopeMonitor] New program: {prog_name} "
                            f"on {platform}"
                        )
                else:
                    # Existing program — check for new domains
                    prev_targets = prev_programs[prog_name].get("targets", {})
                    prev_in_scope = set(
                        t.get("asset_identifier", "")
                        for t in prev_targets.get("in_scope", [])
                        if t.get("asset_identifier")
                    )

                    added = current_in_scope - prev_in_scope
                    removed = prev_in_scope - current_in_scope

                    if added:
                        changes.append({
                            "type": "scope_expanded",
                            "platform": platform,
                            "program": prog_name,
                            "new_domains": list(added),
                            "removed_domains": list(removed),
                            "severity": "medium",
                            "detected_at": datetime.utcnow().isoformat(),
                        })
                        logger.info(
                            f"[ScopeMonitor] Scope expanded: {prog_name} "
                            f"added {len(added)} domains"
                        )

        return changes

    def get_scope_hash(self, program: str) -> str:
        """Get a hash of current scope for a program (for change detection)."""
        scope = self._load_current_scope()
        for platform, programs in scope.items():
            if not isinstance(programs, list):
                continue
            for prog in programs:
                name = prog.get("handle") or prog.get("name", "")
                if name == program:
                    targets = json.dumps(
                        prog.get("targets", {}), sort_keys=True
                    )
                    return hashlib.sha256(targets.encode()).hexdigest()[:16]
        return ""
