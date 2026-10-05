"""
BugFlow Elite v6 — Scope Enforcer
CRITICAL SAFETY MODULE: Validates every target before any tool runs.
Nothing executes against out-of-scope hosts. Ever.
Tinlance Limited | LloydCoder
"""

import re
import json
import logging
import ipaddress
import requests
import yaml
from pathlib import Path
from fnmatch import fnmatch
from datetime import datetime, timedelta
from typing import Optional
from db.models import get_conn

logger = logging.getLogger(__name__)


class ScopeEnforcer:
    """
    The gatekeeper. Every target passes through here before any scan tool
    runs against it. If it's not in scope, it doesn't get touched.
    """

    def __init__(self, config: dict):
        self.config = config
        self.db_path = config.get("general", {}).get("db_path", "./db/bugflow.db")
        self._in_scope: list[dict] = []
        self._out_scope: list[dict] = []
        self._loaded = False

    def load(self):
        """Load scope from manual file and auto-fetched platform data."""
        self._in_scope = []
        self._out_scope = []

        # Manual scope file
        manual_path = self.config.get("scope", {}).get(
            "manual_scope_file", "./config/scope/manual_scope.yaml"
        )
        self._load_manual_scope(manual_path)

        # Auto-fetched scope from bounty-targets-data
        if self.config.get("scope", {}).get("auto_fetch"):
            self._load_auto_scope()

        self._loaded = True
        in_count = len(self._in_scope)
        out_count = len(self._out_scope)
        logger.info(f"Scope loaded: {in_count} in-scope rules, {out_count} out-of-scope rules")

    def _load_manual_scope(self, path: str):
        """Load scope from the manual YAML file."""
        p = Path(path)
        if not p.exists():
            logger.warning(f"Manual scope file not found: {path}")
            return

        with open(p) as f:
            data = yaml.safe_load(f)

        programs = data.get("programs", [])
        for prog in programs:
            if not prog.get("active"):
                continue
            program_name = prog.get("name", "unknown")
            in_scope = prog.get("in_scope", {})
            out_scope = prog.get("out_of_scope", {})

            for domain in in_scope.get("domains", []):
                self._in_scope.append({
                    "type": "domain",
                    "value": domain,
                    "program": program_name
                })
            for ip_range in in_scope.get("ip_ranges", []):
                self._in_scope.append({
                    "type": "ip_range",
                    "value": ip_range,
                    "program": program_name
                })
            for url in in_scope.get("urls", []):
                self._in_scope.append({
                    "type": "url",
                    "value": url,
                    "program": program_name
                })
            for domain in out_scope.get("domains", []):
                self._out_scope.append({
                    "type": "domain",
                    "value": domain,
                    "program": program_name
                })
            for path_rule in out_scope.get("paths", []):
                self._out_scope.append({
                    "type": "path",
                    "value": path_rule,
                    "program": program_name
                })

    def _load_auto_scope(self):
        """
        Fetch scope from bounty-targets-data repo (hourly-updated dumps).
        Only fetches if cache is stale (> fetch_interval_hours old).
        """
        try:
            conn = get_conn(self.db_path)
            interval = self.config.get("scope", {}).get("fetch_interval_hours", 6)
            stale_after = datetime.utcnow() - timedelta(hours=interval)

            cached = conn.execute(
                "SELECT scope_data, fetched_at FROM scope_cache ORDER BY fetched_at DESC LIMIT 1"
            ).fetchone()

            if cached:
                fetched_at = datetime.fromisoformat(cached["fetched_at"])
                if fetched_at > stale_after:
                    scope_data = json.loads(cached["scope_data"])
                    self._apply_auto_scope(scope_data)
                    logger.info("Using cached scope data (still fresh)")
                    return

            # Fetch fresh scope
            base_url = self.config.get("scope", {}).get(
                "bounty_targets_repo",
                "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data"
            )
            platforms = self.config.get("scope", {}).get(
                "platforms", ["hackerone", "bugcrowd"]
            )

            all_scope = {}
            for platform in platforms:
                url = f"{base_url}/{platform}_data.json"
                try:
                    resp = requests.get(url, timeout=15)
                    if resp.status_code == 200:
                        all_scope[platform] = resp.json()
                        logger.info(f"Fetched scope from {platform}")
                except Exception as e:
                    logger.warning(f"Could not fetch {platform} scope: {e}")

            if all_scope:
                conn.execute(
                    "INSERT INTO scope_cache (platform, program, scope_data, fetched_at) VALUES (?, ?, ?, ?)",
                    ("all", "all", json.dumps(all_scope), datetime.utcnow().isoformat())
                )
                conn.commit()
                self._apply_auto_scope(all_scope)

        except Exception as e:
            logger.error(f"Auto-scope fetch failed: {e}")

    def _apply_auto_scope(self, scope_data: dict):
        """Parse bounty-targets-data format and apply to scope rules."""
        for platform, programs in scope_data.items():
            if not isinstance(programs, list):
                continue
            for prog in programs:
                prog_name = prog.get("name", "unknown")
                targets = prog.get("targets", {})
                in_scope_list = targets.get("in_scope", [])

                for target in in_scope_list:
                    asset_type = target.get("asset_type", "")
                    identifier = target.get("asset_identifier", "")
                    if not identifier:
                        continue
                    if asset_type in ("URL", "WILDCARD", "DOMAIN"):
                        self._in_scope.append({
                            "type": "domain",
                            "value": identifier,
                            "program": prog_name,
                            "platform": platform
                        })

    def is_in_scope(self, target: str, path: str = "") -> tuple[bool, str]:
        """
        Check if a target (domain/IP/URL) is in scope.
        Returns (bool, reason_string).
        ALWAYS call this before running any tool.
        """
        if not self._loaded:
            self.load()

        # Normalize target
        target = target.strip().lower()
        target = re.sub(r'^https?://', '', target)
        target = target.split("/")[0].split(":")[0]  # strip port + path

        # Check out-of-scope first (takes precedence)
        for rule in self._out_scope:
            if rule["type"] == "domain":
                if self._domain_matches(target, rule["value"]):
                    return False, f"Out of scope: matches {rule['value']} ({rule['program']})"
            elif rule["type"] == "path" and path:
                if path.startswith(rule["value"]):
                    return False, f"Out of scope path: {rule['value']}"

        # Check in-scope
        for rule in self._in_scope:
            if rule["type"] == "domain":
                if self._domain_matches(target, rule["value"]):
                    return True, f"In scope: {rule['program']}"
            elif rule["type"] == "ip_range":
                if self._ip_in_range(target, rule["value"]):
                    return True, f"In scope IP range: {rule['program']}"
            elif rule["type"] == "url":
                if target in rule["value"]:
                    return True, f"In scope URL: {rule['program']}"

        return False, "Not found in any active scope"

    def _domain_matches(self, target: str, pattern: str) -> bool:
        """Match target against scope pattern (supports wildcards like *.example.com)."""
        pattern = pattern.strip().lower()
        pattern = re.sub(r'^https?://', '', pattern)
        pattern = pattern.split("/")[0]

        if pattern.startswith("*."):
            base = pattern[2:]
            return target == base or target.endswith("." + base)
        return target == pattern or fnmatch(target, pattern)

    def _ip_in_range(self, target: str, cidr: str) -> bool:
        """Check if target IP falls within a CIDR range."""
        try:
            return ipaddress.ip_address(target) in ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False

    def assert_action_allowed(
        self,
        target: str,
        action_class: str,
        path: str = "",
    ) -> None:
        """Authorize a bounded action only after scope resolution.

        Phase 0 does not grant execution authority to tools. It provides the
        domain-level authorization contract consumed by later execution policy.
        Unknown action classes fail closed.
        """
        allowed = {
            "PASSIVE_RECON",
            "ACTIVE_RECON",
            "WEB_REQUEST",
            "PORT_SCAN",
            "FUZZING",
            "PARAM_DISCOVERY",
            "CLOUD_ENUM",
            "REPOSITORY_ANALYSIS",
        }
        if action_class not in allowed:
            raise ScopeViolationError(
                f"ACTION DENIED: unknown action class {action_class!r}"
            )
        self.assert_in_scope(target, path)

        policy = self.config.get("scope", {}).get("allowed_actions")
        if policy is not None:
            configured = {str(item).upper() for item in policy}
            if action_class not in configured:
                raise ScopeViolationError(
                    f"ACTION DENIED: {action_class} is not enabled by scope policy"
                )

    def assert_in_scope(self, target: str, path: str = ""):
        """
        Raise an exception if target is NOT in scope.
        Use this as a hard gate before running any tool.
        """
        in_scope, reason = self.is_in_scope(target, path)
        if not in_scope:
            raise ScopeViolationError(f"SCOPE VIOLATION blocked: {target} — {reason}")
        logger.debug(f"Scope OK: {target} — {reason}")

    def filter_in_scope(self, targets: list[str]) -> list[str]:
        """Filter a list of targets, returning only in-scope ones."""
        result = []
        for t in targets:
            in_scope, reason = self.is_in_scope(t)
            if in_scope:
                result.append(t)
            else:
                logger.debug(f"Filtered out-of-scope: {t} — {reason}")
        logger.info(f"Scope filter: {len(result)}/{len(targets)} targets in scope")
        return result

    def get_active_programs(self) -> list[str]:
        """Return list of active program names."""
        programs = set()
        for rule in self._in_scope:
            programs.add(rule.get("program", "unknown"))
        return list(programs)


class ScopeViolationError(Exception):
    """Raised when a tool attempts to run against an out-of-scope target."""
    pass
