"""Persistent attack-surface graph primitives.

The graph is an intelligence index, not an authorization layer. Nodes represent
normalized attack-surface entities; edges represent observed relationships.
Every mutation is idempotent and records provenance/source metadata.
"""

from __future__ import annotations

import json
import re
from typing import Any, Mapping

from core.contracts import stable_hash
from db.models import get_conn


_HOST_RE = re.compile(r"^[a-z0-9.-]+$", re.IGNORECASE)


def canonical_key(node_type: str, value: str) -> str:
    if not node_type.strip() or not value.strip():
        raise ValueError("node_type and value are required")
    normalized = value.strip().lower().rstrip(".")
    if node_type.lower() in {"domain", "subdomain", "hostname"}:
        if not _HOST_RE.fullmatch(normalized):
            raise ValueError("invalid hostname-like graph key")
    return normalized


class AttackSurfaceGraph:
    def __init__(self, db_path: str, tenant_id: str = "default"):
        if not tenant_id.strip():
            raise ValueError("tenant_id must not be empty")
        self.db_path = db_path
        self.tenant_id = tenant_id

    def upsert_node(
        self,
        node_type: str,
        value: str,
        *,
        attributes: Mapping[str, Any] | None = None,
        source: str = "unknown",
        run_id: str | None = None,
    ) -> tuple[int, bool]:
        key = canonical_key(node_type, value)
        attrs = dict(attributes or {})
        fingerprint = stable_hash({"node_type": node_type, "key": key, "attributes": attrs})
        conn = get_conn(self.db_path)
        try:
            existing = conn.execute(
                "SELECT id, fingerprint FROM attack_surface_nodes "
                "WHERE tenant_id = ? AND node_type = ? AND canonical_key = ?",
                (self.tenant_id, node_type, key),
            ).fetchone()
            if existing is None:
                cur = conn.execute(
                    "INSERT INTO attack_surface_nodes "
                    "(tenant_id, node_type, canonical_key, attributes, fingerprint) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        self.tenant_id,
                        node_type,
                        key,
                        json.dumps(attrs, sort_keys=True, separators=(",", ":")),
                        fingerprint,
                    ),
                )
                node_id = int(cur.lastrowid)
                self._record_change(
                    conn,
                    node_id=node_id,
                    change_type="created",
                    old_fingerprint=None,
                    new_fingerprint=fingerprint,
                    run_id=run_id,
                    reason=source,
                )
                conn.commit()
                return node_id, True

            node_id = int(existing["id"])
            changed = existing["fingerprint"] != fingerprint
            conn.execute(
                "UPDATE attack_surface_nodes SET attributes = ?, fingerprint = ?, "
                "last_seen = CURRENT_TIMESTAMP, is_active = 1 WHERE id = ?",
                (
                    json.dumps(attrs, sort_keys=True, separators=(",", ":")),
                    fingerprint,
                    node_id,
                ),
            )
            if changed:
                self._record_change(
                    conn,
                    node_id=node_id,
                    change_type="changed",
                    old_fingerprint=existing["fingerprint"],
                    new_fingerprint=fingerprint,
                    run_id=run_id,
                    reason=source,
                )
            conn.commit()
            return node_id, changed
        finally:
            conn.close()

    def upsert_edge(
        self,
        source_node_id: int,
        target_node_id: int,
        edge_type: str,
        *,
        source: str,
        evidence_id: str | None = None,
    ) -> int:
        if source_node_id <= 0 or target_node_id <= 0:
            raise ValueError("node IDs must be positive")
        if not edge_type.strip() or not source.strip():
            raise ValueError("edge_type and source are required")
        conn = get_conn(self.db_path)
        try:
            conn.execute(
                "INSERT INTO attack_surface_edges "
                "(tenant_id, source_node_id, target_node_id, edge_type, source, evidence_id) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(tenant_id, source_node_id, target_node_id, edge_type, source) "
                "DO UPDATE SET evidence_id = COALESCE(excluded.evidence_id, evidence_id), "
                "last_seen = CURRENT_TIMESTAMP, is_active = 1",
                (
                    self.tenant_id,
                    source_node_id,
                    target_node_id,
                    edge_type,
                    source,
                    evidence_id,
                ),
            )
            row = conn.execute(
                "SELECT id FROM attack_surface_edges WHERE tenant_id = ? "
                "AND source_node_id = ? AND target_node_id = ? AND edge_type = ? AND source = ?",
                (self.tenant_id, source_node_id, target_node_id, edge_type, source),
            ).fetchone()
            conn.commit()
            return int(row["id"])
        finally:
            conn.close()

    def record_missing(self, node_type: str, value: str, *, run_id: str | None = None) -> bool:
        key = canonical_key(node_type, value)
        conn = get_conn(self.db_path)
        try:
            row = conn.execute(
                "SELECT id, is_active FROM attack_surface_nodes "
                "WHERE tenant_id = ? AND node_type = ? AND canonical_key = ?",
                (self.tenant_id, node_type, key),
            ).fetchone()
            if row is None or not row["is_active"]:
                return False
            conn.execute(
                "UPDATE attack_surface_nodes SET is_active = 0, last_seen = CURRENT_TIMESTAMP "
                "WHERE id = ?",
                (row["id"],),
            )
            self._record_change(
                conn,
                node_id=int(row["id"]),
                change_type="disappeared",
                old_fingerprint=None,
                new_fingerprint=None,
                run_id=run_id,
                reason="not observed in current baseline",
            )
            conn.commit()
            return True
        finally:
            conn.close()

    @staticmethod
    def _record_change(
        conn,
        *,
        node_id: int,
        change_type: str,
        old_fingerprint: str | None,
        new_fingerprint: str | None,
        run_id: str | None,
        reason: str,
    ) -> None:
        conn.execute(
            "INSERT INTO attack_surface_changes "
            "(tenant_id, node_id, change_type, old_fingerprint, new_fingerprint, run_id, reason) "
            "SELECT tenant_id, ?, ?, ?, ?, ?, ? FROM attack_surface_nodes WHERE id = ?",
            (node_id, change_type, old_fingerprint, new_fingerprint, run_id, reason, node_id),
        )
