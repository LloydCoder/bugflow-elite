"""Tenant isolation and tamper-evident governance audit primitives."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from uuid import uuid4

from core.contracts import stable_hash
from db.models import get_conn


TENANT_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$")


def validate_tenant_id(tenant_id: str) -> str:
    if not isinstance(tenant_id, str) or not TENANT_RE.fullmatch(tenant_id):
        raise ValueError("tenant_id contains invalid characters or length")
    return tenant_id


@dataclass(frozen=True)
class TenantContext:
    tenant_id: str
    actor: str

    def __post_init__(self) -> None:
        validate_tenant_id(self.tenant_id)
        if not self.actor.strip():
            raise ValueError("actor must not be empty")


def tenant_db_path(root: str | Path, tenant_id: str) -> Path:
    tenant = validate_tenant_id(tenant_id)
    base = Path(root).expanduser().resolve()
    base.mkdir(parents=True, exist_ok=True)
    path = (base / f"{tenant}.db").resolve()
    if base not in path.parents:
        raise ValueError("tenant database escaped the tenant root")
    return path


class AuditLogger:
    """Append-only hash-chained audit events scoped to one tenant."""

    def __init__(self, db_path: str, context: TenantContext):
        self.db_path = db_path
        self.context = context

    def append(
        self,
        *,
        action: str,
        resource_type: str,
        resource_id: str | None = None,
        decision: str | None = None,
        metadata: dict | None = None,
    ) -> str:
        if not action.strip() or not resource_type.strip():
            raise ValueError("action and resource_type are required")
        conn = get_conn(self.db_path)
        try:
            previous = conn.execute(
                "SELECT event_hash FROM governance_audit "
                "WHERE tenant_id = ? ORDER BY id DESC LIMIT 1",
                (self.context.tenant_id,),
            ).fetchone()
            previous_hash = previous["event_hash"] if previous else None
            event_id = str(uuid4())
            payload = {
                "tenant_id": self.context.tenant_id,
                "event_id": event_id,
                "actor": self.context.actor,
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "decision": decision,
                "metadata": metadata or {},
                "previous_hash": previous_hash,
            }
            event_hash = stable_hash(payload)
            conn.execute(
                "INSERT INTO governance_audit "
                "(tenant_id, event_id, actor, action, resource_type, resource_id, decision, metadata, previous_hash, event_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    self.context.tenant_id,
                    event_id,
                    self.context.actor,
                    action,
                    resource_type,
                    resource_id,
                    decision,
                    json.dumps(metadata or {}, sort_keys=True, separators=(",", ":")),
                    previous_hash,
                    event_hash,
                ),
            )
            conn.commit()
            return event_id
        finally:
            conn.close()

    def verify_chain(self) -> bool:
        conn = get_conn(self.db_path)
        try:
            rows = conn.execute(
                "SELECT tenant_id, event_id, actor, action, resource_type, resource_id, "
                "decision, metadata, previous_hash, event_hash "
                "FROM governance_audit WHERE tenant_id = ? ORDER BY id ASC",
                (self.context.tenant_id,),
            ).fetchall()
            previous_hash = None
            for row in rows:
                if row["previous_hash"] != previous_hash:
                    return False
                metadata = json.loads(row["metadata"])
                payload = {
                    "tenant_id": row["tenant_id"],
                    "event_id": row["event_id"],
                    "actor": row["actor"],
                    "action": row["action"],
                    "resource_type": row["resource_type"],
                    "resource_id": row["resource_id"],
                    "decision": row["decision"],
                    "metadata": metadata,
                    "previous_hash": row["previous_hash"],
                }
                if stable_hash(payload) != row["event_hash"]:
                    return False
                previous_hash = row["event_hash"]
            return True
        finally:
            conn.close()
