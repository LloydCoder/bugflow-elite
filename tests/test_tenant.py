from pathlib import Path

import pytest

from core.tenant import AuditLogger, TenantContext, tenant_db_path, validate_tenant_id
from db.models import init_db


def test_tenant_ids_are_strictly_validated():
    assert validate_tenant_id("acme-prod_1") == "acme-prod_1"
    with pytest.raises(ValueError):
        validate_tenant_id("../escape")
    with pytest.raises(ValueError):
        validate_tenant_id("")


def test_tenant_db_paths_are_namespaced(tmp_path: Path):
    one = tenant_db_path(tmp_path, "tenant-a")
    two = tenant_db_path(tmp_path, "tenant-b")
    assert one != two
    assert one.parent == two.parent
    with pytest.raises(ValueError):
        tenant_db_path(tmp_path, "../escape")


def test_audit_chain_is_tamper_evident(tmp_path: Path):
    db = tmp_path / "audit.db"
    conn = init_db(str(db))
    conn.close()
    audit = AuditLogger(str(db), TenantContext("tenant-a", "tester"))
    audit.append(
        action="scope.check",
        resource_type="target",
        resource_id="example.com",
        decision="allow",
    )
    audit.append(
        action="tool.execute",
        resource_type="tool",
        resource_id="bbot",
        decision="allow",
        metadata={"run_id": "run-1"},
    )
    assert audit.verify_chain() is True

    conn = __import__("db.models", fromlist=["get_conn"]).get_conn(str(db))
    conn.execute(
        "UPDATE governance_audit SET decision = 'deny' WHERE resource_id = 'example.com'"
    )
    conn.commit()
    conn.close()
    assert audit.verify_chain() is False


def test_context_requires_actor():
    with pytest.raises(ValueError):
        TenantContext("tenant-a", "")
