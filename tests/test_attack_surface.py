from pathlib import Path

import pytest

from core.attack_surface import AttackSurfaceGraph, canonical_key
from db.models import init_db


def graph(tmp_path: Path) -> AttackSurfaceGraph:
    db = tmp_path / "graph.db"
    conn = init_db(str(db))
    conn.close()
    return AttackSurfaceGraph(str(db))


def test_canonical_key_normalizes_hostname():
    assert canonical_key("subdomain", "API.Example.COM.") == "api.example.com"
    with pytest.raises(ValueError):
        canonical_key("subdomain", "not a valid hostname")


def test_upsert_node_is_idempotent_and_records_change(tmp_path):
    g = graph(tmp_path)
    node_id, created = g.upsert_node(
        "subdomain",
        "API.Example.COM.",
        attributes={"status": 200},
        source="bbot",
        run_id="run-1",
    )
    assert created is True
    same_id, changed = g.upsert_node(
        "subdomain",
        "api.example.com",
        attributes={"status": 200},
        source="bbot",
        run_id="run-2",
    )
    assert same_id == node_id
    assert changed is False

    _, changed = g.upsert_node(
        "subdomain",
        "api.example.com",
        attributes={"status": 403},
        source="bbot",
        run_id="run-3",
    )
    assert changed is True


def test_edges_are_idempotent_and_provenance_bearing(tmp_path):
    g = graph(tmp_path)
    a, _ = g.upsert_node("domain", "example.com", source="crtsh")
    b, _ = g.upsert_node("subdomain", "api.example.com", source="bbot")
    edge = g.upsert_edge(a, b, "resolves_to", source="dns", evidence_id="ev-1")
    assert edge > 0
    assert g.upsert_edge(a, b, "resolves_to", source="dns", evidence_id="ev-2") == edge


def test_missing_node_is_deactivated(tmp_path):
    g = graph(tmp_path)
    node_id, _ = g.upsert_node("subdomain", "api.example.com", source="bbot")
    assert g.record_missing("subdomain", "api.example.com", run_id="run-4") is True
    assert g.record_missing("subdomain", "api.example.com", run_id="run-5") is False
    conn = __import__("db.models", fromlist=["get_conn"]).get_conn(g.db_path)
    row = conn.execute("SELECT is_active FROM attack_surface_nodes WHERE id = ?", (node_id,)).fetchone()
    conn.close()
    assert row["is_active"] == 0


def test_invalid_edge_is_rejected(tmp_path):
    g = graph(tmp_path)
    with pytest.raises(ValueError):
        g.upsert_edge(0, 1, "x", source="test")
    with pytest.raises(ValueError):
        g.upsert_edge(1, 2, "", source="test")
