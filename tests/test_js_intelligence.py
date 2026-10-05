from pathlib import Path

from core.attack_surface import AttackSurfaceGraph
from core.js_intelligence import (
    extract_endpoint_references,
    ingest_js_intelligence,
    normalize_endpoint,
)
from db.models import init_db


def test_normalize_endpoint():
    assert normalize_endpoint("/api/v1/users#fragment", "https://example.com/app.js") == "https://example.com/api/v1/users"
    assert normalize_endpoint("https://api.example.com/v1", "https://example.com/app.js") == "https://api.example.com/v1"
    assert normalize_endpoint("javascript:void(0)", "https://example.com/app.js") is None


def test_extract_endpoint_references_deduplicates_and_extracts_params():
    script = '''
        fetch("/api/v1/users?id=1");
        const a = "/api/v1/users?id=2";
        const b = "https://example.com/graphql";
    '''
    refs = extract_endpoint_references(script, "https://example.com/app.js")
    assert [r.url for r in refs] == [
        "https://example.com/api/v1/users?id=1",
        "https://example.com/api/v1/users?id=2",
        "https://example.com/graphql",
    ]
    assert refs[0].parameters == ("id",)


def test_ingest_js_intelligence_creates_graph_relationships(tmp_path: Path):
    db = tmp_path / "js.db"
    conn = init_db(str(db))
    conn.close()
    graph = AttackSurfaceGraph(str(db))
    refs = ingest_js_intelligence(
        graph,
        asset_url="https://example.com/",
        js_url="https://example.com/app.js",
        script='fetch("/api/v1/users?id=1")',
    )
    assert len(refs) == 1
    conn = __import__("db.models", fromlist=["get_conn"]).get_conn(str(db))
    nodes = conn.execute("SELECT node_type, canonical_key FROM attack_surface_nodes ORDER BY id").fetchall()
    edges = conn.execute("SELECT edge_type FROM attack_surface_edges ORDER BY id").fetchall()
    conn.close()
    assert ("javascript", "https://example.com/app.js") in [(r["node_type"], r["canonical_key"]) for r in nodes]
    assert any(r["edge_type"] == "contains_endpoint" for r in edges)
