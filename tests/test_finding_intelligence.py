from pathlib import Path

import pytest

from core.finding_intelligence import (
    FindingHistory,
    FindingSignature,
    compare_findings,
)
from db.models import init_db


def sig(**overrides):
    values = {
        "target": "https://example.com",
        "vuln_type": "idor",
        "root_cause": "missing_object_authorization",
        "endpoint": "/api/users/1",
        "parameters": ("id",),
        "impact": "data_disclosure",
        "remediation": "enforce_object_level_authorization",
    }
    values.update(overrides)
    return FindingSignature(**values)


def test_fingerprint_and_novelty_are_deterministic():
    assert sig().fingerprint() == sig().fingerprint()
    assert sig().novelty_key() == sig().novelty_key()
    assert sig(endpoint="/api/users/2").fingerprint() != sig().fingerprint()


def test_duplicate_decision_combines_multiple_signals():
    decision = compare_findings(sig(), sig(), semantic_similarity=0.99)
    assert decision.status == "SUPPRESS_FROM_DRAFT"
    assert decision.score >= 0.92
    assert "root_cause" in decision.reasons


def test_distinct_findings_are_not_suppressed():
    decision = compare_findings(
        sig(target="https://other.example.com", vuln_type="xss"),
        sig(),
        semantic_similarity=0.2,
    )
    assert decision.status == "DISTINCT"


def test_semantic_similarity_is_advisory_and_bounded():
    with pytest.raises(ValueError):
        compare_findings(sig(), sig(), semantic_similarity=1.2)


def test_finding_history_is_idempotent(tmp_path: Path):
    db = tmp_path / "history.db"
    conn = init_db(str(db))
    conn.close()
    history = FindingHistory(str(db))
    first = history.observe(sig(), status="candidate")
    second = history.observe(sig(), status="verified")
    assert first["is_new"] is True
    assert second["is_new"] is False
    assert second["observation_count"] == 2
