from core.contracts import (
    ActionClass,
    EvidenceQuality,
    FindingCandidate,
    Observation,
    ResearchContext,
)
from core.evidence import build_evidence


def test_observation_fingerprint_is_stable():
    context = ResearchContext(program="test", target="example.com", scan_type="unit")
    first = Observation(
        kind="dns_record",
        target="example.com",
        source="fixture",
        observed_at="2026-10-05T00:00:00+00:00",
        data={"type": "A", "value": "192.0.2.10"},
        context=context,
        action_class=ActionClass.PASSIVE_RECON,
    )
    second = Observation(
        kind="dns_record",
        target="example.com",
        source="fixture",
        observed_at="2026-10-05T00:00:00+00:00",
        data={"value": "192.0.2.10", "type": "A"},
        context=context,
        action_class=ActionClass.PASSIVE_RECON,
    )
    assert first.fingerprint() == second.fingerprint()


def test_evidence_hash_is_deterministic():
    observations = [{
        "observation_id": "obs-1",
        "kind": "http_response",
        "status": 200,
    }]
    a = build_evidence(
        evidence_type="http_response",
        observations=observations,
        provenance={"tool": "fixture", "version": "1"},
        quality=EvidenceQuality.REPRODUCIBLE,
    )
    b = build_evidence(
        evidence_type="http_response",
        observations=observations,
        provenance={"tool": "fixture", "version": "1"},
        quality=EvidenceQuality.REPRODUCIBLE,
    )
    assert a.content_hash == b.content_hash


def test_candidate_confidence_is_bounded():
    try:
        FindingCandidate(
            title="test",
            vuln_type="test",
            target="example.com",
            evidence_ids=("e1",),
            confidence=1.1,
            novelty_key="test",
        )
    except ValueError:
        return
    raise AssertionError("out-of-range confidence must be rejected")
