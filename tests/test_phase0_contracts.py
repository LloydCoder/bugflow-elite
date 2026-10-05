from core.contracts import (
    ActionClass,
    EvidenceQuality,
    Finding,
    FindingCandidate,
    FindingStatus,
    Observation,
    Verdict,
    VerdictDecision,
    ResearchContext,
)
from core.evidence import build_evidence, verify_evidence_hash


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


def test_evidence_round_trip_integrity():
    observations = [{
        "observation_id": "obs-1",
        "kind": "http_response",
        "status": 200,
    }]
    evidence = build_evidence(
        evidence_type="http_response",
        observations=observations,
        provenance={"tool": "fixture", "version": "1"},
        quality=EvidenceQuality.REPRODUCIBLE,
    )
    assert verify_evidence_hash(evidence, observations=observations)
    tampered = [{**observations[0], "status": 403}]
    assert not verify_evidence_hash(evidence, observations=tampered)


def test_evidence_requires_observation():
    try:
        build_evidence(
            evidence_type="http_response",
            observations=[],
            provenance={"tool": "fixture"},
        )
    except ValueError:
        return
    raise AssertionError("evidence must reference at least one observation")


def test_finding_requires_evidence():
    try:
        Finding(
            candidate_id="candidate-1",
            title="test",
            vuln_type="xss",
            target="example.com",
            evidence_ids=(),
            severity="high",
            confidence=0.9,
        )
    except ValueError:
        return
    raise AssertionError("finding without evidence must be rejected")


def test_finding_and_verdict_are_explicit_states():
    finding = Finding(
        candidate_id="candidate-1",
        title="test",
        vuln_type="xss",
        target="example.com",
        evidence_ids=("e1",),
        severity="high",
        confidence=0.9,
        status=FindingStatus.VERIFIED,
    )
    verdict = Verdict(
        finding_id=finding.finding_id,
        decision=VerdictDecision.NEEDS_REVIEW,
        rationale="Human review required",
        evidence_ids=finding.evidence_ids,
        decided_by="policy",
        decided_at="2026-10-05T00:00:00+00:00",
    )
    assert finding.to_dict()["status"] == "verified"
    assert verdict.to_dict()["decision"] == "needs_review"
