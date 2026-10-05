import pytest

from core.contracts import Finding, FindingStatus
from core.verification import ThreatSignal, correlate_threat_signal, verify_finding


def finding(status=FindingStatus.OPEN):
    return Finding(
        candidate_id="c1",
        title="test",
        vuln_type="xss",
        target="https://example.com",
        evidence_ids=("ev1",),
        severity="high",
        confidence=0.9,
        status=status,
    )


def test_verification_requires_evidence_and_meets_threshold():
    result = verify_finding(
        finding(),
        evidence_score=0.9,
        checks_passed=3,
        checks_total=4,
        notes=("scope",),
    )
    assert result.verified is True
    assert result.confidence == 0.75


def test_rejected_or_duplicate_findings_cannot_verify():
    for status in (FindingStatus.REJECTED, FindingStatus.DUPLICATE):
        result = verify_finding(
            finding(status),
            evidence_score=1.0,
            checks_passed=4,
            checks_total=4,
        )
        assert result.verified is False


def test_threat_signal_does_not_gain_severity_authority():
    signal = ThreatSignal(
        source="ThreatFade",
        signal_type="c2_like",
        target="https://example.com",
        confidence=0.99,
        attributes={"z_score": 8.0},
    )
    result = correlate_threat_signal(signal, finding=finding())
    assert result["correlated"] is True
    assert result["severity_authority"] == "finding"
    assert "severity" not in result


def test_signal_validation():
    with pytest.raises(ValueError):
        ThreatSignal("", "c2", "target", 0.5, {})
    with pytest.raises(ValueError):
        ThreatSignal("x", "c2", "target", 1.1, {})
