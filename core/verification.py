"""Evidence-first verification and threat-signal correlation contracts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from core.contracts import Finding, FindingStatus


@dataclass(frozen=True)
class VerificationResult:
    finding_id: str
    verified: bool
    confidence: float
    evidence_score: float
    checks_passed: int
    checks_total: int
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        if not 0.0 <= self.evidence_score <= 1.0:
            raise ValueError("evidence_score must be between 0 and 1")
        if self.checks_total < 0 or self.checks_passed < 0:
            raise ValueError("verification check counts cannot be negative")
        if self.checks_passed > self.checks_total:
            raise ValueError("checks_passed cannot exceed checks_total")


def verify_finding(
    finding: Finding,
    *,
    evidence_score: float,
    checks_passed: int,
    checks_total: int,
    notes: tuple[str, ...] = (),
) -> VerificationResult:
    if not finding.evidence_ids:
        raise ValueError("verification requires evidence")
    if finding.status in {FindingStatus.REJECTED, FindingStatus.DUPLICATE}:
        return VerificationResult(
            finding_id=finding.finding_id,
            verified=False,
            confidence=0.0,
            evidence_score=evidence_score,
            checks_passed=checks_passed,
            checks_total=checks_total,
            notes=notes,
        )
    confidence = checks_passed / checks_total if checks_total else 0.0
    verified = confidence >= 0.75 and evidence_score >= 0.5
    return VerificationResult(
        finding_id=finding.finding_id,
        verified=verified,
        confidence=confidence,
        evidence_score=evidence_score,
        checks_passed=checks_passed,
        checks_total=checks_total,
        notes=notes,
    )


@dataclass(frozen=True)
class ThreatSignal:
    source: str
    signal_type: str
    target: str
    confidence: float
    attributes: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not self.source.strip() or not self.signal_type.strip() or not self.target.strip():
            raise ValueError("threat signal identity fields are required")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("threat signal confidence must be between 0 and 1")


def correlate_threat_signal(
    signal: ThreatSignal,
    *,
    finding: Finding | None = None,
) -> dict[str, Any]:
    """Return correlation metadata without changing finding severity."""
    result = {
        "source": signal.source,
        "signal_type": signal.signal_type,
        "target": signal.target,
        "confidence": signal.confidence,
        "attributes": dict(signal.attributes),
        "correlated": finding is not None and finding.target == signal.target,
    }
    if finding is not None:
        result["finding_id"] = finding.finding_id
        result["finding_status"] = finding.status.value
        result["severity_authority"] = "finding"
    return result
