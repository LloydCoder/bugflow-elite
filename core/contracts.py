"""Stable BugFlow Elite Phase 0 domain contracts.

These contracts model research state without granting execution or disclosure
authority. Authority remains outside this package in the governed execution
layer. Contracts are intentionally dependency-light and serialization-friendly.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from hashlib import sha256
import json
from typing import Any, Mapping
from uuid import uuid4


class ActionClass(str, Enum):
    PASSIVE_RECON = "PASSIVE_RECON"
    ACTIVE_RECON = "ACTIVE_RECON"
    WEB_REQUEST = "WEB_REQUEST"
    PORT_SCAN = "PORT_SCAN"
    FUZZING = "FUZZING"
    PARAM_DISCOVERY = "PARAM_DISCOVERY"
    CLOUD_ENUM = "CLOUD_ENUM"
    REPOSITORY_ANALYSIS = "REPOSITORY_ANALYSIS"


class ResearchState(str, Enum):
    OBSERVATION = "observation"
    EVIDENCE = "evidence"
    FINDING_CANDIDATE = "finding_candidate"
    FINDING = "finding"
    VERDICT = "verdict"


class EvidenceQuality(str, Enum):
    UNKNOWN = "unknown"
    PARTIAL = "partial"
    SUFFICIENT = "sufficient"
    REPRODUCIBLE = "reproducible"


class FindingStatus(str, Enum):
    OPEN = "open"
    VERIFIED = "verified"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"
    NEEDS_REVIEW = "needs_review"


class VerdictDecision(str, Enum):
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    NEEDS_REVIEW = "needs_review"
    UNKNOWN = "unknown"


def stable_hash(value: Any) -> str:
    """Return a deterministic SHA-256 hash for JSON-like values."""
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def _require_text(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


@dataclass(frozen=True)
class ResearchContext:
    """Immutable correlation context for a single bounded research run."""

    program: str
    target: str
    scan_type: str
    run_id: str = field(default_factory=lambda: str(uuid4()))
    policy_version: str = "phase0"
    tenant_id: str = "default"

    def __post_init__(self) -> None:
        for name, value in (
            ("program", self.program),
            ("target", self.target),
            ("scan_type", self.scan_type),
            ("run_id", self.run_id),
            ("policy_version", self.policy_version),
            ("tenant_id", self.tenant_id),
        ):
            _require_text(name, value)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Observation:
    """A tool observation; observations are not findings or verdicts."""

    kind: str
    target: str
    source: str
    observed_at: str
    data: Mapping[str, Any]
    context: ResearchContext
    action_class: ActionClass
    observation_id: str = field(default_factory=lambda: str(uuid4()))

    def __post_init__(self) -> None:
        for name, value in (
            ("kind", self.kind),
            ("target", self.target),
            ("source", self.source),
            ("observed_at", self.observed_at),
            ("observation_id", self.observation_id),
        ):
            _require_text(name, value)
        if not isinstance(self.data, Mapping):
            raise ValueError("data must be a mapping")
        if not isinstance(self.action_class, ActionClass):
            raise ValueError("action_class must be an ActionClass")

    def fingerprint(self) -> str:
        """Stable identity for the observation content, excluding volatile IDs."""
        return stable_hash(
            {
                "kind": self.kind,
                "target": self.target,
                "source": self.source,
                "data": self.data,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "observation_id": self.observation_id,
            "kind": self.kind,
            "target": self.target,
            "source": self.source,
            "observed_at": self.observed_at,
            "data": dict(self.data),
            "context": self.context.to_dict(),
            "action_class": self.action_class.value,
        }


@dataclass(frozen=True)
class Evidence:
    """Evidence derived from observations with explicit provenance and integrity."""

    evidence_type: str
    source_observation_ids: tuple[str, ...]
    provenance: Mapping[str, Any]
    quality: EvidenceQuality
    content_hash: str
    evidence_id: str = field(default_factory=lambda: str(uuid4()))

    def __post_init__(self) -> None:
        _require_text("evidence_type", self.evidence_type)
        _require_text("evidence_id", self.evidence_id)
        if not self.source_observation_ids:
            raise ValueError("source_observation_ids must not be empty")
        if any(not isinstance(item, str) or not item.strip() for item in self.source_observation_ids):
            raise ValueError("source_observation_ids must contain non-empty strings")
        if not isinstance(self.provenance, Mapping):
            raise ValueError("provenance must be a mapping")
        _require_text("content_hash", self.content_hash)
        if not isinstance(self.quality, EvidenceQuality):
            raise ValueError("quality must be an EvidenceQuality")

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type,
            "source_observation_ids": list(self.source_observation_ids),
            "provenance": dict(self.provenance),
            "quality": self.quality.value,
            "content_hash": self.content_hash,
        }


@dataclass(frozen=True)
class FindingCandidate:
    """A hypothesis assembled from evidence; it is not yet a verdict."""

    title: str
    vuln_type: str
    target: str
    evidence_ids: tuple[str, ...]
    confidence: float
    novelty_key: str
    candidate_id: str = field(default_factory=lambda: str(uuid4()))

    def __post_init__(self) -> None:
        for name, value in (
            ("title", self.title),
            ("vuln_type", self.vuln_type),
            ("target", self.target),
            ("novelty_key", self.novelty_key),
            ("candidate_id", self.candidate_id),
        ):
            _require_text(name, value)
        if not self.evidence_ids:
            raise ValueError("evidence_ids must not be empty")
        if any(not isinstance(item, str) or not item.strip() for item in self.evidence_ids):
            raise ValueError("evidence_ids must contain non-empty strings")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "title": self.title,
            "vuln_type": self.vuln_type,
            "target": self.target,
            "evidence_ids": list(self.evidence_ids),
            "confidence": self.confidence,
            "novelty_key": self.novelty_key,
        }


@dataclass(frozen=True)
class Finding:
    """A research finding backed by evidence; it is still not a final verdict."""

    candidate_id: str
    title: str
    vuln_type: str
    target: str
    evidence_ids: tuple[str, ...]
    severity: str
    confidence: float
    status: FindingStatus = FindingStatus.OPEN
    finding_id: str = field(default_factory=lambda: str(uuid4()))

    def __post_init__(self) -> None:
        for name, value in (
            ("candidate_id", self.candidate_id),
            ("title", self.title),
            ("vuln_type", self.vuln_type),
            ("target", self.target),
            ("severity", self.severity),
            ("finding_id", self.finding_id),
        ):
            _require_text(name, value)
        if not self.evidence_ids:
            raise ValueError("evidence_ids must not be empty")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        if not isinstance(self.status, FindingStatus):
            raise ValueError("status must be a FindingStatus")

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "candidate_id": self.candidate_id,
            "title": self.title,
            "vuln_type": self.vuln_type,
            "target": self.target,
            "evidence_ids": list(self.evidence_ids),
            "severity": self.severity,
            "confidence": self.confidence,
            "status": self.status.value,
        }


@dataclass(frozen=True)
class Verdict:
    """Explicit decision over a finding; authority remains policy/human controlled."""

    finding_id: str
    decision: VerdictDecision
    rationale: str
    evidence_ids: tuple[str, ...]
    decided_by: str
    decided_at: str
    verdict_id: str = field(default_factory=lambda: str(uuid4()))

    def __post_init__(self) -> None:
        for name, value in (
            ("finding_id", self.finding_id),
            ("rationale", self.rationale),
            ("decided_by", self.decided_by),
            ("decided_at", self.decided_at),
            ("verdict_id", self.verdict_id),
        ):
            _require_text(name, value)
        if not self.evidence_ids:
            raise ValueError("evidence_ids must not be empty")
        if not isinstance(self.decision, VerdictDecision):
            raise ValueError("decision must be a VerdictDecision")

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict_id": self.verdict_id,
            "finding_id": self.finding_id,
            "decision": self.decision.value,
            "rationale": self.rationale,
            "evidence_ids": list(self.evidence_ids),
            "decided_by": self.decided_by,
            "decided_at": self.decided_at,
        }
