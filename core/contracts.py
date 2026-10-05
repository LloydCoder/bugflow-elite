"""Phase 0 domain contracts for BugFlow Elite.

These contracts intentionally model research state without granting authority.
They are serialization-friendly and safe to use at module boundaries.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from hashlib import sha256
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


def stable_hash(value: Any) -> str:
    """Return a deterministic SHA-256 hash for JSON-like values."""
    import json

    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return sha256(encoded).hexdigest()


@dataclass(frozen=True)
class ResearchContext:
    """Immutable correlation context for a single bounded research run."""

    program: str
    target: str
    scan_type: str
    run_id: str = field(default_factory=lambda: str(uuid4()))
    policy_version: str = "phase0"
    tenant_id: str = "default"

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

    def fingerprint(self) -> str:
        return stable_hash({
            "kind": self.kind,
            "target": self.target,
            "source": self.source,
            "data": self.data,
        })


@dataclass(frozen=True)
class Evidence:
    """Evidence derived from observations with explicit provenance."""

    evidence_type: str
    source_observation_ids: tuple[str, ...]
    provenance: Mapping[str, Any]
    quality: EvidenceQuality
    content_hash: str
    evidence_id: str = field(default_factory=lambda: str(uuid4()))

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
