"""Evidence construction and integrity primitives for BugFlow Elite."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Mapping

from .contracts import Evidence, EvidenceQuality, stable_hash


def utc_now() -> str:
    """Return an RFC3339 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def canonical_json(value: Any) -> str:
    """Canonical JSON used for hashes, fixtures, and reproducibility."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def build_evidence(
    *,
    evidence_type: str,
    observations: list[Mapping[str, Any]],
    provenance: Mapping[str, Any],
    quality: EvidenceQuality = EvidenceQuality.SUFFICIENT,
) -> Evidence:
    """Build immutable evidence metadata from normalized observations."""
    if not observations:
        raise ValueError("observations must not be empty")

    ids = tuple(str(item["observation_id"]) for item in observations)
    if any(not item.strip() for item in ids):
        raise ValueError("every observation must have a non-empty observation_id")

    payload = {
        "evidence_type": evidence_type,
        "observations": observations,
        "provenance": dict(provenance),
        "quality": quality.value,
    }
    return Evidence(
        evidence_type=evidence_type,
        source_observation_ids=ids,
        provenance=dict(provenance),
        quality=quality,
        content_hash=stable_hash(payload),
    )


def verify_evidence_hash(
    evidence: Evidence,
    *,
    observations: list[Mapping[str, Any]],
) -> bool:
    """Recompute an evidence hash and fail closed on malformed input."""
    if not observations:
        return False
    ids = tuple(str(item.get("observation_id", "")) for item in observations)
    if ids != evidence.source_observation_ids:
        return False
    payload = {
        "evidence_type": evidence.evidence_type,
        "observations": observations,
        "provenance": dict(evidence.provenance),
        "quality": evidence.quality.value,
    }
    return stable_hash(payload) == evidence.content_hash
