"""Evidence integrity primitives for BugFlow Elite Phase 0."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Mapping

from .contracts import Evidence, EvidenceQuality, stable_hash


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_evidence(
    *,
    evidence_type: str,
    observations: list[Mapping[str, Any]],
    provenance: Mapping[str, Any],
    quality: EvidenceQuality = EvidenceQuality.SUFFICIENT,
) -> Evidence:
    """Build immutable evidence metadata from normalized observations."""
    ids = tuple(str(item["observation_id"]) for item in observations)
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


def canonical_json(value: Any) -> str:
    """Canonical JSON used for hashes, fixtures, and reproducibility."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
