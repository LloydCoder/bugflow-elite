"""Deterministic finding intelligence: deduplication, novelty, and history.

AI/embedding similarity is an input, never the final authority. Decisions are
explainable and combine multiple independent finding attributes.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Mapping

from core.contracts import stable_hash
from db.models import get_conn


@dataclass(frozen=True)
class FindingSignature:
    target: str
    vuln_type: str
    root_cause: str
    endpoint: str
    parameters: tuple[str, ...]
    impact: str
    remediation: str

    def fingerprint(self) -> str:
        return stable_hash(
            {
                "target": self.target.lower().strip(),
                "vuln_type": self.vuln_type.lower().strip(),
                "root_cause": self.root_cause.lower().strip(),
                "endpoint": self.endpoint.lower().strip(),
                "parameters": sorted(p.lower().strip() for p in self.parameters),
                "impact": self.impact.lower().strip(),
                "remediation": self.remediation.lower().strip(),
            }
        )

    def novelty_key(self) -> str:
        return stable_hash(
            {
                "vuln_type": self.vuln_type.lower().strip(),
                "root_cause": self.root_cause.lower().strip(),
                "endpoint": self.endpoint.lower().strip(),
            }
        )


@dataclass(frozen=True)
class DuplicateDecision:
    status: str
    score: float
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.status not in {"SUPPRESS_FROM_DRAFT", "DEPRIORITIZE", "REVIEW_REQUIRED", "DISTINCT"}:
            raise ValueError("invalid duplicate decision")
        if not 0.0 <= self.score <= 1.0:
            raise ValueError("duplicate score must be between 0 and 1")


def _jaccard(left: set[str], right: set[str]) -> float:
    if not left and not right:
        return 1.0
    union = left | right
    return len(left & right) / len(union) if union else 0.0


def compare_findings(
    candidate: FindingSignature,
    existing: FindingSignature,
    *,
    semantic_similarity: float | None = None,
) -> DuplicateDecision:
    if semantic_similarity is not None and not 0.0 <= semantic_similarity <= 1.0:
        raise ValueError("semantic similarity must be between 0 and 1")

    scores = {
        "target": 1.0 if candidate.target.lower() == existing.target.lower() else 0.0,
        "vuln_type": 1.0 if candidate.vuln_type.lower() == existing.vuln_type.lower() else 0.0,
        "root_cause": 1.0 if candidate.root_cause.lower() == existing.root_cause.lower() else 0.0,
        "endpoint": 1.0 if candidate.endpoint.lower() == existing.endpoint.lower() else 0.0,
        "parameters": _jaccard(set(candidate.parameters), set(existing.parameters)),
        "impact": 1.0 if candidate.impact.lower() == existing.impact.lower() else 0.0,
        "remediation": 1.0 if candidate.remediation.lower() == existing.remediation.lower() else 0.0,
    }
    weighted = (
        scores["target"] * 0.20
        + scores["vuln_type"] * 0.20
        + scores["root_cause"] * 0.20
        + scores["endpoint"] * 0.15
        + scores["parameters"] * 0.10
        + scores["impact"] * 0.10
        + scores["remediation"] * 0.05
    )
    if semantic_similarity is not None:
        weighted = weighted * 0.8 + semantic_similarity * 0.2

    reasons = tuple(name for name, value in scores.items() if value >= 0.8)
    if weighted >= 0.92:
        status = "SUPPRESS_FROM_DRAFT"
    elif weighted >= 0.82:
        status = "REVIEW_REQUIRED"
    elif weighted >= 0.70:
        status = "DEPRIORITIZE"
    else:
        status = "DISTINCT"
    return DuplicateDecision(status, weighted, reasons)


class FindingHistory:
    def __init__(self, db_path: str, tenant_id: str = "default"):
        self.db_path = db_path
        self.tenant_id = tenant_id

    def observe(
        self,
        signature: FindingSignature,
        *,
        status: str = "observed",
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        fingerprint = signature.fingerprint()
        novelty_key = signature.novelty_key()
        conn = get_conn(self.db_path)
        try:
            row = conn.execute(
                "SELECT observation_count, first_seen FROM finding_history "
                "WHERE tenant_id = ? AND fingerprint = ?",
                (self.tenant_id, fingerprint),
            ).fetchone()
            payload = json.dumps(dict(metadata or {}), sort_keys=True, separators=(",", ":"))
            if row is None:
                conn.execute(
                    "INSERT INTO finding_history "
                    "(tenant_id, novelty_key, vuln_type, target, fingerprint, last_status, metadata) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        self.tenant_id,
                        novelty_key,
                        signature.vuln_type,
                        signature.target,
                        fingerprint,
                        status,
                        payload,
                    ),
                )
                count = 1
                first_seen = None
            else:
                conn.execute(
                    "UPDATE finding_history SET last_seen = CURRENT_TIMESTAMP, "
                    "observation_count = observation_count + 1, last_status = ?, metadata = ? "
                    "WHERE tenant_id = ? AND fingerprint = ?",
                    (status, payload, self.tenant_id, fingerprint),
                )
                count = int(row["observation_count"]) + 1
                first_seen = row["first_seen"]
            conn.commit()
            return {
                "fingerprint": fingerprint,
                "novelty_key": novelty_key,
                "observation_count": count,
                "first_seen": first_seen,
                "is_new": row is None,
            }
        finally:
            conn.close()
