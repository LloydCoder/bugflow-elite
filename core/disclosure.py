"""Disclosure and prioritization quality gates.

The disclosure layer prepares human-reviewable report intents and evidence packs.
It never submits to a bounty provider automatically.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping


class ReportIntentStatus(str, Enum):
    PENDING_REVIEW = "pending_review"
    READY_TO_SUBMIT = "ready_to_submit"
    SUBMITTED = "submitted"
    REJECTED = "rejected"


@dataclass(frozen=True)
class EvidencePack:
    finding_id: str
    evidence_ids: tuple[str, ...]
    reproduction_steps: tuple[str, ...]
    references: tuple[str, ...] = ()
    attachment_hashes: tuple[str, ...] = ()

    def quality_score(self) -> float:
        score = 0.0
        if self.evidence_ids:
            score += 0.35
        if self.reproduction_steps:
            score += 0.30
        if self.references:
            score += 0.15
        if self.attachment_hashes:
            score += 0.20
        return score


@dataclass(frozen=True)
class ReportIntent:
    finding_id: str
    title: str
    severity: str
    summary: str
    evidence_pack: EvidencePack
    status: ReportIntentStatus = ReportIntentStatus.PENDING_REVIEW

    def __post_init__(self) -> None:
        if not self.finding_id.strip() or not self.title.strip() or not self.summary.strip():
            raise ValueError("report identity and summary are required")
        if self.status == ReportIntentStatus.READY_TO_SUBMIT and self.evidence_pack.quality_score() < 0.85:
            raise ValueError("report cannot be ready_to_submit without sufficient evidence")


@dataclass(frozen=True)
class DisclosureGate:
    approved: bool
    reasons: tuple[str, ...]


def evaluate_report_quality(
    *,
    intent: ReportIntent,
    in_scope: bool,
    verified: bool,
    duplicate: bool,
    human_approved: bool,
) -> DisclosureGate:
    reasons: list[str] = []
    if not in_scope:
        reasons.append("target is not confirmed in scope")
    if not verified:
        reasons.append("finding is not verified")
    if duplicate:
        reasons.append("finding is marked duplicate")
    if intent.evidence_pack.quality_score() < 0.85:
        reasons.append("evidence pack is below disclosure quality threshold")
    if not human_approved:
        reasons.append("human approval is required before submission")
    return DisclosureGate(approved=not reasons, reasons=tuple(reasons))


def prioritize_finding(
    *,
    severity_score: float,
    confidence: float,
    novelty: float,
    change_signal: float,
    threat_signal: float,
) -> float:
    """Research priority only; this does not assign severity or submission authority."""
    values = (severity_score, confidence, novelty, change_signal, threat_signal)
    if any(not 0.0 <= value <= 1.0 for value in values):
        raise ValueError("priority inputs must be between 0 and 1")
    return round(
        severity_score * 0.35
        + confidence * 0.25
        + novelty * 0.20
        + change_signal * 0.10
        + threat_signal * 0.10,
        6,
    )
