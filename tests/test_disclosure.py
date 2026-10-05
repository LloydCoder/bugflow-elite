import pytest

from core.disclosure import (
    EvidencePack,
    ReportIntent,
    ReportIntentStatus,
    evaluate_report_quality,
    prioritize_finding,
)


def pack(**kwargs):
    values = {
        "finding_id": "f1",
        "evidence_ids": ("e1",),
        "reproduction_steps": ("GET /api/users/1",),
        "references": ("https://example.com/advisory",),
        "attachment_hashes": ("a" * 64,),
    }
    values.update(kwargs)
    return EvidencePack(**values)


def test_evidence_pack_and_ready_report_quality():
    intent = ReportIntent(
        finding_id="f1",
        title="IDOR",
        severity="high",
        summary="Unauthorized object access",
        evidence_pack=pack(),
        status=ReportIntentStatus.READY_TO_SUBMIT,
    )
    gate = evaluate_report_quality(
        intent=intent,
        in_scope=True,
        verified=True,
        duplicate=False,
        human_approved=True,
    )
    assert gate.approved is True


def test_disclosure_gate_fails_closed_without_human_approval():
    intent = ReportIntent(
        finding_id="f1",
        title="IDOR",
        severity="high",
        summary="Unauthorized object access",
        evidence_pack=pack(),
    )
    gate = evaluate_report_quality(
        intent=intent,
        in_scope=True,
        verified=True,
        duplicate=False,
        human_approved=False,
    )
    assert gate.approved is False
    assert "human approval" in " ".join(gate.reasons)


def test_ready_to_submit_requires_evidence_quality():
    with pytest.raises(ValueError):
        ReportIntent(
            finding_id="f1",
            title="weak",
            severity="low",
            summary="weak evidence",
            evidence_pack=pack(evidence_ids=(), reproduction_steps=()),
            status=ReportIntentStatus.READY_TO_SUBMIT,
        )


def test_priority_is_bounded_and_deterministic():
    score = prioritize_finding(
        severity_score=1.0,
        confidence=0.8,
        novelty=0.7,
        change_signal=0.5,
        threat_signal=0.4,
    )
    assert 0.0 <= score <= 1.0
    with pytest.raises(ValueError):
        prioritize_finding(2, 0, 0, 0, 0)
