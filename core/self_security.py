"""BugFlow self-security controls.

The self-audit layer evaluates policy invariants and configuration safety. It
does not exploit external targets and does not grant itself execution authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence


@dataclass(frozen=True)
class SecurityControl:
    control_id: str
    title: str
    severity: str
    passed: bool
    evidence: tuple[str, ...] = ()
    remediation: str = ""

    def __post_init__(self) -> None:
        if not self.control_id.strip() or not self.title.strip():
            raise ValueError("security control identity is required")
        if self.severity not in {"critical", "high", "medium", "low", "info"}:
            raise ValueError("invalid security control severity")


def audit_configuration(config: Mapping[str, object]) -> tuple[SecurityControl, ...]:
    controls: list[SecurityControl] = []
    auto_submit = bool(
        config.get("reports", {}).get("auto_submit", False)
        if isinstance(config.get("reports"), Mapping)
        else False
    )
    controls.append(
        SecurityControl(
            "SELF-DISC-001",
            "Automatic disclosure is disabled",
            "critical",
            not auto_submit,
            evidence=(f"auto_submit={auto_submit}",),
            remediation="Require explicit human approval before provider submission.",
        )
    )

    verify_tls = bool(
        config.get("network", {}).get("verify_tls", True)
        if isinstance(config.get("network"), Mapping)
        else True
    )
    controls.append(
        SecurityControl(
            "SELF-NET-001",
            "TLS verification is enabled by default",
            "high",
            verify_tls,
            evidence=(f"verify_tls={verify_tls}",),
            remediation="Enable TLS verification for production network requests.",
        )
    )

    scope_actions = (
        config.get("scope", {}).get("allowed_actions", [])
        if isinstance(config.get("scope"), Mapping)
        else []
    )
    controls.append(
        SecurityControl(
            "SELF-SCOPE-001",
            "Action policy is explicitly configured",
            "high",
            isinstance(scope_actions, Sequence) and not isinstance(scope_actions, (str, bytes)) and len(scope_actions) > 0,
            evidence=(f"allowed_actions={list(scope_actions) if isinstance(scope_actions, Sequence) and not isinstance(scope_actions, (str, bytes)) else scope_actions}",),
            remediation="Configure an explicit capability allowlist.",
        )
    )
    return tuple(controls)


def release_blockers(controls: Sequence[SecurityControl]) -> tuple[SecurityControl, ...]:
    return tuple(
        control for control in controls
        if not control.passed and control.severity in {"critical", "high"}
    )
