"""Ecosystem integration contracts.

Integrations exchange typed intelligence and execution intents rather than
duplicating authority. External systems remain optional adapters.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping


class IntegrationKind(str, Enum):
    TADS = "tads"
    RECONOS = "reconos"
    FDSE = "fdse"
    FDSE_TOOLKIT = "fdse_toolkit"
    WORLD_INTELLIGENCE = "world_intelligence"


@dataclass(frozen=True)
class IntegrationContract:
    name: IntegrationKind
    version: str
    direction: str
    capabilities: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.version.strip():
            raise ValueError("integration version is required")
        if self.direction not in {"inbound", "outbound", "bidirectional"}:
            raise ValueError("invalid integration direction")
        if not self.capabilities:
            raise ValueError("integration must declare capabilities")


@dataclass(frozen=True)
class IntelligenceSignal:
    source: IntegrationKind
    signal_type: str
    subject: str
    confidence: float
    attributes: Mapping[str, object]

    def __post_init__(self) -> None:
        if not self.signal_type.strip() or not self.subject.strip():
            raise ValueError("signal identity is required")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("signal confidence must be between 0 and 1")


DEFAULT_CONTRACTS = (
    IntegrationContract(IntegrationKind.TADS, "1", "inbound", ("account_signal", "demand_signal")),
    IntegrationContract(IntegrationKind.RECONOS, "1", "inbound", ("asset", "observation", "evidence_ref")),
    IntegrationContract(IntegrationKind.FDSE, "1", "outbound", ("finding", "evidence_pack", "engineering_task")),
    IntegrationContract(IntegrationKind.FDSE_TOOLKIT, "1", "outbound", ("field_report", "delivery_artifact")),
    IntegrationContract(IntegrationKind.WORLD_INTELLIGENCE, "1", "inbound", ("entity", "event", "change_signal")),
)


def validate_ecosystem_contracts(
    contracts: tuple[IntegrationContract, ...] = DEFAULT_CONTRACTS,
) -> tuple[IntegrationContract, ...]:
    names = [contract.name for contract in contracts]
    if len(names) != len(set(names)):
        raise ValueError("integration contracts must be unique")
    return contracts


def route_signal(signal: IntelligenceSignal) -> dict[str, object]:
    """Normalize an integration signal without granting it execution authority."""
    return {
        "source": signal.source.value,
        "signal_type": signal.signal_type,
        "subject": signal.subject,
        "confidence": signal.confidence,
        "attributes": dict(signal.attributes),
        "authority": "advisory",
    }
