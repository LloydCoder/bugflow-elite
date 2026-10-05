import pytest

from core.ecosystem import (
    DEFAULT_CONTRACTS,
    IntegrationContract,
    IntegrationKind,
    IntelligenceSignal,
    route_signal,
    validate_ecosystem_contracts,
)


def test_default_ecosystem_contracts_are_unique():
    contracts = validate_ecosystem_contracts()
    assert {item.name for item in contracts} == set(IntegrationKind)


def test_signal_routing_is_advisory():
    signal = IntelligenceSignal(
        source=IntegrationKind.TADS,
        signal_type="funding",
        subject="account-1",
        confidence=0.9,
        attributes={"round": "Series A"},
    )
    result = route_signal(signal)
    assert result["authority"] == "advisory"
    assert result["source"] == "tads"


def test_contract_validation():
    with pytest.raises(ValueError):
        IntegrationContract(IntegrationKind.TADS, "", "inbound", ("x",))
    with pytest.raises(ValueError):
        IntegrationContract(IntegrationKind.TADS, "1", "execute", ("x",))
    with pytest.raises(ValueError):
        validate_ecosystem_contracts(DEFAULT_CONTRACTS + DEFAULT_CONTRACTS[:1])


def test_signal_confidence_validation():
    with pytest.raises(ValueError):
        IntelligenceSignal(IntegrationKind.RECONOS, "asset", "x", 2.0, {})
