import pytest

from core.self_security import SecurityControl, audit_configuration, release_blockers


def secure_config():
    return {
        "reports": {"auto_submit": False},
        "network": {"verify_tls": True},
        "scope": {"allowed_actions": ["PASSIVE_RECON", "WEB_REQUEST"]},
    }


def test_secure_configuration_has_no_high_severity_blockers():
    controls = audit_configuration(secure_config())
    assert release_blockers(controls) == ()


def test_unsafe_configuration_blocks_release():
    config = secure_config()
    config["reports"]["auto_submit"] = True
    config["network"]["verify_tls"] = False
    blockers = release_blockers(audit_configuration(config))
    assert {item.control_id for item in blockers} == {"SELF-DISC-001", "SELF-NET-001"}


def test_control_validation():
    with pytest.raises(ValueError):
        SecurityControl("", "x", "high", False)
    with pytest.raises(ValueError):
        SecurityControl("x", "x", "unknown", False)
