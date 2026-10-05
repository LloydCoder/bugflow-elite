import pytest

from core.api_detection import (
    APIEndpoint,
    DetectionSpec,
    build_detection_candidate,
    normalize_detector_output,
    normalize_observed_endpoint,
    parse_openapi,
)


def test_api_endpoint_normalization():
    endpoint = normalize_observed_endpoint(
        "https://api.example.com/v1/users#fragment",
        method="get",
        source="js",
    )
    assert endpoint.url.endswith("/users")
    assert endpoint.method == "GET"


def test_openapi_operations_are_normalized():
    spec = {
        "openapi": "3.0.3",
        "servers": [{"url": "https://api.example.com"}],
        "paths": {
            "/users": {
                "get": {"operationId": "listUsers", "parameters": [{"name": "limit"}]},
                "post": {"operationId": "createUser"},
            }
        },
    }
    endpoints = parse_openapi(spec, "https://fallback.example.com")
    assert len(endpoints) == 2
    assert endpoints[0].source == "openapi"
    assert endpoints[0].parameters == ("limit",)


def test_openapi_malformed_operations_are_skipped():
    assert parse_openapi({"paths": {"/x": "invalid"}}, "https://example.com") == ()


def test_detection_requires_evidence():
    spec = DetectionSpec("xss", "xss", "WEB_REQUEST")
    with pytest.raises(ValueError):
        build_detection_candidate(
            spec,
            title="x",
            target="https://example.com",
            evidence_ids=(),
            confidence=0.8,
            novelty_key="x",
        )


def test_detector_output_becomes_candidate_not_verdict():
    spec = DetectionSpec("idor", "idor", "WEB_REQUEST")
    candidate = normalize_detector_output(
        spec,
        {
            "title": "Object access control weakness",
            "target": "https://example.com/api/users/1",
            "evidence_ids": ["ev-1"],
            "confidence": 0.92,
        },
    )
    assert candidate.vuln_type == "idor"
    assert candidate.evidence_ids == ("ev-1",)


def test_invalid_api_endpoint_is_rejected():
    with pytest.raises(ValueError):
        APIEndpoint(url="/relative", method="GET")
    with pytest.raises(ValueError):
        APIEndpoint(url="https://example.com", method="CONNECT")
