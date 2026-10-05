"""Normalized API intelligence and detection contracts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urljoin, urlparse

from core.contracts import FindingCandidate


HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options", "trace")


@dataclass(frozen=True)
class APIEndpoint:
    url: str
    method: str
    parameters: tuple[str, ...] = ()
    source: str = "observed"
    schema_ref: str | None = None

    def __post_init__(self) -> None:
        if not self.url.startswith(("http://", "https://")):
            raise ValueError("API endpoint URL must be absolute")
        if self.method.lower() not in HTTP_METHODS:
            raise ValueError("unsupported HTTP method")
        if not urlparse(self.url).netloc:
            raise ValueError("API endpoint URL must include a host")


def normalize_observed_endpoint(
    url: str,
    *,
    method: str = "GET",
    source: str = "observed",
) -> APIEndpoint:
    return APIEndpoint(url=url.split("#", 1)[0], method=method.upper(), source=source)


def parse_openapi(spec: Mapping[str, Any], base_url: str) -> tuple[APIEndpoint, ...]:
    """Extract API operations without executing or trusting the schema as evidence."""
    if not isinstance(spec, Mapping):
        raise ValueError("OpenAPI document must be a mapping")
    if not spec.get("paths"):
        return ()

    servers = spec.get("servers") or []
    server_url = base_url
    if servers and isinstance(servers[0], Mapping):
        server_url = str(servers[0].get("url") or base_url)
    endpoints: list[APIEndpoint] = []

    for path, item in spec["paths"].items():
        if not isinstance(path, str) or not isinstance(item, Mapping):
            continue
        for method, operation in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, Mapping):
                continue
            params = []
            for parameter in operation.get("parameters", []):
                if isinstance(parameter, Mapping) and parameter.get("name"):
                    params.append(str(parameter["name"]))
            endpoints.append(
                APIEndpoint(
                    url=urljoin(server_url.rstrip("/") + "/", path.lstrip("/")),
                    method=method.upper(),
                    parameters=tuple(sorted(set(params))),
                    source="openapi",
                    schema_ref=str(operation.get("operationId")) if operation.get("operationId") else None,
                )
            )
    return tuple(sorted(endpoints, key=lambda endpoint: (endpoint.url, endpoint.method)))


@dataclass(frozen=True)
class DetectionSpec:
    name: str
    vuln_type: str
    action_class: str
    minimum_evidence: int = 1
    advisory_only: bool = True

    def __post_init__(self) -> None:
        if not self.name.strip() or not self.vuln_type.strip() or not self.action_class.strip():
            raise ValueError("detection identity fields are required")
        if self.minimum_evidence <= 0:
            raise ValueError("minimum_evidence must be positive")


def build_detection_candidate(
    spec: DetectionSpec,
    *,
    title: str,
    target: str,
    evidence_ids: tuple[str, ...],
    confidence: float,
    novelty_key: str,
) -> FindingCandidate:
    if len(evidence_ids) < spec.minimum_evidence:
        raise ValueError("detection candidate does not meet evidence threshold")
    return FindingCandidate(
        title=title,
        vuln_type=spec.vuln_type,
        target=target,
        evidence_ids=evidence_ids,
        confidence=confidence,
        novelty_key=novelty_key,
    )


def normalize_detector_output(
    spec: DetectionSpec,
    output: Mapping[str, Any],
) -> FindingCandidate:
    """Convert detector output into a bounded candidate; never a verdict."""
    return build_detection_candidate(
        spec,
        title=str(output["title"]),
        target=str(output["target"]),
        evidence_ids=tuple(str(item) for item in output["evidence_ids"]),
        confidence=float(output["confidence"]),
        novelty_key=str(output.get("novelty_key") or f"{spec.vuln_type}:{output['target']}"),
    )
