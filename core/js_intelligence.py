"""Static JavaScript intelligence normalization.

This module never executes JavaScript. It extracts and normalizes endpoint-like
references so the attack-surface graph can correlate JS files with APIs and
parameters without treating parser output as a vulnerability finding.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, urljoin, urlparse
import hashlib
import re

_ENDPOINT_RE = re.compile(
    r"""(?:https?://[^\s"'<>]+|/+(?:api|graphql|v\d+|rest|internal|admin)[^\s"'<>]*)""",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class EndpointReference:
    url: str
    parameters: tuple[str, ...]
    source: str = "js_static"


def normalize_endpoint(raw: str, base_url: str) -> str | None:
    raw = raw.strip().rstrip(";,)")
    if not raw or raw.startswith("//"):
        return None
    parsed = urlparse(urljoin(base_url, raw))
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return parsed._replace(fragment="").geturl()


def extract_endpoint_references(script: str, base_url: str) -> tuple[EndpointReference, ...]:
    if not script.strip():
        return ()
    candidates = set(_ENDPOINT_RE.findall(script))
    refs: dict[str, EndpointReference] = {}
    for candidate in candidates:
        normalized = normalize_endpoint(candidate, base_url)
        if normalized is None:
            continue
        params = tuple(
            sorted(
                {
                    name
                    for name, _ in parse_qsl(
                        urlparse(normalized).query, keep_blank_values=True
                    )
                }
            )
        )
        refs[normalized] = EndpointReference(normalized, params)
    return tuple(sorted(refs.values(), key=lambda item: item.url))


def ingest_js_intelligence(
    graph,
    *,
    asset_url: str,
    js_url: str,
    script: str,
    source: str = "js_static",
) -> list[EndpointReference]:
    js_node, _ = graph.upsert_node(
        "javascript",
        js_url,
        attributes={
            "asset_url": asset_url,
            "content_hash": hashlib.sha256(
                script.encode("utf-8", errors="replace")
            ).hexdigest(),
        },
        source=source,
    )
    asset_node, _ = graph.upsert_node("url", asset_url, source=source)
    graph.upsert_edge(asset_node, js_node, "serves_javascript", source=source)

    refs = extract_endpoint_references(script, asset_url)
    for ref in refs:
        endpoint_node, _ = graph.upsert_node(
            "endpoint",
            ref.url,
            attributes={"parameters": list(ref.parameters), "source_js": js_url},
            source=source,
        )
        graph.upsert_edge(js_node, endpoint_node, "contains_endpoint", source=source)
    return list(refs)
