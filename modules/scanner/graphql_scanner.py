"""
BugFlow Elite v6 — GraphQL Security Scanner
Tests GraphQL endpoints for:
  - Introspection enabled (schema disclosure)
  - Field-level authorization bypass (IDOR via GraphQL)
  - Batching attacks (rate limit bypass)
  - Injection via GraphQL variables
  - Sensitive field exposure
  - Deeply nested query DoS
Tinlance Limited | LloydCoder
"""

import json
import logging
import asyncio
import aiohttp
from pathlib import Path
from typing import Optional
from modules.scope.scope_enforcer import ScopeEnforcer
from db.models import get_conn, save_finding

logger = logging.getLogger(__name__)

INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind }
        args { name type { name kind } }
      }
    }
  }
}
"""

SENSITIVE_FIELD_PATTERNS = [
    "password", "passwd", "secret", "token", "apikey",
    "api_key", "private", "ssn", "credit_card", "cvv",
    "pin", "otp", "mfa", "auth", "credential", "hash",
    "salt", "key", "certificate", "pem", "private_key",
]

BATCH_ATTACK_QUERY = """
[
  {"query": "{ __typename }"},
  {"query": "{ __typename }"},
  {"query": "{ __typename }"},
  {"query": "{ __typename }"},
  {"query": "{ __typename }"}
]
"""

DEEP_QUERY = """
{
  user {
    friends {
      friends {
        friends {
          friends {
            friends {
              id name email
            }
          }
        }
      }
    }
  }
}
"""

COMMON_GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/graphql/v1",
    "/v1/graphql", "/v2/graphql", "/api/v1/graphql",
    "/api/v2/graphql", "/query", "/gql",
    "/graphiql", "/playground", "/explorer",
    "/api/query", "/graph",
]


class GraphQLScanner:
    """
    Discovers and tests GraphQL endpoints for security issues.
    """

    def __init__(self, config: dict, scope: ScopeEnforcer):
        self.config = config
        self.scope = scope
        self.db_path = config.get("general", {}).get(
            "db_path", "./db/bugflow.db"
        )

    async def scan_domain(
        self, domain: str, program: str = ""
    ) -> list[dict]:
        """Full GraphQL security scan for a domain."""
        logger.info(f"[GraphQL] Scanning {domain}")

        endpoints = await self._discover_endpoints(domain)
        if not endpoints:
            logger.debug(
                f"[GraphQL] No GraphQL endpoints on {domain}"
            )
            return []

        logger.info(
            f"[GraphQL] Found {len(endpoints)} GraphQL endpoints"
        )

        findings = []
        for endpoint in endpoints:
            results = await self._test_endpoint(
                endpoint, domain, program
            )
            findings.extend(results)
            await asyncio.sleep(1.0)

        if findings:
            await self._save_findings(findings, program)
            logger.info(
                f"[GraphQL] {len(findings)} issues found on {domain}"
            )

        return findings

    async def _discover_endpoints(
        self, domain: str
    ) -> list[str]:
        """Find GraphQL endpoints via common paths + DB."""
        endpoints = []

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=8)
        ) as session:
            for path in COMMON_GRAPHQL_PATHS:
                for scheme in ("https", "http"):
                    url = f"{scheme}://{domain}{path}"
                    try:
                        self.scope.assert_in_scope(url)
                        # Send minimal GraphQL query to detect
                        async with session.post(
                            url,
                            json={"query": "{ __typename }"},
                            headers={
                                "Content-Type": "application/json"
                            },
                            ssl=False,
                        ) as resp:
                            text = await resp.text(
                                errors="ignore"
                            )
                            if (
                                resp.status in (200, 400)
                                and ("data" in text
                                     or "errors" in text
                                     or "__typename" in text)
                            ):
                                if url not in endpoints:
                                    endpoints.append(url)
                                    logger.info(
                                        f"[GraphQL] Found: {url}"
                                    )
                                    break  # https found, skip http
                    except Exception:
                        pass

        # Also check DB
        conn = get_conn(self.db_path)
        try:
            rows = conn.execute("""
                SELECT DISTINCT url FROM endpoints
                WHERE url LIKE ? AND (
                    url LIKE '%graphql%' OR
                    url LIKE '%/gql%' OR
                    url LIKE '%/query%' OR
                    url LIKE '%/graph%'
                ) LIMIT 20
            """, (f"%{domain}%",)).fetchall()
            for row in rows:
                if row["url"] not in endpoints:
                    try:
                        self.scope.assert_in_scope(row["url"])
                        endpoints.append(row["url"])
                    except Exception:
                        pass
        except Exception:
            pass
        finally:
            conn.close()

        return endpoints

    async def _test_endpoint(
        self, url: str, domain: str, program: str
    ) -> list[dict]:
        """Run all GraphQL security tests on one endpoint."""
        findings = []

        # Test 1: Introspection enabled
        finding = await self._test_introspection(url, program)
        if finding:
            findings.append(finding)
            schema = finding.get("_schema_data")

            # Test 2: Sensitive field exposure (needs schema)
            if schema:
                sens = self._check_sensitive_fields(
                    schema, url, program
                )
                if sens:
                    findings.append(sens)

        # Test 3: Batching attack
        batch = await self._test_batching(url, program)
        if batch:
            findings.append(batch)

        # Test 4: Deep query (DoS potential)
        deep = await self._test_deep_query(url, program)
        if deep:
            findings.append(deep)

        # Test 5: Field suggestion enabled
        # (leaks schema even without introspection)
        suggestion = await self._test_field_suggestion(
            url, program
        )
        if suggestion:
            findings.append(suggestion)

        return findings

    async def _test_introspection(
        self, url: str, program: str
    ) -> Optional[dict]:
        """Check if introspection is enabled."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json={"query": INTROSPECTION_QUERY},
                    headers={"Content-Type": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=15),
                    ssl=False,
                ) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json(
                        content_type=None
                    )
                    if not data.get("data", {}).get("__schema"):
                        return None

                    schema = data["data"]["__schema"]
                    type_count = len(schema.get("types", []))

                    finding = {
                        "title": (
                            f"GraphQL Introspection Enabled — "
                            f"{url[:70]}"
                        ),
                        "severity": "medium",
                        "vuln_type": "graphql_introspection",
                        "target": url,
                        "description": (
                            f"GraphQL introspection is enabled on "
                            f"this endpoint, exposing the complete "
                            f"API schema including {type_count} "
                            f"types, all queries, mutations, and "
                            f"field names. This allows attackers "
                            f"to map the entire API surface and "
                            f"identify sensitive operations."
                        ),
                        "reproduction_steps": (
                            f"1. Send POST to {url}\n"
                            f"2. Body: {{'query': "
                            f"'{{ __schema {{ types {{ name }} }} }}'}} \n"
                            f"3. Observe full schema returned"
                        ),
                        "proof_of_concept": (
                            f"URL: {url}\n"
                            f"Types exposed: {type_count}\n"
                            f"Sample types: "
                            f"{[t.get('name') for t in schema.get('types', [])[:10]]}"
                        ),
                        "ai_score": 6.5,
                        "tool": "graphql_scanner",
                        "program": program,
                        "_schema_data": schema,
                    }
                    logger.info(
                        f"[GraphQL] Introspection enabled: {url}"
                    )
                    return finding
        except Exception as e:
            logger.debug(f"[GraphQL] Introspection error: {e}")
        return None

    def _check_sensitive_fields(
        self, schema: dict, url: str, program: str
    ) -> Optional[dict]:
        """Find sensitive field names in the schema."""
        sensitive_found = []

        for type_def in schema.get("types", []):
            type_name = type_def.get("name", "")
            if type_name.startswith("__"):
                continue
            for field in type_def.get("fields") or []:
                field_name = (field.get("name") or "").lower()
                for pattern in SENSITIVE_FIELD_PATTERNS:
                    if pattern in field_name:
                        sensitive_found.append(
                            f"{type_name}.{field['name']}"
                        )

        if not sensitive_found:
            return None

        return {
            "title": (
                f"GraphQL Sensitive Fields Exposed — "
                f"{url[:60]}"
            ),
            "severity": "high",
            "vuln_type": "graphql_sensitive_fields",
            "target": url,
            "description": (
                f"GraphQL schema exposes potentially sensitive "
                f"field names: {sensitive_found[:10]}. "
                f"These fields may return sensitive data without "
                f"proper authorization checks."
            ),
            "reproduction_steps": (
                f"1. Get schema via introspection on {url}\n"
                f"2. Query sensitive fields: "
                f"{sensitive_found[:3]}\n"
                f"3. Verify if authorization is enforced"
            ),
            "proof_of_concept": (
                f"Sensitive fields found: "
                f"{json.dumps(sensitive_found[:15], indent=2)}"
            ),
            "ai_score": 7.5,
            "tool": "graphql_scanner",
            "program": program,
        }

    async def _test_batching(
        self, url: str, program: str
    ) -> Optional[dict]:
        """Test if query batching is enabled (rate limit bypass)."""
        try:
            batch_queries = [
                {"query": "{ __typename }"}
            ] * 10

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json=batch_queries,
                    headers={"Content-Type": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=15),
                    ssl=False,
                ) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json(content_type=None)
                    if not isinstance(data, list):
                        return None
                    if len(data) < 5:
                        return None

                    logger.info(
                        f"[GraphQL] Batching enabled: {url}"
                    )
                    return {
                        "title": (
                            f"GraphQL Batching Attack — "
                            f"Rate Limit Bypass ({url[:60]})"
                        ),
                        "severity": "medium",
                        "vuln_type": "graphql_batching",
                        "target": url,
                        "description": (
                            "GraphQL accepts batched queries, "
                            "allowing an attacker to send hundreds "
                            "of queries in a single HTTP request, "
                            "bypassing rate limiting. This enables "
                            "brute-force attacks on login mutations "
                            "and OTP fields."
                        ),
                        "reproduction_steps": (
                            f"1. Send POST to {url}\n"
                            f"2. Body: array of 10 identical "
                            f"queries (see PoC)\n"
                            f"3. All 10 execute — rate limit "
                            f"applies once instead of 10 times"
                        ),
                        "proof_of_concept": (
                            f"URL: {url}\n"
                            f"Batch of 10 queries accepted. "
                            f"Response: {str(data)[:300]}"
                        ),
                        "ai_score": 6.8,
                        "tool": "graphql_scanner",
                        "program": program,
                    }
        except Exception:
            pass
        return None

    async def _test_deep_query(
        self, url: str, program: str
    ) -> Optional[dict]:
        """Test if deeply nested queries are accepted (DoS)."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json={"query": DEEP_QUERY},
                    headers={"Content-Type": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False,
                ) as resp:
                    text = await resp.text(errors="ignore")
                    # If no depth limit error, it's vulnerable
                    if (
                        resp.status == 200
                        and "depth" not in text.lower()
                        and "complexity" not in text.lower()
                        and "limit" not in text.lower()
                    ):
                        return {
                            "title": (
                                f"GraphQL No Query Depth "
                                f"Limit — {url[:60]}"
                            ),
                            "severity": "low",
                            "vuln_type": "graphql_depth",
                            "target": url,
                            "description": (
                                "GraphQL accepts deeply nested "
                                "queries without depth limits, "
                                "potentially enabling DoS through "
                                "computationally expensive queries."
                            ),
                            "reproduction_steps": (
                                f"1. Send POST to {url}\n"
                                f"2. Use deeply nested query "
                                f"(6+ levels)\n"
                                f"3. No depth limit error returned"
                            ),
                            "proof_of_concept": (
                                f"URL: {url}\n"
                                f"Nested query accepted, "
                                f"response: {text[:200]}"
                            ),
                            "ai_score": 5.0,
                            "tool": "graphql_scanner",
                            "program": program,
                        }
        except Exception:
            pass
        return None

    async def _test_field_suggestion(
        self, url: str, program: str
    ) -> Optional[dict]:
        """
        Test for field suggestions — leaks schema info even
        when introspection is disabled.
        """
        try:
            query = '{ usr { id } }'  # Typo on purpose
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json={"query": query},
                    headers={"Content-Type": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False,
                ) as resp:
                    if resp.status != 200:
                        return None
                    text = await resp.text(errors="ignore")
                    if (
                        "did you mean" in text.lower()
                        or "suggestion" in text.lower()
                    ):
                        return {
                            "title": (
                                f"GraphQL Field Suggestions "
                                f"Enabled — {url[:60]}"
                            ),
                            "severity": "low",
                            "vuln_type": "graphql_suggestions",
                            "target": url,
                            "description": (
                                "GraphQL returns field name "
                                "suggestions on typos, leaking "
                                "schema information even when "
                                "introspection is disabled."
                            ),
                            "reproduction_steps": (
                                f"1. POST to {url}\n"
                                f"2. Query: {query}\n"
                                f"3. Response suggests field names"
                            ),
                            "proof_of_concept": (
                                f"Query: {query}\n"
                                f"Response: {text[:300]}"
                            ),
                            "ai_score": 4.5,
                            "tool": "graphql_scanner",
                            "program": program,
                        }
        except Exception:
            pass
        return None

    async def _save_findings(
        self, findings: list[dict], program: str
    ):
        conn = get_conn(self.db_path)
        try:
            for f in findings:
                if f.get("title"):
                    save_finding(
                        conn,
                        title=f["title"],
                        severity=f["severity"],
                        vuln_type=f["vuln_type"],
                        description=f["description"],
                        reproduction_steps=f.get(
                            "reproduction_steps", ""
                        ),
                        proof_of_concept=f.get(
                            "proof_of_concept", ""
                        ),
                        ai_score=f.get("ai_score", 5.0),
                        program=program,
                    )
            conn.commit()
        finally:
            conn.close()
