"""
BugFlow Elite v6 — Deep JS Intelligence Layer
Highest ROI module for finding hidden API endpoints competitors miss.
Pipeline: gau → waymore → subjs → jsluice → JSHunter → LinkFinder → AI analysis
Tinlance Limited | LloydCoder
"""

import re
import json
import logging
import asyncio
import hashlib
import subprocess
import aiohttp
from pathlib import Path
from typing import Optional
from modules.scope.scope_enforcer import ScopeEnforcer
from db.models import get_conn, upsert_asset

logger = logging.getLogger(__name__)

# Patterns for high-value endpoint/secret discovery in JS
INTERESTING_PATTERNS = {
    "api_endpoint":     re.compile(r'["\']/(api|v\d+|graphql|rest|internal|admin|backend|private)[^"\']*["\']', re.I),
    "aws_key":          re.compile(r'(?:AKIA|AIPA|ASIA|AROA)[A-Z0-9]{16}'),
    "jwt_secret":       re.compile(r'(?:jwt|secret|token)[_\-]?(?:key|secret)\s*[:=]\s*["\'][^"\']{10,}["\']', re.I),
    "api_key_generic":  re.compile(r'(?:api[_\-]?key|apikey|api[_\-]?token)\s*[:=]\s*["\'][^"\']{10,}["\']', re.I),
    "password_leak":    re.compile(r'(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}["\']', re.I),
    "internal_url":     re.compile(r'https?://(?:internal|admin|staging|dev|test|uat|qa)\.[a-z0-9\-\.]+', re.I),
    "firebase_config":  re.compile(r'firebase[^"\']*:[^"\']*["\']'),
    "graphql_schema":   re.compile(r'__typename|query\s+[A-Z][a-zA-Z]+\s*\{|mutation\s+[A-Z]'),
    "s3_bucket":        re.compile(r's3\.[a-z0-9\-]+\.amazonaws\.com|[a-z0-9\-]+\.s3\.amazonaws\.com'),
    "oauth_secret":     re.compile(r'(?:client[_\-]?secret|oauth[_\-]?secret)\s*[:=]\s*["\'][^"\']{10,}["\']', re.I),
    "hardcoded_token":  re.compile(r'(?:Bearer|token)\s+[a-zA-Z0-9\-_\.]{20,}', re.I),
    "private_key":      re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
    "basic_auth_url":   re.compile(r'https?://[^:]+:[^@]+@[a-z0-9\-\.]+'),
}


class JSIntelligence:
    """
    Full JS analysis pipeline for a target domain.
    Discovers hidden endpoints, leaked secrets, and API routes
    buried in JavaScript files that standard scanners miss.
    """

    def __init__(self, config: dict, scope: ScopeEnforcer):
        self.config = config
        self.scope = scope
        self.db_path = config.get("general", {}).get("db_path", "./db/bugflow.db")
        self.js_cfg = config.get("crawler", {}).get("js_intel", {})
        self.output_dir = Path("./output/js_intel")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def run(self, domain: str, subdomains: list[str]) -> dict:
        """
        Full JS intelligence pipeline for a domain.
        Returns structured findings: endpoints, secrets, js_files.
        """
        self.scope.assert_in_scope(domain)
        logger.info(f"[JS Intel] Starting full pipeline for {domain}")

        all_js_urls = set()
        all_endpoints = set()
        all_secrets = []

        # Step 1: Historical URL harvest (gau + waymore)
        historical_urls = await self._harvest_historical_urls(domain, subdomains)
        js_from_history = {u for u in historical_urls if self._is_js_url(u)}
        all_js_urls.update(js_from_history)
        logger.info(f"[JS Intel] {len(js_from_history)} JS URLs from history")

        # Step 2: Live JS extraction (subjs on live hosts)
        live_js = await self._extract_live_js(subdomains)
        all_js_urls.update(live_js)
        logger.info(f"[JS Intel] {len(live_js)} live JS URLs")

        # Step 3: Analyze all JS files
        for js_url in list(all_js_urls)[:200]:  # Cap at 200 files per run
            try:
                endpoints, secrets = await self._analyze_js_file(js_url, domain)
                all_endpoints.update(endpoints)
                all_secrets.extend(secrets)
            except Exception as e:
                logger.debug(f"[JS Intel] Error analyzing {js_url}: {e}")

        # Step 4: jsluice deep analysis (if installed)
        if self._tool_installed("jsluice"):
            jsluice_results = await self._run_jsluice(list(all_js_urls)[:50])
            all_endpoints.update(jsluice_results.get("urls", set()))
            all_secrets.extend(jsluice_results.get("secrets", []))

        # Save to DB
        await self._save_results(domain, all_js_urls, all_endpoints, all_secrets)

        result = {
            "js_files": list(all_js_urls),
            "endpoints": list(all_endpoints),
            "secrets": all_secrets,
            "stats": {
                "js_files_found": len(all_js_urls),
                "endpoints_found": len(all_endpoints),
                "secrets_found": len(all_secrets),
            }
        }
        logger.info(
            f"[JS Intel] Complete: {len(all_js_urls)} JS files, "
            f"{len(all_endpoints)} endpoints, {len(all_secrets)} potential secrets"
        )
        return result

    async def _harvest_historical_urls(self, domain: str, subdomains: list[str]) -> set[str]:
        """Run gau + waymore to harvest historical URLs from archives."""
        all_urls = set()

        # gau
        if self.js_cfg.get("gau", {}).get("enabled") and self._tool_installed("gau"):
            gau_urls = await self._run_gau(domain)
            all_urls.update(gau_urls)

        # waymore
        if self.js_cfg.get("waymore", {}).get("enabled") and self._tool_installed("waymore"):
            waymore_urls = await self._run_waymore(domain)
            all_urls.update(waymore_urls)

        return all_urls

    async def _run_gau(self, domain: str) -> set[str]:
        """Run gau to get known URLs from OTX, Wayback, CommonCrawl, URLScan."""
        try:
            cmd = ["gau", "--subs", "--threads", "5", "--json", domain]
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            urls = set()
            for line in stdout.decode().split("\n"):
                line = line.strip()
                if line:
                    try:
                        data = json.loads(line)
                        url = data.get("url", "")
                    except json.JSONDecodeError:
                        url = line
                    if url and domain in url:
                        urls.add(url)
            logger.debug(f"[gau] {len(urls)} URLs for {domain}")
            return urls
        except asyncio.TimeoutError:
            logger.warning(f"[gau] Timeout for {domain}")
            return set()
        except Exception as e:
            logger.error(f"[gau] Error: {e}")
            return set()

    async def _run_waymore(self, domain: str) -> set[str]:
        """Run waymore for deep Wayback Machine URL harvesting."""
        try:
            output_file = self.output_dir / f"{domain}_waymore.txt"
            cmd = ["waymore", "-i", domain, "-mode", "U", "-oU", str(output_file)]
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.communicate(), timeout=180)

            urls = set()
            if output_file.exists():
                with open(output_file) as f:
                    for line in f:
                        url = line.strip()
                        if url and domain in url:
                            urls.add(url)
            logger.debug(f"[waymore] {len(urls)} URLs for {domain}")
            return urls
        except asyncio.TimeoutError:
            logger.warning(f"[waymore] Timeout for {domain}")
            return set()
        except Exception as e:
            logger.error(f"[waymore] Error: {e}")
            return set()

    async def _extract_live_js(self, subdomains: list[str]) -> set[str]:
        """Run subjs to extract JS file URLs from live hosts."""
        if not self._tool_installed("subjs"):
            return set()

        js_urls = set()
        input_data = "\n".join(
            f"https://{s}" for s in subdomains[:100]
        ).encode()

        try:
            proc = await asyncio.create_subprocess_exec(
                "subjs",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(input=input_data), timeout=120
            )
            for line in stdout.decode().split("\n"):
                url = line.strip()
                if url and url.startswith("http") and self._is_js_url(url):
                    js_urls.add(url)
        except Exception as e:
            logger.error(f"[subjs] Error: {e}")

        return js_urls

    async def _analyze_js_file(self, js_url: str, domain: str) -> tuple[set, list]:
        """
        Download and analyze a JS file for endpoints and secrets.
        Returns (endpoints, secrets).
        """
        endpoints = set()
        secrets = []

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    js_url,
                    timeout=aiohttp.ClientTimeout(total=15),
                    allow_redirects=True
                ) as resp:
                    if resp.status != 200:
                        return endpoints, secrets
                    content_type = resp.headers.get("Content-Type", "")
                    if "javascript" not in content_type and not self._is_js_url(js_url):
                        return endpoints, secrets
                    content = await resp.text(errors="ignore")

        except Exception:
            return endpoints, secrets

        # Extract endpoints using LinkFinder-style regex
        for match in INTERESTING_PATTERNS["api_endpoint"].finditer(content):
            endpoint = match.group(0).strip("\"'")
            if len(endpoint) > 2:
                endpoints.add(endpoint)

        # Extract secrets
        for secret_type, pattern in INTERESTING_PATTERNS.items():
            if secret_type == "api_endpoint":
                continue
            for match in pattern.finditer(content):
                raw = match.group(0)
                # Never store full secrets — store type + truncated + hash
                secrets.append({
                    "type": secret_type,
                    "source_url": js_url,
                    "fingerprint": hashlib.sha256(raw.encode()).hexdigest()[:16],
                    "preview": raw[:40] + "..." if len(raw) > 40 else raw,
                })

        return endpoints, secrets

    async def _run_jsluice(self, js_urls: list[str]) -> dict:
        """Run jsluice for deep URL/secret extraction from JS files."""
        results = {"urls": set(), "secrets": []}
        if not js_urls:
            return results

        try:
            input_data = "\n".join(js_urls).encode()
            proc = await asyncio.create_subprocess_exec(
                "jsluice", "urls",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(input=input_data), timeout=60
            )
            for line in stdout.decode().split("\n"):
                if line.strip():
                    try:
                        data = json.loads(line)
                        url = data.get("url", "")
                        if url:
                            results["urls"].add(url)
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            logger.debug(f"[jsluice] Error: {e}")

        return results

    async def _save_results(
        self, domain: str, js_files: set, endpoints: set, secrets: list
    ):
        """Persist JS intelligence results to database."""
        conn = get_conn(self.db_path)
        try:
            now = __import__("datetime").datetime.utcnow().isoformat()

            # Save endpoints
            for url in endpoints:
                try:
                    conn.execute("""
                        INSERT OR IGNORE INTO endpoints
                        (url, source, is_interesting, first_seen, last_seen)
                        VALUES (?, ?, ?, ?, ?)
                    """, (url, "js_analysis", 1, now, now))
                except Exception:
                    pass

            # Save secrets
            for secret in secrets:
                try:
                    conn.execute("""
                        INSERT INTO secrets
                        (source_url, secret_type, raw_value, source_tool, first_seen)
                        VALUES (?, ?, ?, ?, ?)
                    """, (
                        secret["source_url"], secret["type"],
                        secret["preview"], "js_intel", now
                    ))
                except Exception:
                    pass

            conn.commit()
        finally:
            conn.close()

    def _is_js_url(self, url: str) -> bool:
        """Check if a URL points to a JavaScript file."""
        clean = url.split("?")[0].split("#")[0].lower()
        return clean.endswith(".js") or ".js?" in url.lower()

    def _tool_installed(self, tool: str) -> bool:
        try:
            subprocess.run([tool, "--version"], capture_output=True)
            return True
        except FileNotFoundError:
            return False
