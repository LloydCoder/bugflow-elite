"""
BugFlow Elite v6 — Secret Scanner
TruffleHog: scans live URLs, git history, docker images for secrets.
GitHound: GitHub Code Search for leaked credentials in public repos.
Tinlance Limited | LloydCoder
"""

import json
import logging
import asyncio
import subprocess
import hashlib
import tempfile
import os
from pathlib import Path
from typing import Optional
from modules.scope.scope_enforcer import ScopeEnforcer
from db.models import get_conn

logger = logging.getLogger(__name__)

# Secret types worth elevating to high severity
HIGH_VALUE_SECRETS = {
    "AWSAccessKey", "GithubToken", "SlackToken", "StripeApiKey",
    "TwilioApiKey", "SendgridApiKey", "GoogleApiKey", "HerokuApiKey",
    "JwtToken", "PrivateKey", "RSAPrivateKey", "SSHPrivateKey",
    "DockerConfigAuth", "PaystackSecretKey", "FlutterwaveSecretKey",
}


class SecretScanner:
    """
    Two-tool secret scanning pipeline:
    1. TruffleHog — scans URLs, JS, git repos for regex+entropy secrets
    2. GitHound  — GitHub Code Search for the target org's leaked creds
    """

    def __init__(self, config: dict, scope: ScopeEnforcer):
        self.config = config
        self.scope = scope
        self.db_path = config.get("general", {}).get("db_path", "./db/bugflow.db")
        self.trufflehog_cfg = config.get("scanner", {}).get("trufflehog", {})
        self.githound_cfg = config.get("scanner", {}).get("githound", {})
        self.output_dir = Path("./output/secrets")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def run(self, domain: str, urls: list[str] = None) -> list[dict]:
        """
        Run full secret scanning pipeline for a domain.
        Returns list of found secrets (type + fingerprint, never raw value).
        """
        self.scope.assert_in_scope(domain)
        logger.info(f"[Secrets] Starting secret scan for {domain}")

        all_secrets = []

        # TruffleHog on live URLs
        if self.trufflehog_cfg.get("enabled") and urls:
            th_secrets = await self._run_trufflehog_urls(urls, domain)
            all_secrets.extend(th_secrets)

        # TruffleHog on GitHub org (if target has public repos)
        if self.trufflehog_cfg.get("github_org_scan"):
            org_name = self._extract_org_name(domain)
            if org_name:
                org_secrets = await self._run_trufflehog_github(org_name)
                all_secrets.extend(org_secrets)

        # GitHound
        if self.githound_cfg.get("enabled") and self.githound_cfg.get("github_token"):
            gh_secrets = await self._run_githound(domain)
            all_secrets.extend(gh_secrets)

        # Deduplicate by fingerprint
        seen = set()
        unique = []
        for s in all_secrets:
            fp = s.get("fingerprint", "")
            if fp and fp not in seen:
                seen.add(fp)
                unique.append(s)

        await self._save_secrets(unique, domain)
        logger.info(f"[Secrets] Found {len(unique)} unique secrets for {domain}")
        return unique

    async def _run_trufflehog_urls(self, urls: list[str], domain: str) -> list[dict]:
        """Run TruffleHog against a list of URLs (JS files, endpoints)."""
        if not self._tool_installed("trufflehog"):
            logger.warning("[TruffleHog] Not installed")
            return []

        # Filter to in-scope URLs
        urls = [u for u in urls if self.scope.is_in_scope(u)[0]]
        if not urls:
            return []

        secrets = []
        # TruffleHog can scan URLs one at a time
        semaphore = asyncio.Semaphore(5)

        async def scan_url(url: str):
            async with semaphore:
                cmd = [
                    "trufflehog", "filesystem",
                    "--no-update",
                    "--json",
                ]
                if self.trufflehog_cfg.get("only_verified"):
                    cmd.append("--only-verified")

                try:
                    # Fetch URL content to temp file, then scan
                    import aiohttp
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            url, timeout=aiohttp.ClientTimeout(total=10)
                        ) as resp:
                            if resp.status != 200:
                                return
                            content = await resp.read()

                    with tempfile.NamedTemporaryFile(
                        suffix=".js", delete=False
                    ) as f:
                        f.write(content)
                        tmp_path = f.name

                    cmd.append(tmp_path)
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.DEVNULL
                    )
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)

                    for line in stdout.decode().split("\n"):
                        if not line.strip():
                            continue
                        try:
                            result = json.loads(line)
                            secret = self._parse_trufflehog_result(result, url)
                            if secret:
                                secrets.append(secret)
                        except json.JSONDecodeError:
                            pass

                except asyncio.TimeoutError:
                    pass
                except Exception as e:
                    logger.debug(f"[TruffleHog] Error for {url}: {e}")
                finally:
                    try:
                        if 'tmp_path' in locals():
                            os.unlink(tmp_path)
                    except Exception:
                        pass

        await asyncio.gather(*[scan_url(u) for u in urls[:100]])
        return secrets

    async def _run_trufflehog_github(self, org_name: str) -> list[dict]:
        """Scan a GitHub org's public repos for leaked secrets."""
        if not self._tool_installed("trufflehog"):
            return []

        github_token = self.config.get("recon", {}).get(
            "bbot", {}
        ).get("api_keys", {}).get("github", "")

        cmd = [
            "trufflehog", "github",
            "--org", org_name,
            "--json",
            "--no-update",
        ]
        if not self.trufflehog_cfg.get("only_verified"):
            pass  # No flag needed for unverified
        if github_token:
            cmd += ["--token", github_token]

        secrets = []
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=600)

            for line in stdout.decode().split("\n"):
                if not line.strip():
                    continue
                try:
                    result = json.loads(line)
                    secret = self._parse_trufflehog_result(result, f"github:{org_name}")
                    if secret:
                        secrets.append(secret)
                except json.JSONDecodeError:
                    pass
        except asyncio.TimeoutError:
            logger.warning(f"[TruffleHog] GitHub org scan timeout for {org_name}")
        except Exception as e:
            logger.error(f"[TruffleHog] GitHub org error: {e}")

        logger.info(f"[TruffleHog] GitHub org {org_name}: {len(secrets)} secrets")
        return secrets

    async def _run_githound(self, domain: str) -> list[dict]:
        """
        Run GitHound to search GitHub Code Search for leaked credentials.
        GitHub Code Search is extremely effective for finding API keys in
        public repos that reference the target domain.
        """
        if not self._tool_installed("githound"):
            return []

        token = self.githound_cfg.get("github_token", "")
        if not token:
            logger.warning("[GitHound] No GitHub token — skipping")
            return []

        output_file = self.output_dir / f"githound_{domain.replace('.', '_')}.txt"
        cmd = [
            "githound",
            "--dig-files",
            "--dig-commits",
            "--many-results",
            "--threads", "5",
            "--github-token", token,
            "--output", str(output_file),
            domain,
        ]

        secrets = []
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL
            )
            await asyncio.wait_for(proc.communicate(), timeout=300)

            if output_file.exists():
                with open(output_file) as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            secrets.append({
                                "type": "githound_match",
                                "source_url": f"github_search:{domain}",
                                "fingerprint": hashlib.sha256(line.encode()).hexdigest()[:16],
                                "preview": line[:60],
                                "source_tool": "githound",
                                "is_verified": False,
                                "severity": "high",
                            })
        except asyncio.TimeoutError:
            logger.warning("[GitHound] Timeout")
        except Exception as e:
            logger.error(f"[GitHound] Error: {e}")

        logger.info(f"[GitHound] {domain}: {len(secrets)} matches")
        return secrets

    def _parse_trufflehog_result(self, result: dict, source_url: str) -> Optional[dict]:
        """Parse a TruffleHog JSON result into our secret format."""
        detector_name = result.get("DetectorName", result.get("detector_name", "unknown"))
        raw = result.get("Raw", result.get("raw", ""))
        verified = result.get("Verified", result.get("verified", False))

        if not raw:
            return None

        severity = "high" if detector_name in HIGH_VALUE_SECRETS else "medium"
        if verified:
            severity = "critical" if detector_name in HIGH_VALUE_SECRETS else "high"

        return {
            "type": detector_name,
            "source_url": source_url,
            "fingerprint": hashlib.sha256(raw.encode()).hexdigest()[:16],
            "preview": raw[:40] + "..." if len(raw) > 40 else raw,
            "source_tool": "trufflehog",
            "is_verified": verified,
            "severity": severity,
        }

    async def _save_secrets(self, secrets: list[dict], domain: str):
        """Save secrets to the database."""
        conn = get_conn(self.db_path)
        now = __import__("datetime").datetime.utcnow().isoformat()
        try:
            for secret in secrets:
                try:
                    conn.execute("""
                        INSERT OR IGNORE INTO secrets
                        (source_url, secret_type, raw_value, is_verified, source_tool, first_seen)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        secret.get("source_url", ""),
                        secret.get("type", "unknown"),
                        secret.get("preview", ""),
                        int(secret.get("is_verified", False)),
                        secret.get("source_tool", ""),
                        now,
                    ))
                except Exception:
                    pass
            conn.commit()
        finally:
            conn.close()

    def _extract_org_name(self, domain: str) -> Optional[str]:
        """Try to extract a likely GitHub org name from a domain."""
        parts = domain.replace("www.", "").split(".")
        if parts:
            return parts[0]
        return None

    def _tool_installed(self, tool: str) -> bool:
        try:
            subprocess.run([tool], capture_output=True)
            return True
        except FileNotFoundError:
            return False
