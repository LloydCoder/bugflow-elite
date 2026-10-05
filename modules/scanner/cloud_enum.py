"""
BugFlow Elite v6 — Cloud Asset Enum & Misconfiguration Scanner
Discovers and checks AWS S3, GCP, Azure assets for misconfigs.
Tools: cloud_enum + S3Scanner + BucketLoot + Nuclei cloud templates
DETECTION ONLY — never writes to or exploits any bucket.
Tinlance Limited | LloydCoder
"""

import json
import logging
import asyncio
import subprocess
import aiohttp
from pathlib import Path
from typing import Optional
from modules.scope.scope_enforcer import ScopeEnforcer
from db.models import get_conn, save_finding

logger = logging.getLogger(__name__)

# Common bucket name permutations for a given domain keyword
BUCKET_PERMUTATIONS = [
    "{kw}", "{kw}-backup", "{kw}-dev", "{kw}-staging", "{kw}-prod",
    "{kw}-static", "{kw}-assets", "{kw}-media", "{kw}-files",
    "{kw}-uploads", "{kw}-data", "{kw}-logs", "{kw}-archive",
    "{kw}-public", "{kw}-private", "{kw}-internal", "{kw}-test",
    "{kw}-cdn", "{kw}-images", "{kw}-documents", "{kw}-reports",
    "dev-{kw}", "staging-{kw}", "prod-{kw}", "backup-{kw}",
    "{kw}.backup", "{kw}.dev", "{kw}.staging",
]

# S3-compatible bucket URL patterns
BUCKET_URL_PATTERNS = {
    "aws_s3":    "https://{bucket}.s3.amazonaws.com",
    "aws_s3_us": "https://{bucket}.s3.us-east-1.amazonaws.com",
    "gcs":       "https://storage.googleapis.com/{bucket}",
    "azure":     "https://{bucket}.blob.core.windows.net",
    "digitalocean": "https://{bucket}.nyc3.digitaloceanspaces.com",
}


class CloudEnumScanner:
    """
    Discovers cloud storage assets from domain keywords and checks
    for public access misconfigurations. Detection only — no exploitation.
    """

    def __init__(self, config: dict, scope: ScopeEnforcer):
        self.config = config
        self.scope = scope
        self.db_path = config.get("general", {}).get("db_path", "./db/bugflow.db")
        self.cloud_cfg = config.get("scanner", {}).get("cloud", {})
        self.output_dir = Path("./output/cloud")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def run(self, domain: str, program: str = "") -> list[dict]:
        """
        Full cloud enum pipeline for a domain.
        1. Generate bucket name candidates from domain keywords
        2. Check each candidate for public access
        3. If public — check permissions and sample files
        4. Save findings
        """
        self.scope.assert_in_scope(domain)
        logger.info(f"[Cloud] Starting cloud enum for {domain}")

        keywords = self._extract_keywords(domain)
        bucket_names = self._generate_permutations(keywords)
        logger.info(f"[Cloud] Generated {len(bucket_names)} bucket candidates")

        findings = []

        # Run cloud_enum if available
        if self.cloud_cfg.get("cloud_enum", {}).get("enabled"):
            ce_findings = await self._run_cloud_enum(domain)
            findings.extend(ce_findings)

        # Direct bucket checks
        public_buckets = await self._check_buckets_public(bucket_names)

        for bucket_info in public_buckets:
            # Check permissions in detail
            perms = await self._check_bucket_permissions(
                bucket_info["url"], bucket_info["provider"]
            )
            bucket_info["permissions"] = perms

            finding = self._build_finding(bucket_info, domain)
            findings.append(finding)

        if findings:
            await self._save_findings(findings, program)
            logger.info(f"[Cloud] Found {len(findings)} cloud misconfigs")

        return findings

    def _extract_keywords(self, domain: str) -> list[str]:
        """Extract meaningful keywords from a domain for permutation."""
        # Remove TLD and common prefixes
        parts = domain.replace("www.", "").split(".")
        keywords = []
        for part in parts[:-1]:  # Exclude TLD
            if len(part) > 2:
                keywords.append(part)
        # Also add full domain without TLD
        if len(parts) > 1:
            keywords.append(".".join(parts[:-1]))
        return list(set(keywords))

    def _generate_permutations(self, keywords: list[str]) -> list[str]:
        """Generate bucket name candidates from keywords."""
        buckets = set()
        for kw in keywords:
            for pattern in BUCKET_PERMUTATIONS:
                buckets.add(pattern.format(kw=kw))
        return list(buckets)

    async def _run_cloud_enum(self, domain: str) -> list[dict]:
        """Run cloud_enum tool for comprehensive cloud asset discovery."""
        if not self._tool_installed("cloud_enum"):
            return []

        output_file = self.output_dir / f"{domain}_cloud_enum.csv"
        keyword = domain.split(".")[0]

        cmd = [
            "cloud_enum",
            "-k", keyword,
            "--disable-azure",  # Start with S3 + GCS
            "-l", str(output_file),
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.communicate(), timeout=300)

            findings = []
            if output_file.exists():
                with open(output_file) as f:
                    for line in f:
                        line = line.strip()
                        if line and "open" in line.lower():
                            findings.append({
                                "provider": "aws_s3" if "s3" in line.lower() else "gcs",
                                "bucket_name": line.split(",")[0] if "," in line else line,
                                "url": line.split(",")[1] if "," in line else line,
                                "is_public": True,
                                "tool": "cloud_enum",
                            })
            return findings

        except asyncio.TimeoutError:
            logger.warning("[cloud_enum] Timeout")
            return []
        except Exception as e:
            logger.error(f"[cloud_enum] Error: {e}")
            return []

    async def _check_buckets_public(self, bucket_names: list[str]) -> list[dict]:
        """
        Check if bucket names are publicly accessible across providers.
        Uses simple HTTP GET — no auth, no writes, detection only.
        """
        public_buckets = []
        semaphore = asyncio.Semaphore(30)

        async def check_one(bucket_name: str, provider: str, url_template: str):
            url = url_template.format(bucket=bucket_name)
            async with semaphore:
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            url,
                            timeout=aiohttp.ClientTimeout(total=8),
                            allow_redirects=False
                        ) as resp:
                            # 200 = public list, 403 = exists but private
                            # 404 = doesn't exist, anything else = skip
                            if resp.status == 200:
                                body = await resp.text(errors="ignore")
                                # Confirm it's actually a bucket listing
                                if any(marker in body for marker in
                                       ["ListBucketResult", "Contents", "Blobs"]):
                                    public_buckets.append({
                                        "bucket_name": bucket_name,
                                        "provider": provider,
                                        "url": url,
                                        "is_public": True,
                                        "status_code": 200,
                                    })
                                    logger.warning(
                                        f"[Cloud] PUBLIC BUCKET: {url}"
                                    )
                            elif resp.status == 403:
                                # Bucket exists but private — still worth logging
                                logger.debug(f"[Cloud] Exists (private): {url}")
                except Exception:
                    pass

        tasks = []
        for bucket_name in bucket_names[:500]:  # Cap to avoid excessive requests
            for provider, url_template in BUCKET_URL_PATTERNS.items():
                tasks.append(check_one(bucket_name, provider, url_template))

        await asyncio.gather(*tasks)
        return public_buckets

    async def _check_bucket_permissions(self, url: str, provider: str) -> dict:
        """
        Check specific permissions on a known-public bucket.
        Read-only checks — never writes anything.
        """
        perms = {"list": False, "read": False, "write": False}

        try:
            async with aiohttp.ClientSession() as session:
                # Check list permission (already confirmed via _check_buckets_public)
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        perms["list"] = True
                        body = await resp.text(errors="ignore")
                        # Try to read first file listed
                        import re
                        keys = re.findall(r'<Key>([^<]+)</Key>', body)
                        if keys:
                            file_url = f"{url.rstrip('/')}/{keys[0]}"
                            try:
                                async with session.get(
                                    file_url,
                                    timeout=aiohttp.ClientTimeout(total=5)
                                ) as file_resp:
                                    if file_resp.status == 200:
                                        perms["read"] = True
                            except Exception:
                                pass
        except Exception as e:
            logger.debug(f"[Cloud] Permission check error: {e}")

        return perms

    def _build_finding(self, bucket_info: dict, domain: str) -> dict:
        """Build a structured finding from bucket info."""
        perms = bucket_info.get("permissions", {})
        severity = "high" if perms.get("write") else "medium"
        perm_str = ", ".join(k for k, v in perms.items() if v)

        return {
            "title": f"Public Cloud Storage: {bucket_info['bucket_name']}",
            "severity": severity,
            "provider": bucket_info["provider"],
            "bucket_name": bucket_info["bucket_name"],
            "url": bucket_info["url"],
            "permissions": perms,
            "description": (
                f"A publicly accessible {bucket_info['provider'].upper()} "
                f"storage bucket was found: {bucket_info['url']}\n"
                f"Permissions confirmed: {perm_str or 'list'}\n"
                f"This could expose sensitive files, internal documents, "
                f"backup data, or application source code."
            ),
            "reproduction_steps": (
                f"1. curl '{bucket_info['url']}'\n"
                f"2. Review listed files for sensitive content\n"
                f"3. Attempt to read individual files to confirm impact"
            ),
            "ai_score": 8.0 if severity == "high" else 6.5,
        }

    async def _save_findings(self, findings: list[dict], program: str):
        """Persist cloud findings to database."""
        conn = get_conn(self.db_path)
        try:
            for finding in findings:
                finding_id = save_finding(
                    conn,
                    title=finding["title"],
                    severity=finding["severity"],
                    vuln_type="cloud_misconfiguration",
                    description=finding["description"],
                    reproduction_steps=finding["reproduction_steps"],
                    ai_score=finding["ai_score"],
                    program=program,
                )
                # Also save to cloud_assets table
                conn.execute("""
                    INSERT INTO cloud_assets
                    (domain, provider, asset_type, asset_name, is_public,
                     permissions, finding_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    program, finding["provider"],
                    "s3_bucket" if "s3" in finding["provider"] else "cloud_storage",
                    finding["bucket_name"],
                    1,
                    json.dumps(finding.get("permissions", {})),
                    finding_id,
                ))
            conn.commit()
        finally:
            conn.close()

    def _tool_installed(self, tool: str) -> bool:
        try:
            subprocess.run([tool, "--help"], capture_output=True)
            return True
        except FileNotFoundError:
            return False
