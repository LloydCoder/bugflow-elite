"""
BugFlow Elite v6 — GitHub Org Scanner
When a target's GitHub org is found, scans all public repos for:
- Leaked secrets (API keys, tokens, passwords)
- Hardcoded credentials
- Sensitive file exposure (.env, config files)
- Exposed internal tooling, infrastructure code
Uses: TruffleHog + GitHound + direct GitHub API
Tinlance Limited | LloydCoder
"""

import json
import logging
import asyncio
import aiohttp
import subprocess
from pathlib import Path
from typing import Optional
from modules.scope.scope_enforcer import ScopeEnforcer
from db.models import get_conn

logger = logging.getLogger(__name__)

# File patterns that indicate sensitive content
SENSITIVE_FILES = [
    ".env", ".env.local", ".env.production", ".env.staging",
    "config.json", "secrets.json", "credentials.json",
    "database.yml", "database.yaml", "config/database.yml",
    "wp-config.php", "settings.py", "local_settings.py",
    ".aws/credentials", ".ssh/id_rsa", "id_rsa",
    "docker-compose.yml", "docker-compose.override.yml",
    "terraform.tfvars", "*.tfvars",
    "Dockerfile", ".dockerenv",
    "application.properties", "application.yml",
]

# Keywords that indicate sensitive content in repo names/descriptions
SENSITIVE_REPO_KEYWORDS = [
    "internal", "private", "secret", "credentials", "infra",
    "infrastructure", "deploy", "deployment", "backup", "database",
    "config", "configuration", "admin", "ops", "devops",
]


class GitHubOrgScanner:
    """
    Discovers and scans a target company's GitHub organization
    for leaked credentials and sensitive information.
    """

    def __init__(self, config: dict, scope: ScopeEnforcer):
        self.config = config
        self.scope = scope
        self.db_path = config.get("general", {}).get("db_path", "./db/bugflow.db")
        self.github_token = (
            config.get("recon", {}).get("bbot", {})
            .get("api_keys", {}).get("github", "")
        )
        self.output_dir = Path("./output/github")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def run(self, domain: str, program: str = "") -> list[dict]:
        """
        Full GitHub org scan pipeline for a domain.
        1. Find GitHub org for the domain
        2. List all public repos
        3. Scan for secrets and sensitive files
        4. Return structured findings
        """
        self.scope.assert_in_scope(domain)

        if not self.github_token:
            logger.warning("[GitHub] No GITHUB_TOKEN — limited to public API rate limit")

        logger.info(f"[GitHub] Starting org scan for {domain}")

        # Find GitHub org
        org_name = await self._find_org(domain)
        if not org_name:
            logger.info(f"[GitHub] No GitHub org found for {domain}")
            return []

        logger.info(f"[GitHub] Found org: {org_name}")

        # Get all repos
        repos = await self._list_repos(org_name)
        logger.info(f"[GitHub] Found {len(repos)} public repos")

        findings = []

        # Scan each repo
        for repo in repos[:50]:  # Cap at 50 repos
            repo_name = repo.get("name", "")
            repo_findings = await self._scan_repo(
                org_name, repo_name, repo, domain
            )
            findings.extend(repo_findings)
            await asyncio.sleep(0.5)  # Rate limit

        if findings:
            await self._save_findings(findings, program)
            logger.info(f"[GitHub] Found {len(findings)} potential issues")

        return findings

    async def _find_org(self, domain: str) -> Optional[str]:
        """
        Try to find the GitHub org associated with a domain.
        Checks: GitHub search, common org name patterns.
        """
        # Extract company name from domain
        company = domain.split(".")[0]
        candidates = [
            company,
            company.replace("-", ""),
            company + "-inc",
            company + "-hq",
            company + "hq",
        ]

        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"

        async with aiohttp.ClientSession(headers=headers) as session:
            for candidate in candidates:
                try:
                    async with session.get(
                        f"https://api.github.com/orgs/{candidate}",
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            # Verify it's related to the domain
                            blog = data.get("blog", "")
                            email = data.get("email", "")
                            if (domain in blog or domain in email or
                                    company.lower() in data.get("login", "").lower()):
                                return data["login"]
                except Exception:
                    continue

            # Try GitHub search as fallback
            try:
                async with session.get(
                    "https://api.github.com/search/users",
                    params={"q": f"{company} type:org", "per_page": 5},
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        items = data.get("items", [])
                        for item in items:
                            login = item.get("login", "").lower()
                            if company.lower() in login:
                                return item["login"]
            except Exception:
                pass

        return None

    async def _list_repos(self, org_name: str) -> list[dict]:
        """List all public repos for a GitHub org."""
        repos = []
        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"

        page = 1
        async with aiohttp.ClientSession(headers=headers) as session:
            while page <= 10:  # Max 10 pages = 1000 repos
                try:
                    async with session.get(
                        f"https://api.github.com/orgs/{org_name}/repos",
                        params={"per_page": 100, "page": page, "type": "public"},
                        timeout=aiohttp.ClientTimeout(total=15)
                    ) as resp:
                        if resp.status != 200:
                            break
                        page_repos = await resp.json()
                        if not page_repos:
                            break
                        repos.extend(page_repos)
                        page += 1
                except Exception:
                    break

        return repos

    async def _scan_repo(
        self, org: str, repo: str, repo_data: dict, domain: str
    ) -> list[dict]:
        """Scan a single repository for secrets and sensitive files."""
        findings = []

        # Check if repo name/description suggests sensitivity
        is_sensitive_repo = self._is_sensitive_repo(repo_data)

        # Method 1: Check default branch for sensitive files via GitHub API
        file_findings = await self._check_sensitive_files(org, repo, domain)
        findings.extend(file_findings)

        # Method 2: Run TruffleHog on the repo (if installed)
        if self._tool_installed("trufflehog"):
            trufflehog_findings = await self._run_trufflehog_on_repo(
                org, repo, domain
            )
            findings.extend(trufflehog_findings)

        # Flag sensitive-looking repos even without secrets
        if is_sensitive_repo and not findings:
            findings.append({
                "title": f"Sensitive GitHub Repo: {org}/{repo}",
                "severity": "info",
                "vuln_type": "github_recon",
                "target": f"https://github.com/{org}/{repo}",
                "description": (
                    f"Repository {org}/{repo} has a sensitive-sounding name "
                    f"or description that may warrant manual review.\n"
                    f"Description: {repo_data.get('description', 'N/A')}"
                ),
                "ai_score": 3.0,
                "tool": "github_scanner",
                "program": domain,
            })

        return findings

    async def _check_sensitive_files(
        self, org: str, repo: str, domain: str
    ) -> list[dict]:
        """Check if sensitive files exist in the repo's default branch."""
        findings = []
        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"

        default_branch = "main"  # Try main first, then master
        for branch in ["main", "master"]:
            async with aiohttp.ClientSession(headers=headers) as session:
                for fname in SENSITIVE_FILES[:10]:  # Cap checks per repo
                    try:
                        async with session.get(
                            f"https://api.github.com/repos/{org}/{repo}/contents/{fname}",
                            params={"ref": branch},
                            timeout=aiohttp.ClientTimeout(total=8)
                        ) as resp:
                            if resp.status == 200:
                                data = await resp.json()
                                findings.append({
                                    "title": f"Sensitive File Exposed: {org}/{repo}/{fname}",
                                    "severity": "high",
                                    "vuln_type": "github_sensitive_file",
                                    "target": data.get("html_url", ""),
                                    "description": (
                                        f"Sensitive file `{fname}` found in public repo "
                                        f"{org}/{repo} (branch: {branch}).\n"
                                        f"File URL: {data.get('html_url', '')}\n"
                                        f"Size: {data.get('size', 0)} bytes"
                                    ),
                                    "reproduction_steps": (
                                        f"1. Visit: {data.get('html_url', '')}\n"
                                        f"2. Download raw content\n"
                                        f"3. Check for credentials, API keys, or config data"
                                    ),
                                    "ai_score": 7.5,
                                    "tool": "github_scanner",
                                    "program": domain,
                                })
                    except Exception:
                        pass

        return findings

    async def _run_trufflehog_on_repo(
        self, org: str, repo: str, domain: str
    ) -> list[dict]:
        """Run TruffleHog on a GitHub repository."""
        output_file = self.output_dir / f"{org}_{repo}_trufflehog.json"
        repo_url = f"https://github.com/{org}/{repo}"
        findings = []

        cmd = [
            "trufflehog", "github",
            "--repo", repo_url,
            "--json",
            "--no-verification",
        ]
        if self.github_token:
            cmd += ["--token", self.github_token]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=120
            )
            for line in stdout.decode().split("\n"):
                if not line.strip():
                    continue
                try:
                    result = json.loads(line)
                    secret_type = result.get("DetectorName", "Unknown")
                    findings.append({
                        "title": f"Leaked {secret_type}: {org}/{repo}",
                        "severity": "high",
                        "vuln_type": "secret",
                        "target": repo_url,
                        "description": (
                            f"TruffleHog detected a potential {secret_type} "
                            f"in GitHub repo {org}/{repo}.\n"
                            f"Source: {result.get('SourceMetadata', {})}"
                        ),
                        "proof_of_concept": json.dumps({
                            "detector": secret_type,
                            "verified": result.get("Verified", False),
                            "raw": str(result.get("Raw", ""))[:100],
                        }),
                        "ai_score": 8.0 if result.get("Verified") else 6.0,
                        "tool": "trufflehog_github",
                        "program": domain,
                    })
                except json.JSONDecodeError:
                    pass
        except asyncio.TimeoutError:
            logger.debug(f"[GitHub] TruffleHog timeout on {org}/{repo}")
        except Exception as e:
            logger.debug(f"[GitHub] TruffleHog error: {e}")

        return findings

    def _is_sensitive_repo(self, repo_data: dict) -> bool:
        """Check if a repo name/description suggests sensitive content."""
        name = repo_data.get("name", "").lower()
        desc = (repo_data.get("description") or "").lower()
        combined = name + " " + desc
        return any(kw in combined for kw in SENSITIVE_REPO_KEYWORDS)

    def _tool_installed(self, tool: str) -> bool:
        try:
            subprocess.run([tool, "--version"], capture_output=True)
            return True
        except FileNotFoundError:
            return False

    async def _save_findings(self, findings: list[dict], program: str):
        """Save GitHub findings to database."""
        from db.models import save_finding
        conn = get_conn(self.db_path)
        try:
            for f in findings:
                save_finding(
                    conn,
                    title=f.get("title", ""),
                    severity=f.get("severity", "info"),
                    vuln_type=f.get("vuln_type", "github_recon"),
                    target=f.get("target", ""),
                    description=f.get("description", ""),
                    reproduction_steps=f.get("reproduction_steps", ""),
                    proof_of_concept=f.get("proof_of_concept", ""),
                    ai_score=f.get("ai_score", 5.0),
                    program=program,
                )
            conn.commit()
        finally:
            conn.close()
