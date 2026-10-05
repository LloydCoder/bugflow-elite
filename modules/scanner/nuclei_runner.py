"""
BugFlow Elite v6 — Nuclei Scanner Module
Runs Nuclei with curated templates + generates custom templates via AI.
Custom templates target tech stack fingerprinted during recon.
Tinlance Limited | LloydCoder
"""

import json
import logging
import asyncio
import aiohttp
import subprocess
import tempfile
import os
from pathlib import Path
from typing import Optional
from modules.scope.scope_enforcer import ScopeEnforcer
from db.models import get_conn, save_finding

logger = logging.getLogger(__name__)

# Template categories with highest bug bounty ROI
HIGH_VALUE_TEMPLATES = [
    "cves/",
    "vulnerabilities/",
    "exposures/",
    "misconfiguration/",
    "takeovers/",
    "default-logins/",
    "exposed-panels/",
    "technologies/",
]

CUSTOM_TEMPLATE_PROMPT = """You are an expert security researcher.
Generate a Nuclei YAML template to detect: {vuln_description}

Target tech stack: {tech_stack}
Target endpoint pattern: {endpoint_pattern}

Rules:
- Use passive matchers only (no write/modify operations)
- Include multiple matchers for accuracy (reduce false positives)
- Set appropriate severity
- Include clear name, description, and reference
- Follow Nuclei v3 YAML format exactly

Respond ONLY with valid YAML, no markdown fences, no preamble."""


class NucleiRunner:
    """
    Nuclei v3 scanner with dynamic custom template generation.
    AI generates templates based on discovered tech stack and endpoints.
    """

    def __init__(self, config: dict, scope: ScopeEnforcer):
        self.config = config
        self.scope = scope
        self.db_path = config.get("general", {}).get("db_path", "./db/bugflow.db")
        self.nuclei_cfg = config.get("scanner", {}).get("nuclei", {})
        self.ai_cfg = config.get("ai", {})
        self.templates_dir = Path(self.nuclei_cfg.get("templates_dir", "./nuclei-templates"))
        self.custom_dir = Path(self.nuclei_cfg.get("custom_templates_dir", "./custom-templates"))
        self.custom_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir = Path("./output/nuclei")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def run(
        self,
        targets: list[str],
        program: str = "",
        tech_context: dict = None
    ) -> list[dict]:
        """
        Full Nuclei scan:
        1. Update templates
        2. Generate custom templates if tech stack known
        3. Run Nuclei against all in-scope targets
        4. Parse and return findings
        """
        if not targets:
            return []

        # Scope filter
        targets = self.scope.filter_in_scope(targets)
        if not targets:
            logger.warning("[Nuclei] No in-scope targets after filtering")
            return []

        if not self._nuclei_installed():
            logger.warning("[Nuclei] Not installed — skipping")
            return []

        # Update templates
        if self.nuclei_cfg.get("update_templates"):
            await self._update_templates()

        # Generate custom templates if we have tech context
        if tech_context and self.nuclei_cfg.get("auto_generate_templates"):
            await self._generate_custom_templates(tech_context)

        # Write targets to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            for t in targets:
                url = t if t.startswith("http") else f"https://{t}"
                f.write(url + "\n")
            targets_file = f.name

        output_file = self.output_dir / f"nuclei_{program.replace('.', '_')}.json"

        cmd = self._build_command(targets_file, str(output_file))
        findings = []

        try:
            logger.info(f"[Nuclei] Scanning {len(targets)} targets")
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=3600)
            if stderr:
                logger.debug(f"[Nuclei] stderr: {stderr.decode()[:200]}")

            findings = self._parse_output(output_file, program)
            logger.info(f"[Nuclei] Found {len(findings)} findings")

        except asyncio.TimeoutError:
            logger.warning("[Nuclei] Scan timed out (1h limit)")
        except Exception as e:
            logger.error(f"[Nuclei] Error: {e}")
        finally:
            os.unlink(targets_file)

        return findings

    def _build_command(self, targets_file: str, output_file: str) -> list[str]:
        """Build the Nuclei CLI command."""
        cfg = self.nuclei_cfg
        cmd = [
            "nuclei",
            "-l", targets_file,
            "-o", output_file,
            "-json",
            "-silent",
            "-severity", cfg.get("severity", "low,medium,high,critical"),
            "-rate-limit", str(cfg.get("rate_limit", 20)),
            "-bulk-size", str(cfg.get("bulk_size", 25)),
            "-concurrency", str(cfg.get("concurrency", 10)),
            "-timeout", "10",
            "-retries", "1",
        ]
        # Add custom templates directory
        if self.custom_dir.exists() and any(self.custom_dir.iterdir()):
            cmd += ["-t", str(self.custom_dir)]

        # Only include high-value template categories (faster)
        for tmpl in HIGH_VALUE_TEMPLATES:
            if self.templates_dir.exists():
                full_path = self.templates_dir / tmpl
                if full_path.exists():
                    cmd += ["-t", str(full_path)]

        return cmd

    def _parse_output(self, output_file: Path, program: str) -> list[dict]:
        """Parse Nuclei JSON output into structured findings."""
        findings = []
        if not output_file.exists():
            return findings

        with open(output_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    result = json.loads(line)
                    info = result.get("info", {})
                    severity = info.get("severity", "info").lower()
                    # Skip info unless it's a juicy exposure
                    if severity == "info" and "exposure" not in result.get("template-id", ""):
                        continue
                    findings.append({
                        "title":              info.get("name", "Nuclei Finding"),
                        "severity":           severity,
                        "vuln_type":          "nuclei",
                        "target":             result.get("host", ""),
                        "template_id":        result.get("template-id", ""),
                        "description":        info.get("description", ""),
                        "proof_of_concept":   json.dumps({
                            "matched_at":         result.get("matched-at", ""),
                            "extracted_results":  result.get("extracted-results", []),
                            "request":            result.get("request", "")[:500],
                            "response":           result.get("response", "")[:500],
                        }),
                        "cvss_score":         info.get("classification", {}).get("cvss-score"),
                        "cve_id":             ", ".join(
                            info.get("classification", {}).get("cve-id", [])
                        ),
                        "program":            program,
                        "tool":               "nuclei",
                    })
                except json.JSONDecodeError:
                    pass

        return findings

    async def _update_templates(self):
        """Update Nuclei templates in the background."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "nuclei", "-update-templates", "-silent",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await asyncio.wait_for(proc.communicate(), timeout=120)
            logger.debug("[Nuclei] Templates updated")
        except Exception as e:
            logger.debug(f"[Nuclei] Template update error: {e}")

    async def _generate_custom_templates(self, tech_context: dict):
        """
        Use AI to generate custom Nuclei templates for the discovered tech stack.
        Only generates if we have specific tech + endpoint context.
        """
        tech_stack = tech_context.get("technologies", [])
        endpoints = tech_context.get("interesting_endpoints", [])

        if not tech_stack and not endpoints:
            return

        # Build generation targets from context
        targets_to_generate = []
        for tech in tech_stack[:5]:  # Cap at 5 custom templates per run
            targets_to_generate.append({
                "description": f"Security misconfiguration or default credentials for {tech}",
                "tech": tech,
                "endpoint": "",
            })
        for endpoint in endpoints[:3]:
            targets_to_generate.append({
                "description": f"Parameter-based vulnerability at {endpoint}",
                "tech": ", ".join(tech_stack[:3]),
                "endpoint": endpoint,
            })

        for target in targets_to_generate:
            template_yaml = await self._call_ai_for_template(target)
            if template_yaml:
                template_name = target["tech"].lower().replace(" ", "_").replace("/", "_")
                template_file = self.custom_dir / f"custom_{template_name}.yaml"
                if not template_file.exists():  # Don't overwrite existing
                    with open(template_file, "w") as f:
                        f.write(template_yaml)
                    logger.info(f"[Nuclei] Generated custom template: {template_file.name}")

    async def _call_ai_for_template(self, target: dict) -> Optional[str]:
        """Call AI to generate a Nuclei template YAML."""
        prompt = CUSTOM_TEMPLATE_PROMPT.format(
            vuln_description=target["description"],
            tech_stack=target["tech"],
            endpoint_pattern=target.get("endpoint", "generic"),
        )

        ai_cfg_primary = self.ai_cfg.get("primary", {})
        base_url = ai_cfg_primary.get("base_url", "http://ollama:11434")
        model = ai_cfg_primary.get("model", "llama3.2-vision:11b")

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{base_url}/api/generate",
                    json={"model": model, "prompt": prompt, "stream": False},
                    timeout=aiohttp.ClientTimeout(total=60)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        yaml_content = data.get("response", "").strip()
                        # Basic validation — must look like a Nuclei template
                        if "id:" in yaml_content and "requests:" in yaml_content:
                            return yaml_content
        except Exception as e:
            logger.debug(f"[Nuclei AI] Template generation error: {e}")

        return None

    def _nuclei_installed(self) -> bool:
        try:
            subprocess.run(["nuclei", "-version"], capture_output=True, check=True)
            return True
        except (FileNotFoundError, subprocess.CalledProcessError):
            return False
