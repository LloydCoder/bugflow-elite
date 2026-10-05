"""
BugFlow Elite v6 — AI Report Polisher
Rewrites and improves H1 draft reports before submission.
Scores report quality, fills missing sections, improves language,
adds CVSS vectors, strengthens impact statements.
Target: >85% acceptance rate on submitted reports.
Tinlance Limited | LloydCoder
"""

import json
import logging
import aiohttp
from typing import Optional

logger = logging.getLogger(__name__)

POLISH_PROMPT = """You are a world-class bug bounty report writer with a 90%+ acceptance rate on HackerOne.
Your job is to rewrite and improve the following security finding report.

ORIGINAL FINDING:
{finding_json}

MULTI-AGENT ANALYSIS:
{multi_agent_json}

Rules:
- Write for a triage engineer who needs to understand and reproduce this in 5 minutes
- Be specific and technical — no vague language
- Include exact HTTP requests/responses where possible
- Make the impact statement concrete (data at risk, accounts affected, revenue impact)
- Add CVSS 3.1 vector string if missing
- Add MITRE ATT&CK TTPs if relevant
- Keep Summary under 200 words
- Steps to Reproduce must be numbered and exact
- Impact must include business consequence, not just technical
- Never exaggerate severity — triagers will downgrade overhyped reports

Respond ONLY with valid JSON (no markdown):
{{
    "polished_title": "...",
    "polished_summary": "...",
    "polished_steps": "1. ...\\n2. ...\\n3. ...",
    "polished_impact": "...",
    "cvss_vector": "CVSS:3.1/AV:.../...",
    "cvss_score": 0.0,
    "recommended_severity": "critical|high|medium|low",
    "mitre_ttps": [],
    "quality_score": 0.0,
    "acceptance_probability": 0.0,
    "reviewer_notes": "what a triage engineer will think when they read this"
}}"""


class AIReportPolisher:
    """
    Final AI pass before H1 draft creation.
    Takes a raw finding + multi-agent analysis and produces
    a polished, professional, submission-ready report.
    """

    def __init__(self, config: dict):
        self.config = config
        self.ai_cfg = config.get("ai", {})
        self.min_quality = 0.65  # Don't submit below this quality score

    async def polish(self, finding: dict) -> dict:
        """
        Polish a finding's report content.
        Returns enriched finding with polished_* fields.
        """
        finding = dict(finding)

        # Don't polish info/low unless explicitly enabled
        severity = finding.get("severity", "info")
        if severity in ("info", "low"):
            finding["polished"] = False
            return finding

        logger.info(
            f"[Polisher] Polishing report: {finding.get('title', '')[:60]}"
        )

        finding_json = json.dumps({
            "title": finding.get("title", ""),
            "severity": finding.get("severity", ""),
            "vuln_type": finding.get("vuln_type", ""),
            "target": finding.get("target", ""),
            "description": finding.get("description", ""),
            "reproduction_steps": finding.get("reproduction_steps", ""),
            "proof_of_concept": finding.get("proof_of_concept", ""),
            "ai_analysis": finding.get("ai_analysis", ""),
        }, indent=2)[:2500]

        multi_agent_json = json.dumps(
            json.loads(finding.get("multi_agent_analysis", "{}"))
            .get("multi_agent_consensus", {}),
            indent=2
        )[:1000]

        prompt = POLISH_PROMPT.format(
            finding_json=finding_json,
            multi_agent_json=multi_agent_json,
        )

        polished = await self._call_ai(prompt)

        if polished:
            # Apply polished content
            if polished.get("polished_title"):
                finding["title"] = polished["polished_title"]
            if polished.get("polished_summary"):
                finding["description"] = polished["polished_summary"]
            if polished.get("polished_steps"):
                finding["reproduction_steps"] = polished["polished_steps"]
            if polished.get("polished_impact"):
                finding["impact"] = polished["polished_impact"]
            if polished.get("cvss_score"):
                finding["cvss_score"] = polished["cvss_score"]
            if polished.get("cvss_vector"):
                finding["cvss_vector"] = polished["cvss_vector"]
            if polished.get("mitre_ttps"):
                finding["mitre_ttps"] = json.dumps(polished["mitre_ttps"])
            if polished.get("recommended_severity"):
                finding["severity"] = polished["recommended_severity"]

            quality = float(polished.get("quality_score", 0))
            acceptance = float(polished.get("acceptance_probability", 0))

            finding["report_quality_score"] = quality
            finding["acceptance_probability"] = acceptance
            finding["polished"] = True
            finding["polished_data"] = json.dumps(polished)

            # Block draft if quality too low
            if quality < self.min_quality:
                finding["recommend_draft"] = False
                finding["block_reason"] = (
                    f"Report quality {quality:.2f} below threshold "
                    f"{self.min_quality:.2f}. "
                    f"Missing: {polished.get('reviewer_notes', '')}"
                )
                logger.warning(
                    f"[Polisher] Draft blocked — quality too low: "
                    f"{quality:.2f}"
                )
            else:
                logger.info(
                    f"[Polisher] Report ready — quality: {quality:.2f}, "
                    f"acceptance: {acceptance:.2f}"
                )
        else:
            finding["polished"] = False
            logger.warning("[Polisher] AI returned no result — using raw finding")

        return finding

    async def _call_ai(self, prompt: str) -> Optional[dict]:
        """Try AI providers in order."""
        providers = [
            ("ollama", self._call_ollama),
            ("grok",   self._call_grok),
            ("claude", self._call_claude),
        ]
        for name, fn in providers:
            try:
                result = await fn(prompt)
                if result:
                    return result
            except Exception as e:
                logger.debug(f"[Polisher] {name} failed: {e}")
        return None

    async def _call_ollama(self, prompt: str) -> Optional[dict]:
        cfg = self.ai_cfg.get("primary", {})
        if cfg.get("provider") != "ollama":
            return None
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{cfg.get('base_url', 'http://ollama:11434')}/api/generate",
                json={
                    "model": cfg.get("model", "llama3.2-vision:11b"),
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.05},
                },
                timeout=aiohttp.ClientTimeout(total=180)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return self._parse(data.get("response", ""))
        return None

    async def _call_grok(self, prompt: str) -> Optional[dict]:
        cfg = self.ai_cfg.get("fallback", {})
        if not cfg.get("api_key"):
            return None
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{cfg.get('base_url', 'https://api.x.ai/v1')}/chat/completions",
                json={
                    "model": cfg.get("model", "grok-3"),
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.05,
                },
                headers={"Authorization": f"Bearer {cfg['api_key']}"},
                timeout=aiohttp.ClientTimeout(total=90)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return self._parse(
                        data["choices"][0]["message"]["content"]
                    )
        return None

    async def _call_claude(self, prompt: str) -> Optional[dict]:
        cfg = self.ai_cfg.get("secondary_fallback", {})
        if not cfg.get("api_key"):
            return None
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://api.anthropic.com/v1/messages",
                json={
                    "model": cfg.get("model", "claude-haiku-4-5-20251001"),
                    "max_tokens": 1500,
                    "messages": [{"role": "user", "content": prompt}],
                },
                headers={
                    "x-api-key": cfg["api_key"],
                    "anthropic-version": "2023-06-01",
                },
                timeout=aiohttp.ClientTimeout(total=90)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return self._parse(data["content"][0]["text"])
        return None

    def _parse(self, text: str) -> Optional[dict]:
        if not text:
            return None
        text = text.strip()
        if "```" in text:
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        text = text.strip().rstrip("`").strip()
        try:
            return json.loads(text)
        except Exception:
            import re
            m = re.search(r'\{.*\}', text, re.DOTALL)
            if m:
                try:
                    return json.loads(m.group())
                except Exception:
                    pass
        return None
