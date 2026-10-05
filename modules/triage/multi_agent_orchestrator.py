"""
BugFlow Elite v6 — Multi-Agent Orchestrator
Three specialized AI agents analyze every finding from different angles:
  Agent 1 (Attacker)   — exploitability, attack scenario, chaining potential
  Agent 2 (Defender)   — likelihood of false positive, impact minimization
  Agent 3 (Reporter)   — report quality, CVSS scoring, H1 acceptance likelihood
Final verdict = consensus across all three agents.
Tinlance Limited | LloydCoder
"""

import json
import logging
import asyncio
import aiohttp
from typing import Optional

logger = logging.getLogger(__name__)

# ── Agent Prompts ──────────────────────────────────────────────────────────

ATTACKER_PROMPT = """You are an expert offensive security researcher and bug bounty hunter.
Analyze this finding from an attacker's perspective.

Finding:
{finding_json}

Respond ONLY with valid JSON (no markdown):
{{
    "exploitability": 0.0,
    "attack_scenario": "realistic step-by-step attack",
    "chain_potential": ["list of other vulns this could chain with"],
    "real_world_impact": "what an attacker actually gains",
    "cvss_vector": "CVSS:3.1/AV:.../...",
    "cvss_score": 0.0,
    "attacker_verdict": "high_value|medium_value|low_value|false_positive"
}}"""

DEFENDER_PROMPT = """You are a senior security engineer doing triage for a bug bounty program.
Analyze this finding skeptically — look for reasons it might be invalid or low-impact.

Finding:
{finding_json}

Respond ONLY with valid JSON (no markdown):
{{
    "false_positive_probability": 0.0,
    "false_positive_reasons": [],
    "is_known_pattern": false,
    "is_likely_wont_fix": false,
    "wont_fix_reason": "",
    "actual_exploitability": "high|medium|low|none",
    "defender_verdict": "valid|likely_invalid|needs_more_evidence"
}}"""

REPORTER_PROMPT = """You are an expert bug bounty report writer who has submitted 500+ reports to HackerOne.
Evaluate this finding's report quality and H1 acceptance likelihood.

Finding:
{finding_json}

Respond ONLY with valid JSON (no markdown):
{{
    "report_quality_score": 0.0,
    "acceptance_likelihood": 0.0,
    "missing_elements": [],
    "suggested_title": "improved title for H1",
    "suggested_severity": "critical|high|medium|low",
    "report_improvements": [],
    "reporter_verdict": "submit|improve_first|do_not_submit"
}}"""


class MultiAgentOrchestrator:
    """
    Runs three specialized AI agents on each finding.
    Produces a consensus verdict that's more reliable than a single AI pass.
    Only findings where 2+ agents agree on value get recommended for H1 draft.
    """

    def __init__(self, config: dict):
        self.config = config
        self.ai_cfg = config.get("ai", {})

    async def run(self, finding: dict) -> dict:
        """
        Run all three agents concurrently and return consensus result.
        """
        finding_json = json.dumps(finding, indent=2)[:3000]  # Cap input

        logger.info(
            f"[MultiAgent] Analyzing: {finding.get('title', '')[:60]}"
        )

        # Run all three agents concurrently
        attacker_task = asyncio.create_task(
            self._run_agent("attacker", ATTACKER_PROMPT, finding_json)
        )
        defender_task = asyncio.create_task(
            self._run_agent("defender", DEFENDER_PROMPT, finding_json)
        )
        reporter_task = asyncio.create_task(
            self._run_agent("reporter", REPORTER_PROMPT, finding_json)
        )

        attacker, defender, reporter = await asyncio.gather(
            attacker_task, defender_task, reporter_task,
            return_exceptions=True
        )

        attacker = attacker if isinstance(attacker, dict) else {}
        defender = defender if isinstance(defender, dict) else {}
        reporter = reporter if isinstance(reporter, dict) else {}

        # ── Consensus Logic ────────────────────────────────────
        consensus = self._compute_consensus(attacker, defender, reporter)

        result = {
            "multi_agent_attacker":  attacker,
            "multi_agent_defender":  defender,
            "multi_agent_reporter":  reporter,
            "multi_agent_consensus": consensus,
        }

        # Enrich the finding with consensus data
        if consensus.get("final_verdict") == "submit":
            finding["recommend_draft"] = True
            finding["ai_score"] = max(
                float(finding.get("ai_score", 0)),
                consensus.get("consensus_score", 7.0)
            )
        elif consensus.get("final_verdict") == "do_not_submit":
            finding["recommend_draft"] = False
            finding["is_duplicate"] = (
                finding.get("is_duplicate", False) or
                defender.get("is_known_pattern", False)
            )

        # Use reporter's improved title if available
        if reporter.get("suggested_title"):
            finding["title"] = reporter["suggested_title"]

        # Use reporter's suggested severity if it's higher
        sev_order = ["info", "low", "medium", "high", "critical"]
        current_sev = finding.get("severity", "info")
        suggested_sev = reporter.get("suggested_severity", current_sev)
        if (sev_order.index(suggested_sev) >
                sev_order.index(current_sev)):
            finding["severity"] = suggested_sev

        # Store multi-agent analysis
        finding["multi_agent_analysis"] = json.dumps(result)

        logger.info(
            f"[MultiAgent] Verdict: {consensus.get('final_verdict')} "
            f"(score: {consensus.get('consensus_score', 0):.1f})"
        )
        return finding

    def _compute_consensus(
        self,
        attacker: dict,
        defender: dict,
        reporter: dict
    ) -> dict:
        """
        Compute consensus verdict from three agent outputs.
        2 out of 3 agents must agree for a strong recommendation.
        """
        verdicts = {
            "attacker": attacker.get("attacker_verdict", ""),
            "defender": defender.get("defender_verdict", ""),
            "reporter": reporter.get("reporter_verdict", ""),
        }

        # Score each verdict
        attacker_score = {
            "high_value":   9.0,
            "medium_value": 6.0,
            "low_value":    3.0,
            "false_positive": 0.0,
        }.get(verdicts["attacker"], 5.0)

        defender_score = {
            "valid":              1.0,  # multiplier
            "needs_more_evidence": 0.7,
            "likely_invalid":     0.2,
        }.get(verdicts["defender"], 0.5)

        reporter_score = {
            "submit":         1.0,
            "improve_first":  0.7,
            "do_not_submit":  0.0,
        }.get(verdicts["reporter"], 0.5)

        # False positive probability from defender
        fp_prob = float(defender.get("false_positive_probability", 0.3))
        acceptance = float(reporter.get("acceptance_likelihood", 0.5))

        # Weighted consensus score
        consensus_score = (
            attacker_score * 0.4 *
            defender_score * (1 - fp_prob) +
            acceptance * 10 * 0.2
        )

        # Final verdict
        if (
            verdicts["attacker"] in ("high_value", "medium_value") and
            verdicts["defender"] == "valid" and
            verdicts["reporter"] in ("submit", "improve_first") and
            fp_prob < 0.4
        ):
            final_verdict = "submit"
        elif (
            verdicts["attacker"] == "false_positive" or
            verdicts["defender"] == "likely_invalid" or
            verdicts["reporter"] == "do_not_submit" or
            fp_prob > 0.7
        ):
            final_verdict = "do_not_submit"
        else:
            final_verdict = "improve_first"

        return {
            "final_verdict":    final_verdict,
            "consensus_score":  min(consensus_score, 10.0),
            "agent_verdicts":   verdicts,
            "fp_probability":   fp_prob,
            "acceptance_likelihood": acceptance,
            "missing_elements": reporter.get("missing_elements", []),
            "improvements":     reporter.get("report_improvements", []),
        }

    async def _run_agent(
        self, agent_name: str, prompt_template: str, finding_json: str
    ) -> Optional[dict]:
        """Run a single agent with the given prompt."""
        prompt = prompt_template.format(finding_json=finding_json)

        # Try providers in order
        providers = [
            ("ollama", self._call_ollama),
            ("grok",   self._call_grok),
            ("claude", self._call_claude),
        ]
        for name, fn in providers:
            try:
                result = await fn(prompt)
                if result:
                    logger.debug(
                        f"[MultiAgent:{agent_name}] Completed via {name}"
                    )
                    return result
            except Exception as e:
                logger.debug(
                    f"[MultiAgent:{agent_name}] {name} failed: {e}"
                )
        return {}

    async def _call_ollama(self, prompt: str) -> Optional[dict]:
        cfg = self.ai_cfg.get("primary", {})
        if cfg.get("provider") != "ollama":
            return None
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{cfg.get('base_url', 'http://ollama:11434')}/api/generate",
                    json={
                        "model": cfg.get("model", "llama3.2-vision:11b"),
                        "prompt": prompt,
                        "stream": False,
                        "options": {"temperature": 0.1},
                    },
                    timeout=aiohttp.ClientTimeout(total=120)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return self._parse(data.get("response", ""))
        except Exception:
            pass
        return None

    async def _call_grok(self, prompt: str) -> Optional[dict]:
        cfg = self.ai_cfg.get("fallback", {})
        if not cfg.get("api_key"):
            return None
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{cfg.get('base_url', 'https://api.x.ai/v1')}/chat/completions",
                    json={
                        "model": cfg.get("model", "grok-3"),
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.1,
                    },
                    headers={"Authorization": f"Bearer {cfg['api_key']}"},
                    timeout=aiohttp.ClientTimeout(total=60)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return self._parse(
                            data["choices"][0]["message"]["content"]
                        )
        except Exception:
            pass
        return None

    async def _call_claude(self, prompt: str) -> Optional[dict]:
        cfg = self.ai_cfg.get("secondary_fallback", {})
        if not cfg.get("api_key"):
            return None
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://api.anthropic.com/v1/messages",
                    json={
                        "model": cfg.get("model", "claude-haiku-4-5-20251001"),
                        "max_tokens": 1000,
                        "messages": [{"role": "user", "content": prompt}],
                    },
                    headers={
                        "x-api-key": cfg["api_key"],
                        "anthropic-version": "2023-06-01",
                    },
                    timeout=aiohttp.ClientTimeout(total=60)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return self._parse(data["content"][0]["text"])
        except Exception:
            pass
        return None

    def _parse(self, text: str) -> Optional[dict]:
        """Parse JSON from AI response."""
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
        return {}
