"""
BugFlow Elite v6 — Agentic Orchestrator
Higher-level autonomous agent that coordinates the full triage pipeline.
Unlike the MultiAgentOrchestrator (which runs 3 agents in parallel on ONE
finding), the AgenticOrchestrator runs an autonomous LOOP:
  - Decides what action to take next based on finding state
  - Calls tools (verify, chain, polish, draft) in the right order
  - Retries on failure with different strategies
  - Stops when it has enough confidence or exhausts attempts
This is the "brain" that connects all triage modules together.
Tinlance Limited | LloydCoder
"""

import json
import logging
import asyncio
import aiohttp
from typing import Optional
from modules.triage.verification_engine import VerificationEngine
from modules.triage.multi_agent_orchestrator import MultiAgentOrchestrator
from modules.reports.ai_report_polisher import AIReportPolisher

logger = logging.getLogger(__name__)

# Agent actions the orchestrator can take
ACTIONS = [
    "verify",           # Run verification engine
    "multi_agent",      # Run multi-agent analysis
    "gather_evidence",  # Request more evidence from tools
    "polish_report",    # Polish the report
    "approve_draft",    # Approve for H1 draft
    "reject",           # Reject finding
    "escalate",         # Escalate severity
    "request_chain",    # Ask exploit chainer to find chains
]

DECISION_PROMPT = """You are an autonomous security triage agent for a bug bounty program.
Your job is to decide the next best action for this finding.

Current finding state:
{state_json}

Actions taken so far: {actions_taken}
Current confidence: {confidence}
Current recommendation: {recommendation}

Available actions: {available_actions}

Rules:
- If confidence >= 0.85 and recommendation is positive -> approve_draft
- If confidence < 0.3 or finding looks like false positive -> reject
- If severity is critical/high and not yet multi-agent analyzed -> multi_agent
- If evidence is weak -> gather_evidence
- If recommend_draft is True but not polished -> polish_report
- If vuln_type suggests chaining potential (ssrf, xss, idor) -> request_chain
- Maximum 5 actions before final decision

Respond ONLY with valid JSON (no markdown):
{{
    "action": "one of the available actions",
    "reasoning": "why this action",
    "expected_outcome": "what this action should achieve",
    "confidence_after": 0.0
}}"""


class AgenticOrchestrator:
    """
    Autonomous agent loop for triage pipeline coordination.
    Decides action sequence per finding, not just running fixed steps.
    """

    def __init__(self, config: dict, scope):
        self.config = config
        self.scope = scope
        self.ai_cfg = config.get("ai", {})
        self.verifier = VerificationEngine(config, scope)
        self.multi_agent = MultiAgentOrchestrator(config)
        self.polisher = AIReportPolisher(config)
        self.max_actions = 5

    async def run(self, finding: dict) -> dict:
        """
        Run the agentic loop for a single finding.
        Returns fully processed finding with final triage decision.
        """
        finding = dict(finding)
        actions_taken = []
        confidence = float(finding.get("confidence", 0.5))
        max_iterations = self.max_actions

        logger.info(
            f"[AgenticOrchestrator] Starting agent loop: "
            f"{finding.get('title', '')[:50]}"
        )

        for iteration in range(max_iterations):
            # Decide next action
            action_result = await self._decide_action(
                finding, actions_taken, confidence
            )
            if not action_result:
                break

            action = action_result.get("action", "")
            reasoning = action_result.get("reasoning", "")

            if not action or action in actions_taken:
                break

            logger.debug(
                f"[AgenticOrchestrator] Iteration {iteration+1}: "
                f"{action} — {reasoning[:60]}"
            )

            # Execute the action
            finding, confidence = await self._execute_action(
                action, finding, confidence
            )
            actions_taken.append(action)

            # Check terminal conditions
            if action in ("approve_draft", "reject"):
                break
            if confidence >= 0.90:
                finding["recommend_draft"] = True
                break
            if confidence < 0.15:
                finding["recommend_draft"] = False
                break

        # Final decision
        finding["agentic_actions_taken"] = actions_taken
        finding["agentic_confidence"] = confidence
        finding["agentic_complete"] = True

        logger.info(
            f"[AgenticOrchestrator] Complete after {len(actions_taken)} actions. "
            f"Confidence: {confidence:.2f} | "
            f"Draft: {finding.get('recommend_draft', False)}"
        )
        return finding

    async def _decide_action(
        self,
        finding: dict,
        actions_taken: list,
        confidence: float,
    ) -> Optional[dict]:
        """Ask AI to decide the next action."""

        # Fast-path rules before calling AI (saves tokens)
        severity = finding.get("severity", "info")
        vuln_type = finding.get("vuln_type", "")
        recommend = finding.get("recommend_draft", False)
        is_duplicate = finding.get("is_duplicate", False)

        # Hard reject conditions
        if is_duplicate:
            return {"action": "reject", "reasoning": "Duplicate finding"}
        if severity == "info" and "verify" not in actions_taken:
            return {"action": "verify", "reasoning": "Info findings need verification"}

        # If not verified yet, always verify first
        if "verify" not in actions_taken:
            return {"action": "verify", "reasoning": "Always verify first"}

        # High value + not multi-agent analyzed
        if (severity in ("critical", "high") and
                "multi_agent" not in actions_taken):
            return {"action": "multi_agent", "reasoning": "High severity needs multi-agent"}

        # Chain potential vulns
        if (vuln_type in ("ssrf", "xss", "idor", "sqli", "rce") and
                "request_chain" not in actions_taken and
                confidence >= 0.5):
            return {"action": "request_chain", "reasoning": "Chainable vuln type"}

        # Ready to polish
        if recommend and "polish_report" not in actions_taken:
            return {"action": "polish_report", "reasoning": "Ready for report polish"}

        # Ready to approve
        if recommend and "polish_report" in actions_taken:
            return {"action": "approve_draft", "reasoning": "Polished and ready"}

        # Low confidence — gather evidence
        if confidence < 0.5 and "gather_evidence" not in actions_taken:
            return {"action": "gather_evidence", "reasoning": "Need more evidence"}

        # Reject if still low after evidence
        if confidence < 0.3:
            return {"action": "reject", "reasoning": "Insufficient confidence"}

        # Use AI for complex decisions
        return await self._ai_decide(finding, actions_taken, confidence)

    async def _ai_decide(
        self,
        finding: dict,
        actions_taken: list,
        confidence: float,
    ) -> Optional[dict]:
        """Use AI to make complex triage decisions."""
        state = {
            "title": finding.get("title", ""),
            "severity": finding.get("severity", ""),
            "vuln_type": finding.get("vuln_type", ""),
            "ai_score": finding.get("ai_score", 0),
            "verified": finding.get("verified", False),
            "recommend_draft": finding.get("recommend_draft", False),
            "evidence_score": finding.get("evidence_score", 0),
            "is_duplicate": finding.get("is_duplicate", False),
        }

        prompt = DECISION_PROMPT.format(
            state_json=json.dumps(state, indent=2),
            actions_taken=actions_taken,
            confidence=confidence,
            recommendation=finding.get("recommend_draft", False),
            available_actions=[
                a for a in ACTIONS if a not in actions_taken
            ],
        )

        result = await self._call_ai(prompt)
        return result

    async def _execute_action(
        self, action: str, finding: dict, confidence: float
    ) -> tuple[dict, float]:
        """Execute a triage action and return updated finding + confidence."""

        if action == "verify":
            finding = await self.verifier.deep_verify(finding)
            confidence = float(finding.get("confidence", confidence))

        elif action == "multi_agent":
            finding = await self.multi_agent.run(finding)
            consensus = json.loads(
                finding.get("multi_agent_analysis", "{}")
            ).get("multi_agent_consensus", {})
            verdict = consensus.get("final_verdict", "")
            if verdict == "submit":
                confidence = max(confidence, 0.80)
            elif verdict == "do_not_submit":
                confidence = min(confidence, 0.20)

        elif action == "gather_evidence":
            # Re-probe the target for additional evidence
            target = finding.get("target", "")
            if target:
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            target if target.startswith("http") else f"https://{target}",
                            timeout=aiohttp.ClientTimeout(total=10),
                            ssl=self.config.get("network", {}).get("verify_tls", True)
                        ) as resp:
                            body = await resp.text(errors="ignore")
                            # Add response snippet as additional evidence
                            current_poc = finding.get("proof_of_concept", "")
                            finding["proof_of_concept"] = (
                                current_poc + f"\n\nRe-probe response "
                                f"(status {resp.status}):\n"
                                f"{body[:500]}"
                            )
                            confidence = min(confidence + 0.1, 1.0)
                except Exception:
                    pass

        elif action == "polish_report":
            finding = await self.polisher.polish(finding)
            quality = float(finding.get("report_quality_score", 0))
            if quality >= 0.65:
                confidence = max(confidence, 0.75)

        elif action == "approve_draft":
            finding["recommend_draft"] = True
            confidence = max(confidence, 0.85)

        elif action == "reject":
            finding["recommend_draft"] = False
            finding["rejected_by_agent"] = True
            confidence = min(confidence, 0.20)

        elif action == "escalate":
            sev_order = ["info", "low", "medium", "high", "critical"]
            current = finding.get("severity", "medium")
            idx = sev_order.index(current) if current in sev_order else 2
            if idx < len(sev_order) - 1:
                finding["severity"] = sev_order[idx + 1]
                logger.info(
                    f"[AgenticOrchestrator] Escalated: "
                    f"{current} → {finding['severity']}"
                )

        elif action == "request_chain":
            # Signal to exploit chainer — actual chaining happens in pipeline
            finding["chain_requested"] = True
            finding["chain_vuln_type"] = finding.get("vuln_type", "")
            confidence = min(confidence + 0.05, 1.0)

        return finding, confidence

    async def _call_ai(self, prompt: str) -> Optional[dict]:
        """Call AI for decision making — Ollama first."""
        cfg = self.ai_cfg.get("primary", {})
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
                    timeout=aiohttp.ClientTimeout(total=60)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return self._parse(data.get("response", ""))
        except Exception:
            pass

        # Fallback: Grok
        grok_cfg = self.ai_cfg.get("fallback", {})
        if grok_cfg.get("api_key"):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        f"{grok_cfg.get('base_url', 'https://api.x.ai/v1')}/chat/completions",
                        json={
                            "model": grok_cfg.get("model", "grok-3"),
                            "messages": [{"role": "user", "content": prompt}],
                            "temperature": 0.1,
                        },
                        headers={"Authorization": f"Bearer {grok_cfg['api_key']}"},
                        timeout=aiohttp.ClientTimeout(total=30)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            return self._parse(
                                data["choices"][0]["message"]["content"]
                            )
            except Exception:
                pass
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
