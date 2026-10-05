"""
BugFlow Elite v6 — Hybrid AI Triage Engine
Primary: Ollama (local, free, private)
Fallback: Grok API (xAI)
Secondary fallback: Claude API (Anthropic)
+ ThreatFade C2 oracle integration
+ Embedding-based duplicate suppression engine
Tinlance Limited | LloydCoder
"""

import json
import logging
import hashlib
import asyncio
import aiohttp
from datetime import datetime
from typing import Optional
from db.models import get_conn, save_finding

logger = logging.getLogger(__name__)

TRIAGE_PROMPT = """You are an expert bug bounty hunter and vulnerability triager.
Analyze the following security finding and provide a structured assessment.

Target: {target}
Vulnerability Type: {vuln_type}
Tool: {tool}
Raw Finding:
{raw_finding}

Screenshot Analysis (if available): {screenshot_context}

Respond ONLY with a valid JSON object (no markdown, no preamble):
{{
    "title": "concise title for HackerOne report",
    "severity": "critical|high|medium|low|info",
    "cvss_score": 0.0,
    "exploitability_score": 0.0,
    "is_likely_false_positive": false,
    "false_positive_reason": "",
    "is_likely_duplicate": false,
    "duplicate_reason": "",
    "attack_scenario": "realistic attack scenario in 2-3 sentences",
    "impact": "business impact explanation",
    "reproduction_steps": "numbered steps to reproduce",
    "suggested_nuclei_template": "",
    "mitre_ttps": [],
    "suggested_next_actions": [],
    "report_summary": "professional HackerOne report summary paragraph",
    "confidence": 0.0
}}"""


class AITriageEngine:
    """
    Hybrid AI triage: Ollama → Grok → Claude.
    Each finding is scored, analyzed, and checked for duplicates
    before being considered for HackerOne draft creation.
    """

    def __init__(self, config: dict):
        self.config = config
        self.db_path = config.get("general", {}).get("db_path", "./db/bugflow.db")
        self.ai_cfg = config.get("ai", {})
        self.cost_guard = CostGuard(config)
        self.dedup_engine = DuplicateEngine(config)
        self.threatfade = ThreatFadeOracle(config)
        self._embedding_model = None

    async def triage(self, finding: dict) -> dict:
        """
        Full triage pipeline for a single finding.
        Returns enriched finding with AI analysis + dedup + ThreatFade.
        """
        target = finding.get("target", "")
        logger.info(f"[AI Triage] Analyzing: {finding.get('title', 'unknown')}")

        # ThreatFade is an intelligence observation; it never grants severity authority.
        if self.config.get("threatfade", {}).get("enabled") and target:
            c2_result = await self.threatfade.check(target)
            if c2_result.get("c2_detected"):
                finding["threatfade_c2"] = True
                finding["threatfade_c2"] = True
                finding["threatfade_observation"] = {
                    "confidence": c2_result.get("confidence", 0),
                    "summary": c2_result.get("summary", ""),
                    "ttps": c2_result.get("ttps", []),
                    "z_score": c2_result.get("z_score", 0),
                }
                logger.warning(
                    f"[ThreatFade] C2-like signal observed on {target}; verification required"
                )

        # Duplicate suppression check
        is_dup, dup_score = await self.dedup_engine.check(finding)
        if is_dup:
            finding["is_duplicate"] = True
            finding["duplicate_score"] = dup_score
            logger.info(
                f"[Dedup] Suppressed duplicate (score: {dup_score:.2f}): "
                f"{finding.get('title', '')}"
            )
            return finding

        # Cost guard check
        if not self.cost_guard.can_spend():
            logger.warning("[Cost Guard] Daily AI budget reached — skipping AI triage")
            finding["ai_score"] = 5.0
            finding["ai_analysis"] = json.dumps({"note": "AI budget exceeded"})
            return finding

        # Run AI triage
        prompt = TRIAGE_PROMPT.format(
            target=finding.get("target", "unknown"),
            vuln_type=finding.get("vuln_type", "unknown"),
            tool=finding.get("tool", "unknown"),
            raw_finding=json.dumps(finding, indent=2)[:3000],  # Cap input
            screenshot_context=finding.get("screenshot_path", "none"),
        )

        ai_result = await self._call_ai(prompt)

        if ai_result:
            finding["ai_analysis"] = json.dumps(ai_result)
            finding["ai_score"] = float(ai_result.get("exploitability_score", 5.0))
            finding["severity"] = ai_result.get("severity", finding.get("severity", "medium"))
            finding["title"] = ai_result.get("title", finding.get("title", ""))
            finding["mitre_ttps"] = json.dumps(ai_result.get("mitre_ttps", []))

            # Override false positives
            if ai_result.get("is_likely_false_positive"):
                finding["ai_score"] = 1.0
                logger.info(f"[AI Triage] False positive: {ai_result.get('false_positive_reason')}")

        return finding

    async def _call_ai(self, prompt: str) -> Optional[dict]:
        """Try AI providers in order: Ollama → Grok → Claude."""
        providers = [
            ("ollama",  self._call_ollama),
            ("grok",    self._call_grok),
            ("claude",  self._call_claude),
        ]
        for name, fn in providers:
            try:
                result = await fn(prompt)
                if result:
                    self.cost_guard.record_call(name, prompt)
                    return result
            except Exception as e:
                logger.warning(f"[AI] {name} failed: {e}")
        logger.error("[AI] All providers failed")
        return None

    async def _call_ollama(self, prompt: str) -> Optional[dict]:
        """Call local Ollama instance."""
        cfg = self.ai_cfg.get("primary", {})
        if cfg.get("provider") != "ollama":
            return None

        base_url = cfg.get("base_url", "http://ollama:11434")
        model = cfg.get("model", "llama3.2-vision:11b")

        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.1},
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{base_url}/api/generate",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=120)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return self._parse_ai_response(data.get("response", ""))
        return None

    async def _call_grok(self, prompt: str) -> Optional[dict]:
        """Call Grok API (xAI)."""
        cfg = self.ai_cfg.get("fallback", {})
        api_key = cfg.get("api_key", "")
        if not api_key:
            return None

        payload = {
            "model": cfg.get("model", "grok-3"),
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
            "max_tokens": 1500,
        }
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{cfg.get('base_url', 'https://api.x.ai/v1')}/chat/completions",
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=60)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    content = data["choices"][0]["message"]["content"]
                    return self._parse_ai_response(content)
        return None

    async def _call_claude(self, prompt: str) -> Optional[dict]:
        """Call Claude API (Anthropic) as last resort."""
        cfg = self.ai_cfg.get("secondary_fallback", {})
        api_key = cfg.get("api_key", "")
        if not api_key:
            return None

        payload = {
            "model": cfg.get("model", "claude-haiku-4-5-20251001"),
            "max_tokens": 1500,
            "messages": [{"role": "user", "content": prompt}],
        }
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://api.anthropic.com/v1/messages",
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=60)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    content = data["content"][0]["text"]
                    return self._parse_ai_response(content)
        return None

    def _parse_ai_response(self, text: str) -> Optional[dict]:
        """Parse AI JSON response, stripping markdown if present."""
        if not text:
            return None
        # Strip markdown code blocks
        text = text.strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        text = text.strip().rstrip("```").strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Try to extract JSON from mixed response
            import re
            match = re.search(r'\{.*\}', text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group())
                except Exception:
                    pass
        return None


class DuplicateEngine:
    """
    Embedding-based duplicate suppression.
    Compares new findings against known disclosed/common findings
    using sentence-transformer cosine similarity.
    """

    def __init__(self, config: dict):
        self.config = config
        self.threshold = config.get("ai", {}).get("dedup", {}).get(
            "similarity_threshold", 0.82
        )
        self.db_path = config.get("general", {}).get("db_path", "./db/bugflow.db")
        self._model = None
        self._known_embeddings = []
        self._loaded = False

    def _get_model(self):
        """Lazy-load the sentence transformer model."""
        if self._model is None:
            try:
                from sentence_transformers import SentenceTransformer
                model_name = self.config.get("ai", {}).get("dedup", {}).get(
                    "embedding_model", "all-MiniLM-L6-v2"
                )
                self._model = SentenceTransformer(model_name)
            except ImportError:
                logger.warning("[Dedup] sentence-transformers not installed — dedup disabled")
        return self._model

    async def check(self, finding: dict) -> tuple[bool, float]:
        """
        Check if a finding is a likely duplicate.
        Returns (is_duplicate, similarity_score).
        """
        model = self._get_model()
        if model is None:
            return False, 0.0

        text = self._finding_to_text(finding)
        if not text:
            return False, 0.0

        # Load known findings if not loaded
        if not self._loaded:
            await self._load_known_findings()

        if not self._known_embeddings:
            return False, 0.0

        try:
            import numpy as np
            new_emb = model.encode([text])[0]
            similarities = [
                float(np.dot(new_emb, known) / (
                    np.linalg.norm(new_emb) * np.linalg.norm(known) + 1e-8
                ))
                for known in self._known_embeddings
            ]
            max_sim = max(similarities) if similarities else 0.0
            return max_sim >= self.threshold, max_sim
        except Exception as e:
            logger.error(f"[Dedup] Similarity check error: {e}")
            return False, 0.0

    async def _load_known_findings(self):
        """Load embeddings of existing findings from DB."""
        model = self._get_model()
        if model is None:
            return

        conn = get_conn(self.db_path)
        try:
            rows = conn.execute(
                "SELECT title, description FROM findings WHERE is_duplicate = 0 LIMIT 1000"
            ).fetchall()
            texts = [self._row_to_text(r) for r in rows if r["title"]]
            if texts:
                self._known_embeddings = list(model.encode(texts))
            self._loaded = True
        finally:
            conn.close()

    def _finding_to_text(self, finding: dict) -> str:
        return f"{finding.get('title', '')} {finding.get('description', '')} {finding.get('vuln_type', '')}"

    def _row_to_text(self, row) -> str:
        return f"{row['title']} {row['description'] or ''}"

    def add_to_known(self, finding: dict):
        """Add a new finding to the known embeddings cache."""
        model = self._get_model()
        if model is None:
            return
        text = self._finding_to_text(finding)
        if text.strip():
            emb = model.encode([text])[0]
            self._known_embeddings.append(emb)


class ThreatFadeOracle:
    """
    Calls your ThreatFade C2 detection engine for each discovered host.
    A C2 detection is an intelligence observation only; severity requires independent evidence and verification.
    """

    def __init__(self, config: dict):
        self.config = config
        self.tf_cfg = config.get("threatfade", {})

    async def check(self, target: str) -> dict:
        """Check a target host against ThreatFade's C2 detection engine."""
        base_url = self.tf_cfg.get("base_url", "http://localhost:8000")
        api_key = self.tf_cfg.get("api_key", "")

        headers = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{base_url}/analyze",
                    json={"target": target, "mode": "fast"},
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return {
                            "c2_detected": data.get("confidence", 0) >= 0.7,
                            "confidence": data.get("confidence", 0),
                            "summary": data.get("summary", ""),
                            "ttps": data.get("mitre_ttps", ["T1071"]),
                            "z_score": data.get("z_score", 0),
                        }
        except aiohttp.ClientConnectorError:
            logger.debug("[ThreatFade] Not reachable — skipping C2 check")
        except Exception as e:
            logger.debug(f"[ThreatFade] Error: {e}")

        return {"c2_detected": False}


class CostGuard:
    """Tracks AI API spend and enforces daily budget limits."""

    def __init__(self, config: dict):
        self.config = config
        self.db_path = config.get("general", {}).get("db_path", "./db/bugflow.db")
        self.max_daily = config.get("ai", {}).get("cost_guard", {}).get("max_daily_usd", 2.0)
        self.warn_at = config.get("ai", {}).get("cost_guard", {}).get("warn_at_usd", 1.5)
        # Token costs (USD per 1M tokens, approximate)
        self._costs = {
            "ollama":  0.0,
            "grok":    2.0 / 1_000_000,
            "claude":  0.8 / 1_000_000,
        }

    def can_spend(self) -> bool:
        """Check if we're under the daily budget."""
        spent = self._get_today_spend()
        if spent >= self.max_daily:
            return False
        if spent >= self.warn_at:
            logger.warning(f"[CostGuard] Approaching daily limit: ${spent:.3f}/${self.max_daily}")
        return True

    def record_call(self, provider: str, prompt: str):
        """Record an AI API call for cost tracking."""
        if provider == "ollama":
            return  # Free
        token_estimate = len(prompt.split()) * 1.3
        cost = token_estimate * self._costs.get(provider, 0)

        conn = get_conn(self.db_path)
        try:
            conn.execute("""
                INSERT INTO ai_costs (provider, model, tokens_in, estimated_usd, operation)
                VALUES (?, ?, ?, ?, ?)
            """, (provider, provider, int(token_estimate), cost, "triage"))
            conn.commit()
        finally:
            conn.close()

    def _get_today_spend(self) -> float:
        """Get total AI spend for today."""
        conn = get_conn(self.db_path)
        try:
            today = datetime.utcnow().date().isoformat()
            row = conn.execute("""
                SELECT COALESCE(SUM(estimated_usd), 0) as total
                FROM ai_costs
                WHERE DATE(timestamp) = ?
            """, (today,)).fetchone()
            return float(row["total"]) if row else 0.0
        finally:
            conn.close()
