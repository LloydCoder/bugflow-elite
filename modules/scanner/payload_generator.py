"""
BugFlow Elite v6 — AI Payload & Exploit Generator
Uses local Ollama to generate custom payloads for confirmed findings.
WAF bypass variants for XSS, SQLi, SSRF, SSTI, Path Traversal.
Reduces Grok API costs — runs entirely locally and privately.
Tinlance Limited | LloydCoder
"""

import json
import logging
import asyncio
import aiohttp
from typing import Optional
from db.models import get_conn

logger = logging.getLogger(__name__)

# Prompt templates per vuln type
PAYLOAD_PROMPTS = {
    "xss": """You are a security researcher generating XSS payloads for a bug bounty PoC.

Target context:
- URL: {url}
- Parameter: {param}
- Tech stack: {tech}
- WAF detected: {waf}
- Original payload that triggered: {original}

Generate 5 XSS payloads that:
1. Work in this specific context
2. Bypass common WAFs (Cloudflare, Akamai, AWS WAF)
3. Are safe and non-destructive (no cookie theft, just alert/confirm)
4. Include HTML context, attribute context, and JS context variants

Respond ONLY with valid JSON (no markdown):
{{"payloads": ["payload1", "payload2", "payload3", "payload4", "payload5"],
 "recommended": "the single best payload for the report",
 "context": "brief explanation of why these work",
 "cvss_notes": "how this affects CVSS score"}}""",

    "sqli": """You are a security researcher generating SQL injection payloads for PoC.

Target context:
- URL: {url}
- Parameter: {param}
- DB type: {tech}
- WAF detected: {waf}
- Original payload: {original}

Generate 5 safe SQLi payloads that:
1. Confirm injection without modifying data
2. Bypass WAF if present
3. Work for error-based, boolean-based, and time-based detection
4. Extract only: DB version, current user, DB name

Respond ONLY with valid JSON (no markdown):
{{"payloads": ["payload1", "payload2", "payload3", "payload4", "payload5"],
 "recommended": "the single best payload for the report",
 "technique": "error-based|boolean-based|time-based",
 "context": "brief explanation"}}""",

    "ssrf": """You are a security researcher generating SSRF payloads for PoC.

Target context:
- URL: {url}
- Parameter: {param}
- Tech stack: {tech}
- WAF detected: {waf}

Generate 5 SSRF payloads that:
1. Test for internal network access
2. Try cloud metadata endpoints (169.254.169.254, 100.100.100.200)
3. Use protocol variations (http, https, file, dict, gopher)
4. Bypass common SSRF filters

Respond ONLY with valid JSON (no markdown):
{{"payloads": ["payload1", "payload2", "payload3", "payload4", "payload5"],
 "recommended": "the single best payload",
 "targets": ["internal endpoint this can reach"],
 "context": "brief explanation"}}""",

    "ssti": """You are a security researcher generating SSTI payloads for PoC.

Target context:
- URL: {url}
- Parameter: {param}
- Template engine: {tech}
- WAF detected: {waf}

Generate 5 SSTI detection payloads for the identified template engine:
1. Safe detection payloads (math expressions, not RCE)
2. Template-engine-specific syntax
3. WAF bypass variants

Respond ONLY with valid JSON (no markdown):
{{"payloads": ["payload1", "payload2", "payload3", "payload4", "payload5"],
 "recommended": "the single best payload",
 "engine": "jinja2|twig|velocity|freemarker|etc",
 "context": "brief explanation"}}""",

    "path_traversal": r"""You are a security researcher generating path traversal payloads.

Target context:
- URL: {url}
- Parameter: {param}
- OS: {tech}
- WAF detected: {waf}

Generate 5 path traversal payloads that:
1. Read a safe, non-sensitive file (/etc/hostname or C:\\Windows\\win.ini)
2. Bypass common filters (../, ..\, URL encoding, double encoding)
3. Test both Unix and Windows paths

Respond ONLY with valid JSON (no markdown):
{{"payloads": ["payload1", "payload2", "payload3", "payload4", "payload5"],
 "recommended": "the single best payload",
 "target_file": "/etc/hostname",
 "context": "brief explanation"}}""",
}

# Generic fallback
GENERIC_PROMPT = """You are a security researcher generating test payloads for a {vuln_type} vulnerability.

Target: {url}
Parameter: {param}
Tech stack: {tech}

Generate 5 safe, non-destructive test payloads for this vulnerability type.

Respond ONLY with valid JSON:
{{"payloads": ["p1","p2","p3","p4","p5"],
 "recommended": "best single payload",
 "context": "brief explanation"}}"""


class PayloadGenerator:
    """
    Generates context-aware, WAF-bypassing payloads using local Ollama.
    Falls back to Grok if Ollama is unavailable.
    Keeps cost at $0 for most operations.
    """

    def __init__(self, config: dict):
        self.config = config
        self.ai_cfg = config.get("ai", {})
        self.db_path = config.get("general", {}).get(
            "db_path", "./db/bugflow.db"
        )

    async def generate(self, finding: dict) -> Optional[dict]:
        """
        Generate payloads for a confirmed finding.
        Returns dict with payloads + recommendation.
        """
        vuln_type = finding.get("vuln_type", "").lower()
        url = finding.get("target", "")
        param = finding.get("param", "")
        tech = self._extract_tech(finding)
        waf = self._detect_waf(finding)
        original = self._extract_original_payload(finding)

        if not url:
            return None

        prompt_template = PAYLOAD_PROMPTS.get(vuln_type, GENERIC_PROMPT)
        prompt = prompt_template.format(
            url=url,
            param=param,
            tech=tech,
            waf=waf,
            original=original,
            vuln_type=vuln_type,
        )

        logger.info(
            f"[PayloadGen] Generating {vuln_type} payloads for {url[:60]}"
        )

        result = await self._call_ai(prompt)
        if result:
            result["vuln_type"] = vuln_type
            result["target"] = url
            result["generated_at"] = __import__(
                "datetime"
            ).datetime.utcnow().isoformat()

            # Save payloads back to finding
            await self._update_finding_payloads(
                finding.get("id"), result
            )

            logger.info(
                f"[PayloadGen] Generated {len(result.get('payloads', []))} "
                f"payloads for {vuln_type}"
            )

        return result

    async def generate_batch(
        self, findings: list[dict]
    ) -> list[dict]:
        """Generate payloads for multiple findings concurrently."""
        semaphore = asyncio.Semaphore(3)
        results = []

        async def gen_one(finding: dict):
            async with semaphore:
                result = await self.generate(finding)
                if result:
                    results.append(result)

        await asyncio.gather(*[gen_one(f) for f in findings])
        return results

    def _extract_tech(self, finding: dict) -> str:
        """Extract tech stack info from finding."""
        analysis = finding.get("ai_analysis", "")
        if analysis:
            try:
                data = json.loads(analysis)
                return data.get("tech_stack", "unknown")
            except Exception:
                pass
        return "unknown"

    def _detect_waf(self, finding: dict) -> str:
        """Check if WAF was detected for this target."""
        poc = finding.get("proof_of_concept", "")
        desc = finding.get("description", "")
        combined = (poc + desc).lower()
        for waf in ["cloudflare", "akamai", "aws waf", "imperva", "sucuri"]:
            if waf in combined:
                return waf
        return "unknown"

    def _extract_original_payload(self, finding: dict) -> str:
        """Extract original payload from finding PoC."""
        poc = finding.get("proof_of_concept", "")
        if "payload:" in poc.lower():
            for line in poc.split("\n"):
                if "payload:" in line.lower():
                    return line.split(":", 1)[-1].strip()[:100]
        return ""

    async def _call_ai(self, prompt: str) -> Optional[dict]:
        """Call AI for payload generation — Ollama first (free)."""
        # Ollama primary (free, local, private)
        cfg = self.ai_cfg.get("primary", {})
        if cfg.get("provider") == "ollama":
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        f"{cfg.get('base_url', 'http://ollama:11434')}/api/generate",
                        json={
                            "model": "qwen2.5-coder:14b",  # Best for security
                            "prompt": prompt,
                            "stream": False,
                            "options": {"temperature": 0.3},
                        },
                        timeout=aiohttp.ClientTimeout(total=120)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            return self._parse(data.get("response", ""))
            except Exception as e:
                logger.debug(f"[PayloadGen] Ollama error: {e}")

        # Grok fallback
        grok = self.ai_cfg.get("fallback", {})
        if grok.get("api_key"):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        f"{grok.get('base_url', 'https://api.x.ai/v1')}/chat/completions",
                        json={
                            "model": grok.get("model", "grok-3"),
                            "messages": [{"role": "user", "content": prompt}],
                            "temperature": 0.3,
                        },
                        headers={"Authorization": f"Bearer {grok['api_key']}"},
                        timeout=aiohttp.ClientTimeout(total=60)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            return self._parse(
                                data["choices"][0]["message"]["content"]
                            )
            except Exception as e:
                logger.debug(f"[PayloadGen] Grok error: {e}")
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

    async def _update_finding_payloads(
        self, finding_id: Optional[int], payloads: dict
    ):
        """Store generated payloads back on the finding."""
        if not finding_id:
            return
        conn = get_conn(self.db_path)
        try:
            conn.execute("""
                UPDATE findings
                SET proof_of_concept = proof_of_concept || ?
                WHERE id = ?
            """, (
                f"\n\n=== AI Generated Payloads ===\n"
                f"Recommended: {payloads.get('recommended', '')}\n"
                f"All: {json.dumps(payloads.get('payloads', []))}\n"
                f"Context: {payloads.get('context', '')}",
                finding_id,
            ))
            conn.commit()
        except Exception as e:
            logger.debug(f"[PayloadGen] DB update error: {e}")
        finally:
            conn.close()
