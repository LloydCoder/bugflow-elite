"""
BugFlow Elite v6 — AI Custom Wordlist Generator
Builds target-specific wordlists from JS analysis, tech stack,
endpoint patterns, and company vocabulary.
Better than generic lists for finding hidden admin panels and APIs.
Tinlance Limited | LloydCoder
"""

import json
import logging
import asyncio
import aiohttp
import re
from pathlib import Path
from typing import Optional
from db.models import get_conn

logger = logging.getLogger(__name__)

WORDLIST_PROMPT = """You are a security researcher building a custom wordlist for directory/parameter fuzzing.

Target: {domain}
Tech stack detected: {tech_stack}
Endpoints discovered: {endpoints_sample}
JS keywords found: {js_keywords}
Company/product context: {company_context}

Generate a comprehensive fuzzing wordlist with:
1. Admin/management paths (/admin, /dashboard, /manage, /console, etc.)
2. API endpoints (/api/v1, /api/v2, /internal, /graphql, etc.)
3. Common file exposures (/.env, /config.json, /backup, etc.)
4. Tech-stack-specific paths (Laravel: /telescope, Spring: /actuator, etc.)
5. Target-specific vocabulary (from the company/product name)
6. Hidden parameter names likely for this app

Respond ONLY with valid JSON (no markdown):
{{
  "paths": ["path1", "path2", ...],
  "parameters": ["param1", "param2", ...],
  "high_priority": ["most_likely_path1", "most_likely_path2"],
  "tech_specific": ["framework_path1", "framework_path2"],
  "count": 0
}}

Include 150-300 unique entries total."""

# Tech-stack specific wordlists (pre-built, no AI needed)
TECH_WORDLISTS = {
    "spring": [
        "/actuator", "/actuator/env", "/actuator/health", "/actuator/info",
        "/actuator/mappings", "/actuator/beans", "/actuator/heapdump",
        "/actuator/threaddump", "/actuator/loggers", "/h2-console",
        "/swagger-ui.html", "/v2/api-docs", "/spring-security-oauth-resource",
    ],
    "laravel": [
        "/telescope", "/horizon", "/_debugbar", "/admin",
        "/api/user", "/sanctum/csrf-cookie", "/storage",
    ],
    "django": [
        "/admin/", "/admin/login/", "/__debug__/", "/api/schema/",
        "/api/docs/", "/static/admin/", "/media/",
    ],
    "express": [
        "/api/v1/", "/api/v2/", "/graphql", "/.well-known/",
        "/health", "/metrics", "/status", "/debug",
    ],
    "wordpress": [
        "/wp-admin/", "/wp-login.php", "/wp-json/", "/xmlrpc.php",
        "/wp-content/uploads/", "/wp-config.php.bak",
    ],
    "jenkins": [
        "/jenkins/", "/script", "/console", "/credentials/",
        "/manage", "/asynchPeople/", "/systemInfo",
    ],
    "grafana": [
        "/grafana/", "/api/dashboards/", "/api/datasources/",
        "/api/admin/", "/login",
    ],
}

# Common high-value paths for all targets
UNIVERSAL_PATHS = [
    "/.env", "/.git/config", "/config.json", "/config.yaml",
    "/backup", "/backup.zip", "/backup.tar.gz", "/database.sql",
    "/admin", "/administrator", "/admin.php", "/admin/login",
    "/api", "/api/v1", "/api/v2", "/api/v3", "/internal",
    "/graphql", "/graphiql", "/playground",
    "/swagger", "/swagger-ui", "/swagger.json", "/openapi.json",
    "/docs", "/documentation", "/api-docs",
    "/debug", "/test", "/dev", "/staging",
    "/health", "/status", "/metrics", "/info",
    "/console", "/dashboard", "/manage", "/management",
    "/.well-known/security.txt", "/security.txt",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/server-status", "/server-info", "/.htaccess",
]


class WordlistGenerator:
    """
    Generates target-specific fuzzing wordlists by combining:
    1. AI-generated context-aware paths
    2. Tech-stack specific pre-built lists
    3. JS-extracted vocabulary
    4. Universal high-value paths
    """

    def __init__(self, config: dict):
        self.config = config
        self.ai_cfg = config.get("ai", {})
        self.db_path = config.get("general", {}).get(
            "db_path", "./db/bugflow.db"
        )
        self.output_dir = Path("./output/wordlists")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def generate(self, domain: str) -> dict:
        """
        Generate a complete custom wordlist for a domain.
        Returns dict with paths, parameters, and file path.
        """
        logger.info(f"[WordlistGen] Generating wordlist for {domain}")

        # Gather context from DB
        context = self._gather_context(domain)

        # Start with universal paths
        all_paths = set(UNIVERSAL_PATHS)

        # Add tech-stack specific paths
        tech_paths = self._get_tech_paths(context.get("tech_stack", []))
        all_paths.update(tech_paths)

        # Extract words from discovered JS/endpoints
        js_words = self._extract_js_vocabulary(domain)
        all_paths.update(js_words)

        # AI-generated target-specific paths
        ai_result = await self._ai_generate(domain, context)
        if ai_result:
            all_paths.update(ai_result.get("paths", []))
            params = ai_result.get("parameters", [])
            high_priority = ai_result.get("high_priority", [])
        else:
            params = []
            high_priority = list(all_paths)[:20]

        # Save wordlist to file
        wordlist_path = self.output_dir / f"{domain.replace('.', '_')}_wordlist.txt"
        sorted_paths = sorted(all_paths)
        wordlist_path.write_text("\n".join(sorted_paths))

        # Save params wordlist
        params_path = self.output_dir / f"{domain.replace('.', '_')}_params.txt"
        params_path.write_text("\n".join(set(params)))

        result = {
            "domain": domain,
            "wordlist_path": str(wordlist_path),
            "params_path": str(params_path),
            "total_paths": len(sorted_paths),
            "total_params": len(params),
            "high_priority": high_priority[:20],
            "tech_specific_count": len(tech_paths),
        }

        logger.info(
            f"[WordlistGen] Generated {len(sorted_paths)} paths, "
            f"{len(params)} params for {domain}"
        )
        return result

    def _gather_context(self, domain: str) -> dict:
        """Pull context about domain from BugFlow's DB."""
        conn = get_conn(self.db_path)
        try:
            # Get tech stack
            tech_rows = conn.execute(
                "SELECT tech_stack FROM assets WHERE domain=? AND tech_stack IS NOT NULL LIMIT 20",
                (domain,)
            ).fetchall()

            tech_stack = []
            for row in tech_rows:
                ts = row["tech_stack"]
                if ts:
                    try:
                        tech_stack.extend(json.loads(ts))
                    except Exception:
                        tech_stack.append(ts)

            # Get sample endpoints
            ep_rows = conn.execute(
                "SELECT url FROM endpoints WHERE url LIKE ? LIMIT 50",
                (f"%{domain}%",)
            ).fetchall()
            endpoints = [r["url"] for r in ep_rows]

            return {
                "tech_stack": list(set(tech_stack))[:10],
                "endpoints": endpoints[:20],
            }
        except Exception:
            return {"tech_stack": [], "endpoints": []}
        finally:
            conn.close()

    def _get_tech_paths(self, tech_stack: list) -> set:
        """Get tech-specific paths for detected technologies."""
        paths = set()
        for tech in tech_stack:
            tech_lower = tech.lower()
            for key, word_list in TECH_WORDLISTS.items():
                if key in tech_lower:
                    paths.update(word_list)
        return paths

    def _extract_js_vocabulary(self, domain: str) -> set:
        """Extract meaningful path words from JS files BugFlow analyzed."""
        conn = get_conn(self.db_path)
        paths = set()
        try:
            rows = conn.execute(
                "SELECT endpoints_found FROM js_files LIMIT 100"
            ).fetchall()
            for row in rows:
                if row["endpoints_found"]:
                    try:
                        eps = json.loads(row["endpoints_found"])
                        for ep in eps:
                            # Extract path segments as wordlist entries
                            clean = ep.strip("/").split("?")[0]
                            if clean and len(clean) < 50:
                                paths.add(f"/{clean}")
                                # Add path segments
                                for seg in clean.split("/"):
                                    if seg and len(seg) > 2:
                                        paths.add(f"/{seg}")
                    except Exception:
                        pass
        except Exception:
            pass
        finally:
            conn.close()
        return paths

    async def _ai_generate(
        self, domain: str, context: dict
    ) -> Optional[dict]:
        """Use AI to generate context-aware wordlist entries."""
        tech_str = ", ".join(context.get("tech_stack", ["unknown"]))
        eps_sample = "\n".join(
            context.get("endpoints", [])[:10]
        )
        company = domain.split(".")[0]

        # Extract JS keywords from DB
        conn = get_conn(self.db_path)
        js_kws = []
        try:
            rows = conn.execute(
                "SELECT raw_value FROM secrets LIMIT 20"
            ).fetchall()
            js_kws = [r["raw_value"][:30] for r in rows if r["raw_value"]]
        except Exception:
            pass
        finally:
            conn.close()

        prompt = WORDLIST_PROMPT.format(
            domain=domain,
            tech_stack=tech_str,
            endpoints_sample=eps_sample or "none discovered yet",
            js_keywords=", ".join(js_kws[:10]) or "none",
            company_context=company,
        )

        # Use Ollama (free)
        cfg = self.ai_cfg.get("primary", {})
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{cfg.get('base_url', 'http://ollama:11434')}/api/generate",
                    json={
                        "model": cfg.get("model", "llama3.2-vision:11b"),
                        "prompt": prompt,
                        "stream": False,
                        "options": {"temperature": 0.4},
                    },
                    timeout=aiohttp.ClientTimeout(total=120)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return self._parse(data.get("response", ""))
        except Exception as e:
            logger.debug(f"[WordlistGen] AI error: {e}")
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
            m = re.search(r'\{.*\}', text, re.DOTALL)
            if m:
                try:
                    return json.loads(m.group())
                except Exception:
                    pass
        return None
