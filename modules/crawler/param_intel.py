"""
BugFlow Elite v6 — Parameter Discovery Module
Tools: Arjun (GET/POST) + cariddi (crawler+param combo)
Finds hidden parameters that unlock IDOR, SQLi, SSRF, and logic bugs.
Tinlance Limited | LloydCoder
"""

import json
import logging
import asyncio
import subprocess
import tempfile
import os
from pathlib import Path
from modules.scope.scope_enforcer import ScopeEnforcer
from db.models import get_conn

logger = logging.getLogger(__name__)

# Parameters frequently linked to high-value vulnerabilities
HIGH_VALUE_PARAMS = {
    "idor":   {"id", "user_id", "account", "uid", "profile_id", "order_id", "doc_id"},
    "ssrf":   {"url", "path", "dest", "redirect", "uri", "link", "src", "source"},
    "sqli":   {"id", "search", "query", "filter", "sort", "order", "page", "limit"},
    "lfi":    {"file", "path", "page", "template", "view", "include", "doc", "document"},
    "ssti":   {"template", "name", "format", "theme", "style", "preview"},
    "xxe":    {"xml", "data", "input", "body", "payload"},
    "rce":    {"cmd", "exec", "command", "run", "shell", "ping", "test", "debug"},
    "open_redirect": {"redirect", "return", "next", "url", "goto", "target", "continue"},
}


class ParamDiscovery:
    """
    Discovers hidden GET/POST parameters on endpoints using Arjun.
    Flags high-value parameters that commonly lead to critical bugs.
    """

    def __init__(self, config: dict, scope: ScopeEnforcer):
        self.config = config
        self.scope = scope
        self.db_path = config.get("general", {}).get("db_path", "./db/bugflow.db")
        self.param_cfg = config.get("crawler", {}).get("param_discovery", {})
        self.output_dir = Path("./output/params")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def run(self, endpoints: list[str], domain: str) -> dict:
        """
        Discover parameters for a list of endpoints.
        Returns {endpoint: [params], high_value: [{endpoint, param, vuln_type}]}
        """
        # Filter to in-scope
        endpoints = [
            e for e in endpoints
            if self.scope.is_in_scope(e)[0] and e.startswith("http")
        ]
        if not endpoints:
            return {"params": {}, "high_value": []}

        logger.info(f"[Params] Discovering parameters for {len(endpoints)} endpoints")

        all_params = {}

        # Arjun
        if (self.param_cfg.get("arjun", {}).get("enabled")
                and self._tool_installed("arjun")):
            arjun_results = await self._run_arjun(endpoints)
            all_params.update(arjun_results)

        # Cariddi (crawler + param discovery combined)
        if (self.param_cfg.get("cariddi", {}).get("enabled")
                and self._tool_installed("cariddi")):
            cariddi_results = await self._run_cariddi(domain)
            for ep, params in cariddi_results.items():
                existing = all_params.get(ep, [])
                all_params[ep] = list(set(existing + params))

        # Flag high-value parameters
        high_value = self._flag_high_value(all_params)

        # Save to DB
        await self._save_params(all_params, domain)

        logger.info(
            f"[Params] {sum(len(v) for v in all_params.values())} params found, "
            f"{len(high_value)} high-value"
        )
        return {"params": all_params, "high_value": high_value}

    async def _run_arjun(self, endpoints: list[str]) -> dict:
        """Run Arjun to discover hidden GET and POST parameters."""
        results = {}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(endpoints[:200]))
            input_file = f.name

        output_file = self.output_dir / "arjun_results.json"
        arjun_cfg = self.param_cfg.get("arjun", {})

        cmd = [
            "arjun",
            "-i", input_file,
            "-oJ", str(output_file),
            "-t", str(arjun_cfg.get("threads", 5)),
            "-m", "GET,POST",
            "--stable",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await asyncio.wait_for(proc.communicate(), timeout=600)

            if output_file.exists():
                with open(output_file) as f:
                    data = json.load(f)
                    # Arjun output: {url: {params: [...]}}
                    for url, info in data.items():
                        params = info.get("params", [])
                        if params:
                            results[url] = params

        except asyncio.TimeoutError:
            logger.warning("[Arjun] Timeout")
        except Exception as e:
            logger.error(f"[Arjun] Error: {e}")
        finally:
            os.unlink(input_file)

        logger.debug(f"[Arjun] {len(results)} endpoints with params found")
        return results

    async def _run_cariddi(self, domain: str) -> dict:
        """Run cariddi for combined crawl + parameter extraction."""
        results = {}
        output_file = self.output_dir / f"cariddi_{domain.replace('.', '_')}.txt"

        cmd = [
            "cariddi",
            "-s",                  # Scraped endpoints
            "-e",                  # Extract endpoints
            "-ef", "3",            # Endpoint focus level
        ]

        try:
            input_data = f"https://{domain}\n".encode()
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(input=input_data), timeout=300
            )
            for line in stdout.decode().split("\n"):
                line = line.strip()
                if "?" in line and domain in line:
                    url_part = line.split("?")[0]
                    param_part = line.split("?")[1] if "?" in line else ""
                    params = [p.split("=")[0] for p in param_part.split("&") if "=" in p]
                    if params:
                        results[url_part] = params
        except Exception as e:
            logger.debug(f"[Cariddi] Error: {e}")

        return results

    def _flag_high_value(self, params: dict) -> list[dict]:
        """Flag parameters that commonly lead to high-severity vulnerabilities."""
        flagged = []
        for endpoint, param_list in params.items():
            for param in param_list:
                param_lower = param.lower()
                for vuln_type, bad_params in HIGH_VALUE_PARAMS.items():
                    if param_lower in bad_params:
                        flagged.append({
                            "endpoint": endpoint,
                            "param": param,
                            "vuln_type": vuln_type,
                            "note": (
                                f"Parameter '{param}' commonly associated "
                                f"with {vuln_type.upper()} vulnerabilities"
                            ),
                        })
                        break
        return flagged

    async def _save_params(self, params: dict, domain: str):
        """Save discovered parameters to endpoints table."""
        conn = get_conn(self.db_path)
        now = __import__("datetime").datetime.utcnow().isoformat()
        try:
            for url, param_list in params.items():
                try:
                    conn.execute("""
                        INSERT OR REPLACE INTO endpoints
                        (url, params, source, is_interesting, first_seen, last_seen)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        url,
                        json.dumps(param_list),
                        "arjun",
                        1 if len(param_list) > 0 else 0,
                        now, now
                    ))
                except Exception:
                    pass
            conn.commit()
        finally:
            conn.close()

    def _tool_installed(self, tool: str) -> bool:
        try:
            subprocess.run([tool, "--help"], capture_output=True)
            return True
        except FileNotFoundError:
            return False
