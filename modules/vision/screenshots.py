"""
BugFlow Elite v6 — Visual Recon / Screenshots
Gowitness: bulk screenshot all live subdomains.
Used for: admin panel detection, login page discovery,
error page analysis, and AI visual analysis input.
Tinlance Limited | LloydCoder
"""

import logging
import asyncio
import subprocess
import tempfile
import os
from pathlib import Path
from modules.scope.scope_enforcer import ScopeEnforcer
from db.models import get_conn

logger = logging.getLogger(__name__)

# Visual signatures of high-value pages
INTERESTING_TITLES = [
    "admin", "login", "dashboard", "panel", "management",
    "console", "monitor", "jenkins", "grafana", "kibana",
    "portainer", "jira", "confluence", "gitlab", "phpMyAdmin",
    "swagger", "api docs", "debug", "test", "staging", "dev",
    "phpmyadmin", "adminer", "webmin", "cpanel", "whm",
]


class VisualRecon:
    """
    Takes screenshots of all live subdomains using Gowitness.
    Flags pages with interesting titles (admin panels, login pages).
    """

    def __init__(self, config: dict, scope: ScopeEnforcer):
        self.config = config
        self.scope = scope
        self.db_path = config.get("general", {}).get("db_path", "./db/bugflow.db")
        self.vision_cfg = config.get("vision", {}).get("gowitness", {})
        self.screenshot_dir = Path("./output/screenshots")
        self.screenshot_dir.mkdir(parents=True, exist_ok=True)

    async def run(self, subdomains: list[str], domain: str) -> list[dict]:
        """
        Screenshot all live subdomains and flag interesting pages.
        Returns list of interesting findings.
        """
        subdomains = self.scope.filter_in_scope(subdomains)
        if not subdomains:
            return []

        if not self._gowitness_installed():
            logger.warning("[Screenshots] Gowitness not installed — skipping")
            return []

        logger.info(f"[Screenshots] Capturing {len(subdomains)} subdomains")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            for sub in subdomains:
                f.write(f"https://{sub}\n")
                f.write(f"http://{sub}\n")
            targets_file = f.name

        db_file = self.screenshot_dir / f"gowitness_{domain.replace('.', '_')}.db"
        cmd = [
            "gowitness",
            "file",
            "-f", targets_file,
            "--screenshot-path", str(self.screenshot_dir),
            "--db-path", str(db_file),
            "--timeout", str(self.vision_cfg.get("timeout", 30)),
            "--threads", str(self.vision_cfg.get("threads", 10)),
            "--disable-db",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await asyncio.wait_for(proc.communicate(), timeout=1800)
        except asyncio.TimeoutError:
            logger.warning("[Screenshots] Gowitness timeout")
        except Exception as e:
            logger.error(f"[Screenshots] Error: {e}")
        finally:
            os.unlink(targets_file)

        # Analyze screenshots for interesting pages
        interesting = await self._find_interesting(subdomains, domain)
        logger.info(f"[Screenshots] {len(interesting)} interesting pages found")
        return interesting

    async def _find_interesting(self, subdomains: list[str], domain: str) -> list[dict]:
        """
        Check page titles for interesting admin/login panels.
        Uses httpx to get titles quickly.
        """
        interesting = []
        if not self._tool_installed("httpx"):
            return interesting

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(subdomains))
            input_file = f.name

        try:
            proc = await asyncio.create_subprocess_exec(
                "httpx",
                "-l", input_file,
                "-silent", "-json",
                "-title", "-tech-detect",
                "-status-code",
                "-timeout", "10",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)

            for line in stdout.decode().split("\n"):
                if not line.strip():
                    continue
                try:
                    import json
                    result = json.loads(line)
                    title = (result.get("title") or "").lower()
                    url = result.get("url", "")
                    status = result.get("status-code", 0)

                    if any(kw in title for kw in INTERESTING_TITLES):
                        screenshot_file = self._find_screenshot(url)
                        interesting.append({
                            "url": url,
                            "title": result.get("title", ""),
                            "status_code": status,
                            "tech": result.get("tech", []),
                            "screenshot": screenshot_file,
                            "finding_type": "interesting_panel",
                            "note": f"High-interest page title: '{result.get('title', '')}'",
                        })
                        # Update DB asset with tech stack info
                        host = url.split("//")[-1].split("/")[0].split(":")[0]
                        conn = get_conn(self.db_path)
                        conn.execute(
                            "UPDATE assets SET title=?, tech_stack=?, screenshot_path=? WHERE subdomain=?",
                            (
                                result.get("title", ""),
                                str(result.get("tech", []))[:500],
                                screenshot_file,
                                host,
                            )
                        )
                        conn.commit()
                        conn.close()
                except Exception:
                    pass

        except Exception as e:
            logger.error(f"[Screenshots] httpx error: {e}")
        finally:
            os.unlink(input_file)

        return interesting

    def _find_screenshot(self, url: str) -> str:
        """Find the gowitness screenshot file for a URL."""
        import hashlib
        # Gowitness names files by MD5 of URL
        safe = url.replace("://", "-").replace("/", "-").replace(":", "-")
        for ext in [".png", ".jpg"]:
            candidate = self.screenshot_dir / f"{safe}{ext}"
            if candidate.exists():
                return str(candidate)
        return ""

    def _gowitness_installed(self) -> bool:
        return self._tool_installed("gowitness")

    def _tool_installed(self, tool: str) -> bool:
        try:
            subprocess.run([tool, "--help"], capture_output=True)
            return True
        except FileNotFoundError:
            return False
