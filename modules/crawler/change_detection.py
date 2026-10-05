"""
BugFlow Elite v6 — Content Change Detection
Tracks page content hashes over time and alerts on changes.
New endpoints appearing after a deploy = new attack surface.
Tinlance Limited | LloydCoder
"""

import hashlib
import logging
import asyncio
import aiohttp
from datetime import datetime
from pathlib import Path
from typing import Optional
from modules.scope.scope_enforcer import ScopeEnforcer
from db.models import get_conn

logger = logging.getLogger(__name__)


class ChangeDetector:
    """
    Monitors known URLs for content changes between scan runs.
    When a page changes, it triggers a re-scan of that endpoint.
    This catches new functionality rolled out between scans.
    """

    def __init__(self, config: dict, scope: ScopeEnforcer):
        self.config = config
        self.scope = scope
        self.db_path = config.get("general", {}).get("db_path", "./db/bugflow.db")
        self.change_cfg = config.get("crawler", {}).get("change_detection", {})
        self.algo = self.change_cfg.get("hash_algorithm", "sha256")

    async def run(self, urls: list[str], domain: str) -> list[dict]:
        """
        Check a list of URLs for content changes since last scan.
        Returns list of changed URLs with old/new hash.
        """
        if not self.change_cfg.get("enabled", True):
            return []

        urls = [u for u in urls if self.scope.is_in_scope(u)[0]]
        if not urls:
            return []

        logger.info(f"[ChangeDetect] Checking {len(urls)} URLs for changes")
        changes = []
        semaphore = asyncio.Semaphore(15)

        async def check_one(url: str):
            async with semaphore:
                change = await self._check_url(url, domain)
                if change:
                    changes.append(change)
                await asyncio.sleep(0.3)

        await asyncio.gather(*[check_one(u) for u in urls[:500]])

        if changes:
            await self._save_changes(changes)
            logger.info(f"[ChangeDetect] {len(changes)} pages changed since last scan")

        return changes

    async def _check_url(self, url: str, domain: str) -> Optional[dict]:
        """Fetch URL, compute hash, compare with stored hash."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    allow_redirects=True,
                    ssl=False,
                    headers={"User-Agent": "Mozilla/5.0 BugFlow-Elite/6.0"}
                ) as resp:
                    if resp.status != 200:
                        return None
                    content = await resp.read()

            new_hash = self._hash(content)
            old_hash = self._get_stored_hash(url)

            if old_hash is None:
                # First time seeing this URL — store hash, no alert
                self._store_hash(url, new_hash, domain)
                return None

            if old_hash != new_hash:
                self._store_hash(url, new_hash, domain)
                logger.info(f"[ChangeDetect] CHANGED: {url}")
                return {
                    "url": url,
                    "domain": domain,
                    "old_hash": old_hash,
                    "new_hash": new_hash,
                    "detected_at": datetime.utcnow().isoformat(),
                }

        except asyncio.TimeoutError:
            pass
        except Exception as e:
            logger.debug(f"[ChangeDetect] Error for {url}: {e}")

        return None

    def _hash(self, content: bytes) -> str:
        """Hash page content."""
        if self.algo == "md5":
            return hashlib.md5(content).hexdigest()
        return hashlib.sha256(content).hexdigest()

    def _get_stored_hash(self, url: str) -> Optional[str]:
        """Get previously stored content hash for a URL."""
        conn = get_conn(self.db_path)
        try:
            row = conn.execute(
                "SELECT content_hash FROM endpoints WHERE url = ?", (url,)
            ).fetchone()
            if row:
                return row["content_hash"]
            # Also check assets table
            host = url.split("//")[-1].split("/")[0]
            row = conn.execute(
                "SELECT content_hash FROM assets WHERE subdomain = ?", (host,)
            ).fetchone()
            return row["content_hash"] if row else None
        finally:
            conn.close()

    def _store_hash(self, url: str, content_hash: str, domain: str):
        """Store the current content hash for a URL."""
        conn = get_conn(self.db_path)
        now = datetime.utcnow().isoformat()
        try:
            conn.execute("""
                INSERT INTO endpoints (url, content_hash, source, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(url) DO UPDATE SET
                    content_hash = excluded.content_hash,
                    last_seen = excluded.last_seen
            """, (url, content_hash, "change_detection", now, now))
            conn.commit()
        except Exception as e:
            logger.debug(f"[ChangeDetect] Store hash error: {e}")
        finally:
            conn.close()

    async def _save_changes(self, changes: list[dict]):
        """Save detected changes to the content_changes table."""
        conn = get_conn(self.db_path)
        now = datetime.utcnow().isoformat()
        try:
            for change in changes:
                conn.execute("""
                    INSERT INTO content_changes
                    (url, old_hash, new_hash, detected_at)
                    VALUES (?, ?, ?, ?)
                """, (
                    change["url"],
                    change["old_hash"],
                    change["new_hash"],
                    change["detected_at"],
                ))
            conn.commit()
        finally:
            conn.close()
