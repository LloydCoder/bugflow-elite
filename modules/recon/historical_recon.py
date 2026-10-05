"""
BugFlow Elite v6 — Historical Recon
Gap 19: Wayback Machine Scanner — finds historical endpoints
Gap 20: Certificate Transparency Monitor — first-mover on new subdomains
Both give first-mover advantage before other hunters notice new scope.
Tinlance Limited | LloydCoder
"""

import json
import logging
import asyncio
import aiohttp
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from db.models import get_conn

logger = logging.getLogger(__name__)


# ── GAP 19: Wayback Machine Scanner ────────────────────────────────────────

class WaybackScanner:
    """
    Fetches historical URLs from Wayback Machine CDX API.
    Finds endpoints that were removed from public access
    but may still be live in the backend — high value target.
    """

    CDX_URL = "http://web.archive.org/cdx/search/cdx"

    def __init__(self, config: dict):
        self.config = config
        self.db_path = config.get("general", {}).get(
            "db_path", "./db/bugflow.db"
        )

    async def fetch_historical_urls(
        self, domain: str, limit: int = 500
    ) -> list[str]:
        """
        Fetch historical URLs from Wayback Machine.
        Returns unique URLs that were indexed historically.
        """
        logger.info(f"[Wayback] Fetching history for {domain}")
        urls = set()

        params = {
            "url": f"*.{domain}/*",
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
            "limit": str(limit),
            "filter": "statuscode:200",
            "from": (
                datetime.utcnow() - timedelta(days=1825)
            ).strftime("%Y%m%d"),
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.CDX_URL,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status != 200:
                        return []
                    data = await resp.json(content_type=None)

                    # CDX returns list of lists, first row is header
                    for row in data[1:]:
                        if row and row[0]:
                            urls.add(row[0])

            logger.info(
                f"[Wayback] {len(urls)} historical URLs "
                f"found for {domain}"
            )

            # Save to DB for use in scanning
            self._save_historical_urls(list(urls), domain)
            return list(urls)

        except Exception as e:
            logger.error(f"[Wayback] Error: {e}")
            return []

    async def find_removed_endpoints(
        self, domain: str
    ) -> list[dict]:
        """
        Find interesting removed endpoints worth testing.
        Filters for admin panels, API endpoints, dev files.
        """
        historical = await self.fetch_historical_urls(domain)
        if not historical:
            return []

        # Get currently known live URLs
        conn = get_conn(self.db_path)
        try:
            live = set(
                r["url"] for r in conn.execute(
                    "SELECT url FROM endpoints WHERE url LIKE ?",
                    (f"%{domain}%",)
                ).fetchall()
            )
        except Exception:
            live = set()
        finally:
            conn.close()

        # Find historically interesting URLs not in current scan
        interesting_patterns = [
            "/admin", "/api/v", "/internal", "/debug",
            "/console", "/manage", "/staff", "/secret",
            "/.env", "/config", "/backup", "/test",
            "/dev", "/staging", "/old", "/legacy",
            "/swagger", "/graphql", "/phpmyadmin",
        ]

        removed = []
        for url in historical:
            if url in live:
                continue
            url_lower = url.lower()
            for pattern in interesting_patterns:
                if pattern in url_lower:
                    removed.append({
                        "url": url,
                        "pattern": pattern,
                        "source": "wayback",
                    })
                    break

        logger.info(
            f"[Wayback] {len(removed)} interesting removed "
            f"endpoints to test for {domain}"
        )
        return removed[:50]  # Cap to avoid noise

    def _save_historical_urls(
        self, urls: list[str], domain: str
    ):
        """Save historical URLs to endpoints table."""
        conn = get_conn(self.db_path)
        try:
            for url in urls[:200]:
                try:
                    conn.execute("""
                        INSERT OR IGNORE INTO endpoints
                        (url, source, is_interesting)
                        VALUES (?, 'wayback', 0)
                    """, (url,))
                except Exception:
                    pass
            conn.commit()
        finally:
            conn.close()


# ── GAP 20: Certificate Transparency Monitor ───────────────────────────────

class CTLogMonitor:
    """
    Monitors Certificate Transparency logs for new subdomains.
    Uses crt.sh API (free, no rate limits) to check for
    certificates issued in the last N hours.
    New certificate = new subdomain = first-mover opportunity.
    """

    def __init__(self, config: dict):
        self.config = config
        self.db_path = config.get("general", {}).get(
            "db_path", "./db/bugflow.db"
        )
        self.state_file = Path("./output/.ct_state.json")
        self.state_file.parent.mkdir(parents=True, exist_ok=True)

    async def check_new_certs(
        self, domain: str, hours_back: int = 24
    ) -> list[dict]:
        """
        Check crt.sh for certificates issued in the last N hours.
        Returns list of new subdomains not previously seen.
        """
        logger.info(
            f"[CTMonitor] Checking CT logs for {domain} "
            f"(last {hours_back}h)"
        )

        current_certs = await self._fetch_certs(domain)
        if not current_certs:
            return []

        previous = self._load_state(domain)
        previous_names = {c["name_value"] for c in previous}
        current_names = {c["name_value"] for c in current_certs}

        new_names = current_names - previous_names

        if new_names:
            logger.info(
                f"[CTMonitor] ⚡ {len(new_names)} NEW subdomains "
                f"detected for {domain}: {list(new_names)[:5]}"
            )

        self._save_state(domain, current_certs)

        # Return new cert events
        new_events = []
        for cert in current_certs:
            if cert["name_value"] in new_names:
                new_events.append({
                    "domain": cert["name_value"],
                    "issuer": cert.get("issuer_name", ""),
                    "issued_at": cert.get("entry_timestamp", ""),
                    "parent_domain": domain,
                })

        return new_events

    async def _fetch_certs(self, domain: str) -> list[dict]:
        """Fetch certificates from crt.sh API."""
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=20),
                ) as resp:
                    if resp.status != 200:
                        return []
                    data = await resp.json(content_type=None)
                    return data if isinstance(data, list) else []
        except Exception as e:
            logger.debug(f"[CTMonitor] crt.sh error: {e}")
            return []

    def _load_state(self, domain: str) -> list[dict]:
        """Load previously seen certificates."""
        if not self.state_file.exists():
            return []
        try:
            state = json.loads(self.state_file.read_text())
            return state.get(domain, [])
        except Exception:
            return []

    def _save_state(self, domain: str, certs: list[dict]):
        """Save current cert state as new baseline."""
        try:
            state = {}
            if self.state_file.exists():
                state = json.loads(self.state_file.read_text())
            # Store only name and timestamp to keep file small
            state[domain] = [
                {
                    "name_value": c.get("name_value", ""),
                    "entry_timestamp": c.get(
                        "entry_timestamp", ""
                    ),
                }
                for c in certs[:500]
            ]
            self.state_file.write_text(json.dumps(state))
        except Exception as e:
            logger.debug(f"[CTMonitor] Save error: {e}")

    async def get_all_subdomains(self, domain: str) -> list[str]:
        """
        Get all subdomains ever seen in CT logs for a domain.
        Useful for initial recon to supplement BBOT/reconFTW.
        """
        certs = await self._fetch_certs(domain)
        subdomains = set()
        for cert in certs:
            name = cert.get("name_value", "")
            if name and domain in name:
                # Handle wildcard certs
                clean = name.lstrip("*.")
                if clean and "." in clean:
                    subdomains.add(clean)
        return sorted(subdomains)
