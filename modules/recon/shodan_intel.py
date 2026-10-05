"""
BugFlow Elite v6 — Shodan Intelligence Module
Favicon hash pivot (FavFreak) + Shodan InternetDB passive port data.
Finds additional infrastructure running the same tech stack.
Tinlance Limited | LloydCoder
"""

import hashlib
import struct
import logging
import asyncio
import aiohttp
import mmh3
import base64
from typing import Optional
from modules.scope.scope_enforcer import ScopeEnforcer
from db.models import get_conn, upsert_asset

logger = logging.getLogger(__name__)

# Well-known favicon hashes and their associated technologies
FAVICON_FINGERPRINTS = {
    116323821:   "Spring Boot",
    -1248682348: "Grafana Dashboard",
    -876922081:  "Jenkins CI",
    1085041816:  "Jira",
    726876556:   "Confluence",
    -1942745920: "GitLab",
    708578229:   "Kibana",
    -1624129604: "Elasticsearch",
    1108011843:  "Kubernetes Dashboard",
    -297069493:  "Traefik Proxy",
    941176648:   "Portainer",
    -1255857499: "Netdata Monitoring",
    1278918579:  "Nagios",
    -1501581041: "pfSense",
    -476463972:  "phpMyAdmin",
    -1042988226: "Adminer",
    1899556386:  "WebLogic",
    -587754157:  "JBoss",
    984498075:   "Tomcat Manager",
    -247940256:  "RabbitMQ Management",
    -1001485665: "Redis Insight",
    710382544:   "Prometheus",
    1956744146:  "HashiCorp Vault",
    -1474615808: "Rancher",
    1591514665:  "SonarQube",
    -1557011823: "Nexus Repository",
    -90533054:   "Zabbix Monitoring",
    1496048386:  "Graylog",
    -878069364:  "OpenSearch Dashboard",
    517709870:   "Rundeck",
}


class ShodanIntelligence:
    """
    Two-layer Shodan intelligence:
    1. InternetDB (free, no auth) — passive port/service data for discovered IPs
    2. FavFreak favicon hash pivot — find more infra running same tech stack
    """

    def __init__(self, config: dict, scope: ScopeEnforcer):
        self.config = config
        self.scope = scope
        self.db_path = config.get("general", {}).get("db_path", "./db/bugflow.db")
        self.shodan_cfg = config.get("recon", {}).get("bbot", {}).get("api_keys", {})

    async def enrich_with_internetdb(self, ip: str) -> Optional[dict]:
        """
        Query Shodan InternetDB for passive port/service data.
        Completely free, no API key, no active scanning footprint.
        """
        url = f"https://internetdb.shodan.io/{ip}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        logger.debug(f"[Shodan InternetDB] {ip}: {data.get('ports', [])}")
                        return {
                            "ip": ip,
                            "ports": data.get("ports", []),
                            "hostnames": data.get("hostnames", []),
                            "cpes": data.get("cpes", []),
                            "vulns": data.get("vulns", []),
                            "tags": data.get("tags", []),
                        }
                    elif resp.status == 404:
                        return None  # IP not in Shodan
        except Exception as e:
            logger.debug(f"[Shodan InternetDB] Error for {ip}: {e}")
        return None

    async def bulk_enrich_ips(self, ips: list[str]) -> dict[str, dict]:
        """Enrich multiple IPs with InternetDB data concurrently."""
        results = {}
        semaphore = asyncio.Semaphore(10)  # Max 10 concurrent requests

        async def enrich_one(ip: str):
            async with semaphore:
                data = await self.enrich_with_internetdb(ip)
                if data:
                    results[ip] = data
                await asyncio.sleep(0.5)  # Gentle rate limiting

        await asyncio.gather(*[enrich_one(ip) for ip in ips])
        logger.info(f"[Shodan InternetDB] Enriched {len(results)}/{len(ips)} IPs")
        return results

    async def get_favicon_hash(self, url: str) -> Optional[int]:
        """
        Download a favicon.ico and compute its MurmurHash3 (Shodan's format).
        This hash is used to find other servers running the same software.
        """
        favicon_urls = [
            url.rstrip("/") + "/favicon.ico",
            url.rstrip("/") + "/static/favicon.ico",
            url.rstrip("/") + "/assets/favicon.ico",
        ]

        for favicon_url in favicon_urls:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        favicon_url,
                        timeout=aiohttp.ClientTimeout(total=10),
                        allow_redirects=True
                    ) as resp:
                        if resp.status == 200:
                            content = await resp.read()
                            if len(content) > 100:  # Valid favicon, not empty
                                favicon_hash = mmh3.hash(
                                    base64.encodebytes(content).decode()
                                )
                                logger.debug(f"[FavFreak] {url} hash: {favicon_hash}")
                                return favicon_hash
            except Exception:
                continue
        return None

    async def identify_tech_from_favicon(self, url: str) -> Optional[dict]:
        """
        Get favicon hash and check against known fingerprints.
        Returns tech identification and Shodan dork if matched.
        """
        favicon_hash = await self.get_favicon_hash(url)
        if favicon_hash is None:
            return None

        result = {
            "url": url,
            "favicon_hash": favicon_hash,
            "tech": None,
            "shodan_dork": f"http.favicon.hash:{favicon_hash}",
            "is_known_tech": False,
        }

        if favicon_hash in FAVICON_FINGERPRINTS:
            result["tech"] = FAVICON_FINGERPRINTS[favicon_hash]
            result["is_known_tech"] = True
            logger.info(
                f"[FavFreak] {url} identified as {result['tech']} "
                f"(hash: {favicon_hash})"
            )

        return result

    async def run_favicon_pivot(self, targets: list[str]) -> list[dict]:
        """
        Run favicon hash analysis on all live targets.
        Returns list of tech identifications + Shodan dorks.
        """
        results = []
        semaphore = asyncio.Semaphore(5)

        async def analyze_one(url: str):
            async with semaphore:
                self.scope.assert_in_scope(url)
                result = await self.identify_tech_from_favicon(url)
                if result:
                    results.append(result)
                await asyncio.sleep(0.5)

        await asyncio.gather(*[analyze_one(t) for t in targets])

        known = [r for r in results if r["is_known_tech"]]
        logger.info(
            f"[FavFreak] Analyzed {len(results)} targets, "
            f"{len(known)} with known tech fingerprints"
        )
        return results

    def get_interesting_ports(self, port_data: dict) -> list[int]:
        """
        From InternetDB data, flag ports of high bug bounty interest.
        """
        interesting_cfg = self.config.get("live_check", {}).get(
            "nmap", {}
        ).get("interesting_services", [])
        interesting_set = {int(p) for p in interesting_cfg if str(p).isdigit()}

        high_interest = [
            p for p in port_data.get("ports", [])
            if p in interesting_set
        ]

        # Always flag these regardless of config
        always_flag = {6379, 27017, 5432, 3306, 9200, 5601, 8080, 8443}
        high_interest += [p for p in port_data.get("ports", []) if p in always_flag]

        return list(set(high_interest))
