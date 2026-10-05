"""
BugFlow Elite v6 — Playwright Headless Crawler
JS-rendered page crawling + full-page screenshots.
Catches SPAs and dynamically loaded content that Katana misses.
Tinlance Limited | LloydCoder
"""

import logging
import asyncio
import hashlib
from pathlib import Path
from typing import Optional
from modules.scope.scope_enforcer import ScopeEnforcer
from db.models import get_conn, upsert_asset

logger = logging.getLogger(__name__)


class PlaywrightCrawler:
    """
    Headless browser crawler using Playwright.
    Handles SPAs, JS-rendered content, and captures screenshots
    for AI-assisted visual analysis.
    """

    def __init__(self, config: dict, scope: ScopeEnforcer):
        self.config = config
        self.scope = scope
        self.db_path = config.get("general", {}).get("db_path", "./db/bugflow.db")
        self.playwright_cfg = config.get("crawler", {}).get("playwright", {})
        self.screenshot_dir = Path("./output/screenshots")
        self.screenshot_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = self.playwright_cfg.get("timeout", 30000)

    async def crawl(self, targets: list[str], domain: str) -> dict:
        """
        Crawl a list of targets with Playwright.
        Returns dict: {urls: [], endpoints: [], screenshots: [], tech: []}
        """
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            logger.warning("[Playwright] Not installed — skipping headless crawl")
            return {"urls": [], "endpoints": [], "screenshots": [], "tech": []}

        targets = self.scope.filter_in_scope(targets)
        if not targets:
            return {"urls": [], "endpoints": [], "screenshots": [], "tech": []}

        logger.info(f"[Playwright] Crawling {len(targets)} targets")
        all_results = {"urls": set(), "endpoints": set(), "screenshots": [], "tech": set()}

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=self.playwright_cfg.get("headless", True),
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ]
            )
            semaphore = asyncio.Semaphore(3)  # Max 3 concurrent browsers

            async def crawl_one(target: str):
                async with semaphore:
                    result = await self._crawl_target(browser, target, domain)
                    if result:
                        all_results["urls"].update(result.get("urls", []))
                        all_results["endpoints"].update(result.get("endpoints", []))
                        all_results["screenshots"].extend(result.get("screenshots", []))
                        all_results["tech"].update(result.get("tech", []))

            await asyncio.gather(*[crawl_one(t) for t in targets[:50]])
            await browser.close()

        all_results["urls"] = list(all_results["urls"])
        all_results["endpoints"] = list(all_results["endpoints"])
        all_results["tech"] = list(all_results["tech"])
        logger.info(
            f"[Playwright] {len(all_results['urls'])} URLs, "
            f"{len(all_results['screenshots'])} screenshots"
        )
        return all_results

    async def _crawl_target(self, browser, target: str, domain: str) -> Optional[dict]:
        """Crawl a single target URL."""
        url = target if target.startswith("http") else f"https://{target}"
        discovered_urls = set()
        discovered_endpoints = set()
        discovered_tech = set()
        screenshots = []

        context = None
        page = None

        try:
            context = await browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                ),
                ignore_https_errors=True,
            )

            # Intercept network requests to discover API endpoints
            async def handle_request(request):
                req_url = request.url
                if self.scope.is_in_scope(req_url)[0]:
                    discovered_urls.add(req_url)
                    if any(p in req_url for p in ["/api/", "/v1/", "/v2/", "/graphql", "/rest/"]):
                        discovered_endpoints.add(req_url)

            context.on("request", handle_request)

            page = await context.new_page()
            await page.set_default_timeout(self.timeout)

            # Navigate
            try:
                response = await page.goto(url, wait_until="networkidle", timeout=self.timeout)
            except Exception:
                response = await page.goto(url, wait_until="domcontentloaded", timeout=self.timeout)

            if not response:
                return None

            status = response.status
            if status >= 400:
                return None

            # Take screenshot
            if self.playwright_cfg.get("screenshot"):
                screenshot_path = self._screenshot_path(url)
                try:
                    await page.screenshot(
                        path=str(screenshot_path),
                        full_page=True,
                        timeout=10000
                    )
                    screenshots.append(str(screenshot_path))
                except Exception as e:
                    logger.debug(f"[Playwright] Screenshot error: {e}")

            # Extract page content hash for change detection
            content = await page.content()
            content_hash = hashlib.sha256(content.encode()).hexdigest()

            # Detect technologies from page
            tech = await self._detect_tech(page)
            discovered_tech.update(tech)

            # Find all links on the page
            links = await page.eval_on_selector_all(
                "a[href]",
                "elements => elements.map(e => e.href)"
            )
            for link in links:
                if link and domain in link:
                    in_scope, _ = self.scope.is_in_scope(link)
                    if in_scope:
                        discovered_urls.add(link)

            # Extract form actions (potential POST endpoints)
            form_actions = await page.eval_on_selector_all(
                "form[action]",
                "forms => forms.map(f => f.action)"
            )
            for action in form_actions:
                if action and domain in action:
                    discovered_endpoints.add(action)

            # Save to DB
            asset_host = url.split("//")[-1].split("/")[0].split(":")[0]
            conn = get_conn(self.db_path)
            upsert_asset(
                conn,
                subdomain=asset_host,
                domain=domain,
                status_code=status,
                content_hash=content_hash,
                tech_stack=str(list(discovered_tech))[:500],
                screenshot_path=screenshots[0] if screenshots else None,
            )
            conn.close()

            return {
                "urls": discovered_urls,
                "endpoints": discovered_endpoints,
                "screenshots": screenshots,
                "tech": discovered_tech,
            }

        except asyncio.TimeoutError:
            logger.debug(f"[Playwright] Timeout: {url}")
            return None
        except Exception as e:
            logger.debug(f"[Playwright] Error crawling {url}: {e}")
            return None
        finally:
            if page:
                try:
                    await page.close()
                except Exception:
                    pass
            if context:
                try:
                    await context.close()
                except Exception:
                    pass

    async def _detect_tech(self, page) -> set[str]:
        """Detect technologies from page source and headers."""
        tech = set()
        try:
            content = await page.content()
            content_lower = content.lower()

            tech_signatures = {
                "React":       ["react.development.js", "__react", "data-reactroot"],
                "Vue.js":      ["vue.js", "vue.min.js", "__vue__", "data-v-"],
                "Angular":     ["ng-version", "angular.js", "__ng_app"],
                "Next.js":     ["__next_data", "_next/static"],
                "Nuxt.js":     ["__nuxt", "_nuxt/"],
                "WordPress":   ["wp-content", "wp-includes"],
                "Laravel":     ["laravel_session", "csrf-token"],
                "Django":      ["csrfmiddlewaretoken", "django"],
                "Spring Boot": ["spring", "Whitelabel Error Page"],
                "Express.js":  ["x-powered-by: express"],
                "GraphQL":     ["__typename", "graphql"],
                "Swagger":     ["swagger-ui", "swagger.json"],
                "jQuery":      ["jquery.min.js", "jquery.js"],
            }

            for tech_name, signatures in tech_signatures.items():
                if any(sig.lower() in content_lower for sig in signatures):
                    tech.add(tech_name)
        except Exception:
            pass

        return tech

    def _screenshot_path(self, url: str) -> Path:
        """Generate a safe screenshot file path from a URL."""
        safe_name = hashlib.md5(url.encode()).hexdigest()[:12]
        return self.screenshot_dir / f"{safe_name}.png"
