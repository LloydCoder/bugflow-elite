"""
BugFlow Elite v6 — Main Pipeline Orchestrator
Full autonomous pipeline: Recon → Crawl → Scan → Triage → Report
24/7 on Contabo VPS. Incremental every 6h, full scan every 24h.
LEGAL USE ONLY: Authorized bug bounty programs only.
Tinlance Limited | LloydCoder
"""

import asyncio
import logging
import json
import time
from datetime import datetime
from pathlib import Path

from config.loader import load_config, validate_config
from db.models import init_db, save_scan_run, complete_scan_run, save_finding, get_conn
from modules.scope.scope_enforcer import ScopeEnforcer
from modules.recon.bbot_engine import BBOTEngine
from modules.recon.shodan_intel import ShodanIntelligence
from modules.recon.reconftw_engine import ReconFTWEngine
from modules.recon.github_scanner import GitHubOrgScanner
from modules.triage.verification_engine import VerificationEngine
from modules.triage.agentic_orchestrator import AgenticOrchestrator
from modules.scanner.exploit_chainer import ExploitChainer
from modules.reports.ai_report_polisher import AIReportPolisher
from modules.reports.program_selector import ProgramSelector
from modules.reports.logger import FindingLogger
from modules.reports.payout_tracker import PayoutTracker
from modules.reports.burp_exporter import BurpExporter
from modules.reports.platform_client import PlatformClient
from modules.scanner.sqlmap_runner import SQLmapRunner
from modules.scanner.dalfox_runner import DalfoxRunner
from modules.scanner.payload_generator import PayloadGenerator
from modules.scanner.wordlist_generator import WordlistGenerator
from modules.scanner.prompt_injection import PromptInjectionScanner
from modules.scanner.graphql_scanner import GraphQLScanner
from modules.recon.historical_recon import WaybackScanner, CTLogMonitor
from modules.scanner.web3_scanner import Web3Scanner
from modules.reports.immunefi_client import ImmunefiBountyClient
from modules.recon.scope_monitor import ScopeMonitor
from modules.triage.false_positive_tracker import FalsePositiveTracker
from modules.self_improver import SelfImprover
from modules.crawler.js_hunter import JSIntelligence
from modules.crawler.playwright_crawl import PlaywrightCrawler
from modules.crawler.param_intel import ParamDiscovery
from modules.crawler.change_detection import ChangeDetector
from modules.scanner.takeover import TakeoverHunter
from modules.scanner.cloud_enum import CloudEnumScanner
from modules.scanner.nuclei_runner import NucleiRunner
from modules.scanner.trufflehog import SecretScanner
from modules.triage.ai_engine import AITriageEngine
from modules.reports.hackerone import HackerOneClient
from modules.notify.telegram import TelegramNotifier
from modules.vision.screenshots import VisualRecon

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("bugflow")


class BugFlowElite:
    """
    The main BugFlow Elite v6 orchestrator.
    Coordinates all modules across a complete bug bounty pipeline.
    """

    def __init__(self, config_path: str = "./config/config.yaml"):
        self.config = load_config(config_path)

        # Startup warnings
        warnings = validate_config(self.config)
        for w in warnings:
            logger.warning(f"CONFIG: {w}")

        # Initialize DB
        db_path = self.config.get("general", {}).get("db_path", "./db/bugflow.db")
        self.conn = init_db(db_path)

        # Initialize all modules
        self.scope       = ScopeEnforcer(self.config)
        self.bbot        = BBOTEngine(self.config, self.scope)
        self.reconftw    = ReconFTWEngine(self.config, self.scope)
        self.shodan      = ShodanIntelligence(self.config, self.scope)
        self.js_intel    = JSIntelligence(self.config, self.scope)
        self.playwright  = PlaywrightCrawler(self.config, self.scope)
        self.param_disc  = ParamDiscovery(self.config, self.scope)
        self.takeover    = TakeoverHunter(self.config, self.scope)
        self.cloud       = CloudEnumScanner(self.config, self.scope)
        self.nuclei      = NucleiRunner(self.config, self.scope)
        self.secrets     = SecretScanner(self.config, self.scope)
        self.change_det  = ChangeDetector(self.config, self.scope)
        self.ai_triage   = AITriageEngine(self.config)
        self.h1_client   = HackerOneClient(self.config)
        self.telegram    = TelegramNotifier(self.config)
        self.vision      = VisualRecon(self.config, self.scope)
        self.github      = GitHubOrgScanner(self.config, self.scope)
        self.verifier    = VerificationEngine(self.config, self.scope)
        self.agentic        = AgenticOrchestrator(self.config, self.scope)
        self.chainer        = ExploitChainer(self.config)
        self.polisher    = AIReportPolisher(self.config)
        self.selector    = ProgramSelector(self.config)
        self.find_logger = FindingLogger(self.config)
        self.improver    = SelfImprover(self.config)
        self.payout      = PayoutTracker(self.config)
        self.burp        = BurpExporter(self.config)
        self.platforms   = PlatformClient(self.config)
        self.sqlmap      = SQLmapRunner(self.config, self.scope)
        self.dalfox      = DalfoxRunner(self.config, self.scope)
        self.payloads    = PayloadGenerator(self.config)
        self.wordlists      = WordlistGenerator(self.config)
        self.prompt_inject  = PromptInjectionScanner(self.config, self.scope)
        self.graphql        = GraphQLScanner(self.config, self.scope)
        self.wayback        = WaybackScanner(self.config)
        self.ct_monitor     = CTLogMonitor(self.config)
        self.web3           = Web3Scanner(self.config)
        self.immunefi       = ImmunefiBountyClient(self.config)
        self.scope_mon   = ScopeMonitor(self.config)
        self.fp_tracker  = FalsePositiveTracker(self.config)

        # Give Telegram a reference to this pipeline for command handling
        self.telegram.set_pipeline(self)
        self.telegram.set_fp_tracker(self.fp_tracker)

        logger.info("🛡️  BugFlow Elite v6 initialized | Tinlance Limited")

    async def run_web3(self, address: str, chain: str = "ethereum") -> list[dict]:
        """Run Web3 smart contract scan for a contract address."""
        program = f"{chain}:{address[:10]}"
        findings = await self.web3.scan_contract(
            address, chain=chain, program=program
        )
        for finding in findings:
            # Run through normal AI triage pipeline
            triaged = await self.ai_triage.triage(finding)
            await self._process_finding(triaged, program)
            # Generate Immunefi checklist for each finding
            if finding.get("recommend_draft"):
                await self.immunefi.export_submission_checklist(finding)
        return findings

    def _adaptive_delay(self, status_code: int) -> float:
        """Doubles delay on 429/503, resets on success."""
        if status_code in (429, 503):
            self._rate_backoff = min(self._rate_backoff * 2, 60.0)
            logger.warning(
                f"[Pipeline] Rate limited ({status_code}) — "
                f"backing off {self._rate_backoff:.0f}s"
            )
        elif status_code < 400:
            self._rate_backoff = max(self._rate_backoff * 0.9, 1.0)
        return self._rate_backoff

    async def run_incremental(self, domain: str):
        """
        Incremental scan (every 6h): recon new assets only, quick scan.
        Faster and stealthier than a full scan.
        """
        logger.info(f"[Pipeline] Starting INCREMENTAL scan: {domain}")
        await self._run_pipeline(domain, scan_type="incremental")

    async def run_full(self, domain: str):
        """
        Full scan (every 24h): complete pipeline against all known assets.
        """
        logger.info(f"[Pipeline] Starting FULL scan: {domain}")
        await self._run_pipeline(domain, scan_type="full")

    async def _run_pipeline(self, domain: str, scan_type: str):
        """Core pipeline execution."""
        start_time = time.time()

        # Hard scope check — nothing runs if domain isn't in scope
        in_scope, reason = self.scope.is_in_scope(domain)
        if not in_scope:
            logger.error(f"[Pipeline] SCOPE VIOLATION BLOCKED: {domain} — {reason}")
            return

        # Log scan run start
        program = domain
        run_id = save_scan_run(
            self.conn, scan_type=scan_type, program=program, target=domain
        )

        assets_found = 0
        findings_found = 0
        drafts_created = 0
        total_cost = 0.0

        try:
            # ── STAGE 1: Recon — BBOT + reconFTW + crt.sh ─────────────────
            logger.info("[Stage 1] Recon — Asset Discovery (BBOT + reconFTW + crt.sh)")

            # Run BBOT and reconFTW concurrently for maximum coverage
            bbot_task     = asyncio.create_task(self.bbot.run(domain, scan_type))
            reconftw_task = asyncio.create_task(self.reconftw.run(domain, scan_type))
            crtsh_task    = asyncio.create_task(self.bbot.run_crtsh(domain))

            bbot_subs, reconftw_results, crt_subs = await asyncio.gather(
                bbot_task, reconftw_task, crtsh_task,
                return_exceptions=True
            )

            # Safely unpack (tasks could return exceptions)
            bbot_subs = bbot_subs if isinstance(bbot_subs, list) else []
            crt_subs  = crt_subs  if isinstance(crt_subs, list)  else []
            if isinstance(reconftw_results, Exception):
                logger.warning(f"[reconFTW] Task failed: {reconftw_results}")
                reconftw_results = {
                    "subdomains": [], "takeovers": [], "nuclei_findings": [],
                    "secrets": [], "live_hosts": [], "endpoints": [],
                    "vulnerabilities": []
                }

            # Merge all subdomain sources
            subdomains = list(set(
                bbot_subs
                + crt_subs
                + reconftw_results.get("subdomains", [])
            ))
            assets_found = len(subdomains)
            logger.info(
                f"[Stage 1] Subdomains: {len(bbot_subs)} BBOT + "
                f"{len(reconftw_results.get('subdomains', []))} reconFTW + "
                f"{len(crt_subs)} crt.sh = {assets_found} total"
            )

            # ── STAGE 1b: AI Triage of reconFTW Findings ───────────────────
            logger.info("[Stage 1b] AI Triage — reconFTW Findings")

            # Triage takeovers from reconFTW
            for tf in reconftw_results.get("takeovers", []):
                triaged = await self.ai_triage.triage(tf)
                await self._process_finding(triaged, domain)
                findings_found += 1

            # Triage nuclei hits from reconFTW
            for nf in reconftw_results.get("nuclei_findings", []):
                triaged = await self.ai_triage.triage(nf)
                await self._process_finding(triaged, domain)
                findings_found += 1

            # Triage secrets from reconFTW
            for sf in reconftw_results.get("secrets", []):
                triaged = await self.ai_triage.triage(sf)
                await self._process_finding(triaged, domain)
                findings_found += 1

            # Triage other vulnerabilities from reconFTW
            for vf in reconftw_results.get("vulnerabilities", []):
                triaged = await self.ai_triage.triage(vf)
                await self._process_finding(triaged, domain)
                findings_found += 1

            # Save reconFTW endpoints to DB for downstream modules
            if reconftw_results.get("endpoints"):
                conn = get_conn(self.config["general"]["db_path"])
                from datetime import datetime
                now = datetime.utcnow().isoformat()
                for ep in reconftw_results["endpoints"][:1000]:
                    try:
                        conn.execute(
                            "INSERT OR IGNORE INTO endpoints "
                            "(url, source, first_seen, last_seen) VALUES (?,?,?,?)",
                            (ep, "reconftw", now, now)
                        )
                    except Exception:
                        pass
                conn.commit()
                conn.close()
                logger.info(
                    f"[Stage 1b] Saved {len(reconftw_results['endpoints'])} "
                    f"endpoints from reconFTW"
                )

            # Notify on new assets
            if scan_type == "incremental":
                conn = get_conn(self.config["general"]["db_path"])
                new_assets = [
                    s for s in subdomains
                    if not conn.execute(
                        "SELECT 1 FROM assets WHERE subdomain=?", (s,)
                    ).fetchone()
                ]
                conn.close()
                for new_sub in new_assets[:5]:  # Cap Telegram spam
                    await self.telegram.send_new_asset(new_sub, domain)

            # ── STAGE 2: Shodan Intelligence ───────────────────────────────
            logger.info("[Stage 2] Shodan Intelligence")
            # Get IPs for all discovered subdomains (simplified — real impl resolves DNS)
            favicon_results = await self.shodan.run_favicon_pivot(
                [f"https://{s}" for s in subdomains[:50]]
            )

            # ── STAGE 3: Deep Subdomain Takeover Check ─────────────────────
            logger.info("[Stage 3] Subdomain Takeover Scanning")
            takeover_findings = await self.takeover.run(subdomains, program=domain)
            for tf in takeover_findings:
                await self._process_finding(tf, domain)
                findings_found += 1

            # ── STAGE 4: Cloud Asset Enumeration ───────────────────────────
            logger.info("[Stage 4] Cloud Asset Enumeration")
            cloud_findings = await self.cloud.run(domain, program=domain)
            for cf in cloud_findings:
                finding = {
                    "title": cf.get("title", "Cloud Misconfiguration"),
                    "severity": cf.get("severity", "medium"),
                    "vuln_type": "cloud_misconfiguration",
                    "target": cf.get("url", domain),
                    "description": cf.get("description", ""),
                    "reproduction_steps": cf.get("reproduction_steps", ""),
                    "ai_score": cf.get("ai_score", 6.0),
                    "program": domain,
                }
                triaged = await self.ai_triage.triage(finding)
                await self._process_finding(triaged, domain)
                findings_found += 1

            # ── STAGE 5: JS Intelligence ────────────────────────────────────
            logger.info("[Stage 5] JS Intelligence — Endpoint & Secret Discovery")
            js_results = await self.js_intel.run(domain, subdomains)

            # Report leaked secrets as findings
            for secret in js_results.get("secrets", []):
                finding = {
                    "title": f"Leaked Secret in JS: {secret['type'].replace('_', ' ').title()}",
                    "severity": "high" if "key" in secret["type"] else "medium",
                    "vuln_type": "secret",
                    "target": secret["source_url"],
                    "description": (
                        f"Potential {secret['type']} detected in JavaScript file.\n"
                        f"Source: {secret['source_url']}\n"
                        f"Preview: {secret['preview']}"
                    ),
                    "program": domain,
                }
                triaged = await self.ai_triage.triage(finding)
                await self._process_finding(triaged, domain)
                findings_found += 1

            # ── STAGE 6: Secret Scanning (TruffleHog + GitHound) ───────────
            logger.info("[Stage 6] Secret Scanning — TruffleHog + GitHound")
            secret_results = await self.secrets.run(
                domain,
                urls=js_results.get("js_files", [])
            )
            for secret in secret_results:
                finding = {
                    "title": f"Credential Leak: {secret['type']}",
                    "severity": secret.get("severity", "high"),
                    "vuln_type": "secret",
                    "target": secret.get("source_url", domain),
                    "description": (
                        f"{secret['type']} credential detected by {secret['source_tool']}.\n"
                        f"Verified: {secret.get('is_verified', False)}\n"
                        f"Preview: {secret.get('preview', '')}"
                    ),
                    "program": domain,
                }
                triaged = await self.ai_triage.triage(finding)
                await self._process_finding(triaged, domain)
                findings_found += 1

            # ── STAGE 6b: GitHub Org Scanning ───────────────────────────
            logger.info("[Stage 6b] GitHub Org Scanning — Repos + Secrets")
            github_findings = await self.github.run(domain, program=domain)
            for gf in github_findings:
                triaged = await self.ai_triage.triage(gf)
                await self._process_finding(triaged, domain)
                findings_found += 1

            # ── STAGE 7: Visual Recon + Screenshots ─────────────────────────
            logger.info("[Stage 7] Visual Recon — Screenshots + Panel Detection")
            visual_findings = await self.vision.run(subdomains, domain)
            for vf in visual_findings:
                finding = {
                    "title": f"Interesting Panel: {vf['title']}",
                    "severity": "medium",
                    "vuln_type": "exposed_panel",
                    "target": vf["url"],
                    "description": vf["note"],
                    "screenshot_paths": json.dumps([vf.get("screenshot", "")]),
                    "program": domain,
                }
                triaged = await self.ai_triage.triage(finding)
                await self._process_finding(triaged, domain)
                findings_found += 1

            # ── STAGE 8: Playwright Crawl + Param Discovery (full only) ──────
            if scan_type == "full":
                logger.info("[Stage 8] Playwright Crawl + Parameter Discovery")
                live_targets = subdomains[:50]  # Cap for stealth
                crawl_results = await self.playwright.crawl(live_targets, domain)

                # Change detection on crawled URLs
                all_crawled_urls = crawl_results.get("urls", [])
                if all_crawled_urls:
                    changed = await self.change_det.run(all_crawled_urls, domain)
                    if changed:
                        logger.info(f"[ChangeDetect] {len(changed)} pages changed — re-queued for deep scan")

                param_endpoints = (
                    crawl_results.get("endpoints", []) +
                    js_results.get("endpoints", [])
                )
                param_results = await self.param_disc.run(param_endpoints, domain)

                # Report high-value parameter findings
                for hv in param_results.get("high_value", []):
                    finding = {
                        "title": f"High-Value Parameter: {hv['param']} ({hv['vuln_type'].upper()})",
                        "severity": "medium",
                        "vuln_type": hv["vuln_type"],
                        "target": hv["endpoint"],
                        "description": hv["note"],
                        "reproduction_steps": (
                            f"1. Send request to: {hv['endpoint']}\n"
                            f"2. Fuzz parameter: {hv['param']}\n"
                            f"3. Test for {hv['vuln_type'].upper()}"
                        ),
                        "program": domain,
                    }
                    triaged = await self.ai_triage.triage(finding)
                    await self._process_finding(triaged, domain)
                    findings_found += 1

                # Build tech context for Nuclei template generation
                tech_context = {
                    "technologies": list(set(
                        crawl_results.get("tech", [])
                    )),
                    "interesting_endpoints": param_endpoints[:20],
                }
            else:
                tech_context = {}

            # ── STAGE 9: Nuclei Scanning ────────────────────────────────────
            logger.info(f"[Stage {'9' if scan_type == 'full' else '6'}] Nuclei Scanning")
            nuclei_findings = await self.nuclei.run(
                subdomains, program=domain, tech_context=tech_context
            )
            for nf in nuclei_findings:
                triaged = await self.ai_triage.triage(nf)
                await self._process_finding(triaged, domain)
                findings_found += 1

        except Exception as e:
            logger.exception(f"[Pipeline] Error: {e}")
        finally:
            duration = int(time.time() - start_time)
            complete_scan_run(
                self.conn,
                run_id,
                assets_found=assets_found,
                findings_found=findings_found,
                drafts_created=drafts_created,
                duration_secs=duration,
            )
            # Log scan completion
            self.find_logger.log_scan_complete(run_id, {
                "assets_found": assets_found,
                "findings_found": findings_found,
                "drafts_created": drafts_created,
            })

            # Self-improvement is handled by the scheduler (Sunday 03:00)
            # Not triggered from pipeline to avoid running on every full scan

            # ── STAGE 10: SQLmap verification of SQLi findings ────────────────
            if scan_type == "full" and self.config.get("sqlmap", {}).get("auto_verify_sqli"):
                logger.info("[Stage 10] SQLmap — Verifying SQLi findings")
                conn_t = get_conn(self.config["general"]["db_path"])
                sqli_findings = conn_t.execute(
                    "SELECT id, title, description FROM findings "
                    "WHERE program=? AND vuln_type='sqli' AND is_duplicate=0 "
                    "AND ai_score >= 6.0 LIMIT 5",
                    (domain,)
                ).fetchall()
                conn_t.close()
                sqli_list = [dict(r) for r in sqli_findings]
                if sqli_list:
                    confirmed = await self.sqlmap.batch_verify(sqli_list, domain)
                    findings_found += len(confirmed)

            # ── STAGE 11: Dalfox XSS scanning ────────────────────────────────
            if scan_type == "full" and self.config.get("dalfox", {}).get("auto_scan_params"):
                logger.info("[Stage 11] Dalfox — XSS Scanning")
                conn_t = get_conn(self.config["general"]["db_path"])
                param_urls = [
                    r["url"] for r in conn_t.execute(
                        "SELECT url FROM endpoints WHERE url LIKE ? AND url LIKE '%?%' LIMIT 200",
                        (f"%{domain}%",)
                    ).fetchall()
                ]
                conn_t.close()
                if param_urls:
                    xss_findings = await self.dalfox.scan_urls(param_urls, domain)
                    for xf in xss_findings:
                        triaged = await self.ai_triage.triage(xf)
                        await self._process_finding(triaged, domain)
                        findings_found += 1

            # ── STAGE 12: Generate custom wordlist + run ffuf ─────────────────
            if scan_type == "full":
                logger.info("[Stage 12] AI Wordlist Generation")
                wl_result = await self.wordlists.generate(domain)
                logger.info(
                    f"[Stage 12] Wordlist: {wl_result.get('total_paths', 0)} paths, "
                    f"{wl_result.get('total_params', 0)} params"
                )

            # ── STAGE 13: Prompt Injection (AI endpoints) ─────────────────
            if self.config.get("scanner", {}).get(
                "prompt_injection", {}
            ).get("enabled", True):
                logger.info("[Stage 13] Prompt Injection Scanner")
                pi_findings = await self.prompt_inject.scan_domain(
                    domain, program=domain
                )
                for pif in pi_findings:
                    triaged = await self.ai_triage.triage(pif)
                    await self._process_finding(triaged, domain)
                    findings_found += 1

            # ── STAGE 14: GraphQL Security Scanner ───────────────────────────
            if self.config.get("scanner", {}).get(
                "graphql", {}
            ).get("enabled", True):
                logger.info("[Stage 14] GraphQL Security Scanner")
                gql_findings = await self.graphql.scan_domain(
                    domain, program=domain
                )
                for gf in gql_findings:
                    triaged = await self.ai_triage.triage(gf)
                    await self._process_finding(triaged, domain)
                    findings_found += 1

            # ── STAGE 15: Historical Recon (Wayback + CT) ────────────────────
            if scan_type == "full":
                logger.info(
                    "[Stage 15] Historical Recon — "
                    "Wayback + CT Log Monitor"
                )
                # CT Log — detect new subdomains
                new_certs = await self.ct_monitor.check_new_certs(
                    domain
                )
                if new_certs:
                    logger.info(
                        f"[Stage 15] {len(new_certs)} new "
                        f"CT subdomains detected"
                    )
                    await self.telegram.send_scope_change_alert(
                        program=domain,
                        new_domains=[c["domain"] for c in new_certs],
                        platform="ct_log",
                    )

                # Wayback — find removed interesting endpoints
                removed = await self.wayback.find_removed_endpoints(
                    domain
                )
                if removed:
                    logger.info(
                        f"[Stage 15] {len(removed)} historical "
                        f"endpoints to probe"
                    )

            # Full-scan exploit chain sweep across all findings
            if scan_type == "full":
                logger.info("[Pipeline] Running exploit chain analysis")
                chain_findings = await self.chainer.run(domain)
                for cf in chain_findings:
                    await self._process_finding(cf, domain)
                    findings_found += 1

            # Send summary to Telegram
            await self.telegram.send_scan_summary({
                "scan_type": scan_type,
                "program": domain,
                "assets_found": assets_found,
                "findings_found": findings_found,
                "drafts_created": drafts_created,
                "duration_secs": duration,
            })
            logger.info(
                f"[Pipeline] Complete: {assets_found} assets, "
                f"{findings_found} findings, {drafts_created} H1 drafts "
                f"({duration}s)"
            )

    async def _process_finding(self, finding: dict, domain: str):
        """Triage, save, verify, polish, draft, and alert on a finding."""
        if not finding:
            return

        # Skip duplicates and very low scores
        if finding.get("is_duplicate"):
            return
        score = float(finding.get("ai_score", 0))
        if score < 3.0:
            return

        # False positive check — adjust score based on learned patterns
        finding = self.fp_tracker.adjust_score(finding)

        # Agentic orchestrator runs the full triage loop autonomously
        # (verify → multi-agent → chain → polish → approve/reject)
        finding = await self.agentic.run(finding)

        # If chaining was requested, run exploit chainer
        if finding.get("chain_requested"):
            chains = await self.chainer.chain_single(finding, domain)
            for chain in chains:
                # Process each chain as a separate finding
                chain["from_chain"] = True
                await self._process_finding(chain, domain)

        # Block rejected findings
        if finding.get("rejected_by_agent"):
            logger.debug(f"[Pipeline] Agent rejected: {finding.get('title','')[:50]}")
            return

        # Save to DB
        finding_id = save_finding(
            self.conn,
            title=finding.get("title", "Finding"),
            severity=finding.get("severity", "info"),
            vuln_type=finding.get("vuln_type", "unknown"),
            description=finding.get("description", ""),
            reproduction_steps=finding.get("reproduction_steps", ""),
            proof_of_concept=finding.get("proof_of_concept", ""),
            ai_score=score,
            ai_analysis=finding.get("ai_analysis", ""),
            is_duplicate=int(finding.get("is_duplicate", False)),
            duplicate_score=finding.get("duplicate_score", 0.0),
            threatfade_c2=int(finding.get("threatfade_c2", False)),
            mitre_ttps=finding.get("mitre_ttps", ""),
            program=domain,
        )
        finding["id"] = finding_id

        # H1 draft (if score + severity qualifies)
        program_handle = await self.h1_client.get_program_handle(domain)
        draft_url = ""
        if program_handle:
            draft_result = await self.h1_client.create_draft(finding, program_handle)
            if draft_result:
                draft_url = draft_result.get("report_url", "")

        # Telegram alert
        await self.telegram.send_finding(finding, draft_url)

        # Log finding to JSONL + CSV audit trail
        self.find_logger.log_finding(finding)

        # Add to dedup engine's known set
        self.ai_triage.dedup_engine.add_to_known(finding)

    async def _run_nuclei(self, subdomains: list[str], domain: str) -> list[dict]:
        """Run Nuclei against live subdomains."""
        import asyncio
        import subprocess
        import tempfile, os

        if not subdomains:
            return []

        findings = []
        output_file = Path(f"./output/nuclei_{domain.replace('.', '_')}.json")

        # Write targets to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            for sub in subdomains:
                f.write(f"https://{sub}\n")
            targets_file = f.name

        nuclei_cfg = self.config.get("scanner", {}).get("nuclei", {})
        cmd = [
            "nuclei",
            "-l", targets_file,
            "-severity", nuclei_cfg.get("severity", "low,medium,high,critical"),
            "-rate-limit", str(nuclei_cfg.get("rate_limit", 20)),
            "-json",
            "-o", str(output_file),
            "-silent",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.communicate(), timeout=1800)

            if output_file.exists():
                with open(output_file) as f:
                    for line in f:
                        if not line.strip():
                            continue
                        try:
                            result = json.loads(line)
                            findings.append({
                                "title": result.get("info", {}).get("name", "Nuclei Finding"),
                                "severity": result.get("info", {}).get("severity", "info"),
                                "vuln_type": "nuclei",
                                "target": result.get("host", ""),
                                "template_id": result.get("template-id", ""),
                                "description": result.get("info", {}).get("description", ""),
                                "proof_of_concept": json.dumps({
                                    "matched": result.get("matched-at", ""),
                                    "extracted": result.get("extracted-results", []),
                                }),
                                "program": domain,
                                "tool": "nuclei",
                            })
                        except json.JSONDecodeError:
                            pass
        except asyncio.TimeoutError:
            logger.warning("[Nuclei] Timeout")
        except Exception as e:
            logger.error(f"[Nuclei] Error: {e}")
        finally:
            os.unlink(targets_file)

        logger.info(f"[Nuclei] Found {len(findings)} findings")
        return findings


async def main():
    """Entry point for manual runs."""
    import sys
    pipeline = BugFlowElite()

    if len(sys.argv) < 2:
        print("Usage: python main.py <domain> [incremental|full]")
        print("Example: python main.py example.com full")
        return

    domain = sys.argv[1]
    scan_type = sys.argv[2] if len(sys.argv) > 2 else "incremental"

    if scan_type == "full":
        await pipeline.run_full(domain)
    else:
        await pipeline.run_incremental(domain)


if __name__ == "__main__":
    asyncio.run(main())
