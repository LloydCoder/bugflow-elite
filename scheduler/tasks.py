"""
BugFlow Elite v6 — Task Scheduler (Complete)
All 12 Telegram features wired.
Handles:
  - Manual domain scans (incremental/full)
  - ProgramSelector auto-picks daily target
  - Telegram bot polling (two-way commands)
  - Daily 9am finding digest
  - Payout tracker (every 6h)
  - Scope change monitor (every 6h)
  - Retest reminders (every 30 days)
  - VPS health alert (every 12h)
  - Weekly self-improvement (Sunday 03:00)
Tinlance Limited | LloydCoder
"""

import asyncio
import json
from pathlib import Path
import logging
import signal
from datetime import datetime, timedelta
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger
from config.loader import load_config
from db.models import init_db, get_conn
from main import BugFlowElite

logger = logging.getLogger("bugflow.scheduler")


class BugFlowScheduler:
    """
    Master scheduler for BugFlow Elite v6.
    Coordinates all autonomous operations.
    """

    def __init__(self):
        self.config = load_config()
        self.db_path = self.config.get("general", {}).get(
            "db_path", "./db/bugflow.db"
        )
        init_db(self.db_path)
        self.pipeline = BugFlowElite()
        self.scheduler = AsyncIOScheduler(
            timezone=self.config.get("scheduler", {}).get(
                "timezone", "Africa/Lagos"
            )
        )
        self._manual_domains = self._get_manual_domains()

    # ── Domain Loading ─────────────────────────────────────────────────────

    def _get_manual_domains(self) -> list[str]:
        """Get domains from active programs in manual_scope.yaml."""
        domains = []
        try:
            self.pipeline.scope.load()
            for rule in self.pipeline.scope._in_scope:
                val = rule.get("value", "")
                domain = val.lstrip("*.").split("/")[0]
                if domain and "." in domain and domain not in domains:
                    domains.append(domain)
        except Exception as e:
            logger.error(f"[Scheduler] Error loading manual domains: {e}")
        return domains

    async def _get_auto_selected_domain(self) -> str | None:
        """Use ProgramSelector to pick best program for today's full scan."""
        try:
            prog = await self.pipeline.selector.recommend_daily_target()
            if not prog:
                return None
            targets = prog.get("targets", {}).get("in_scope", [])
            for t in targets:
                identifier = t.get("asset_identifier", "")
                domain = identifier.lstrip("*.").split("/")[0]
                if domain and "." in domain:
                    logger.info(
                        f"[Scheduler] ProgramSelector picked: {domain} "
                        f"(score: {prog.get('selector_score', 0):.1f})"
                    )
                    return domain
        except Exception as e:
            logger.warning(f"[Scheduler] ProgramSelector error: {e}")
        return None

    # ── Job Setup ──────────────────────────────────────────────────────────

    def setup(self):
        """Register all scheduled jobs."""
        sched_cfg = self.config.get("scheduler", {})
        incr_hours = sched_cfg.get("incremental_interval_hours", 6)
        full_hours = sched_cfg.get("full_scan_interval_hours", 24)

        # ── Manual domains ────────────────────────────────────
        if self._manual_domains:
            for domain in self._manual_domains:
                self.scheduler.add_job(
                    self._run_incremental,
                    trigger=IntervalTrigger(hours=incr_hours),
                    args=[domain],
                    id=f"incremental_{domain}",
                    name=f"Incremental: {domain}",
                    misfire_grace_time=300,
                    coalesce=True, max_instances=1,
                )
                self.scheduler.add_job(
                    self._run_full,
                    trigger=IntervalTrigger(hours=full_hours),
                    args=[domain],
                    id=f"full_{domain}",
                    name=f"Full Scan: {domain}",
                    misfire_grace_time=600,
                    coalesce=True, max_instances=1,
                )
                logger.info(
                    f"[Scheduler] Manual domain: {domain} "
                    f"(incr/{incr_hours}h, full/{full_hours}h)"
                )
        else:
            logger.warning(
                "[Scheduler] No manual domains — ProgramSelector active"
            )

        # ── Auto-selected daily full scan at 02:00 ─────────────
        self.scheduler.add_job(
            self._run_auto_selected_full,
            trigger=CronTrigger(hour=2, minute=0),
            id="auto_selected_full",
            name="Auto-Selected Full Scan",
            misfire_grace_time=600,
            coalesce=True, max_instances=1,
        )

        # ── Daily digest at 09:00 ──────────────────────────────
        self.scheduler.add_job(
            self._run_daily_digest,
            trigger=CronTrigger(hour=9, minute=0),
            id="daily_digest",
            name="Daily Finding Digest",
            misfire_grace_time=300,
            coalesce=True, max_instances=1,
        )

        # ── Payout tracker every 6 hours ───────────────────────
        self.scheduler.add_job(
            self._run_payout_check,
            trigger=IntervalTrigger(hours=6),
            id="payout_check",
            name="Payout Tracker",
            misfire_grace_time=300,
            coalesce=True, max_instances=1,
        )

        # ── Scope change monitor every 6 hours ─────────────────
        self.scheduler.add_job(
            self._run_scope_monitor,
            trigger=IntervalTrigger(hours=6),
            id="scope_monitor",
            name="Scope Change Monitor",
            misfire_grace_time=300,
            coalesce=True, max_instances=1,
        )

        # ── VPS health check every 12 hours ────────────────────
        self.scheduler.add_job(
            self._run_health_check,
            trigger=IntervalTrigger(hours=12),
            id="health_check",
            name="VPS Health Check",
            misfire_grace_time=600,
            coalesce=True, max_instances=1,
        )

        # ── Retest reminders every 7 days ──────────────────────
        self.scheduler.add_job(
            self._run_retest_reminders,
            trigger=CronTrigger(day_of_week="wed", hour=10, minute=0),
            id="retest_reminders",
            name="Retest Reminders",
            misfire_grace_time=3600,
            coalesce=True, max_instances=1,
        )

        # ── Dashboard scan trigger watcher (every 30 seconds) ──
        self.scheduler.add_job(
            self._check_scan_trigger,
            trigger=IntervalTrigger(seconds=30),
            id="scan_trigger_watcher",
            name="Dashboard Scan Trigger",
            misfire_grace_time=30,
            coalesce=True,
            max_instances=1,
        )

        # ── Weekly self-improvement: Sunday 03:00 ──────────────
        self.scheduler.add_job(
            self._run_self_improvement,
            trigger=CronTrigger(day_of_week="sun", hour=3, minute=0),
            id="weekly_self_improvement",
            name="Weekly Self-Improvement",
            misfire_grace_time=3600,
            coalesce=True, max_instances=1,
        )

        # ── Immunefi program refresh: Daily 03:30 ──────────────
        if self.config.get("web3", {}).get("auto_fetch_immunefi"):
            self.scheduler.add_job(
                self._run_immunefi_refresh,
                trigger=CronTrigger(hour=3, minute=30),
                id="immunefi_refresh",
                name="Immunefi Program Refresh",
                misfire_grace_time=600,
                coalesce=True, max_instances=1,
            )
            logger.info("[Scheduler] Immunefi auto-refresh registered")

        total_jobs = len(self.scheduler.get_jobs())
        logger.info(f"[Scheduler] {total_jobs} jobs registered")

    # ── Job Runners ────────────────────────────────────────────────────────

    async def _run_incremental(self, domain: str):
        try:
            logger.info(f"[Scheduler] → Incremental: {domain}")
            await self.pipeline.run_incremental(domain)
        except Exception as e:
            logger.exception(f"[Scheduler] Incremental error ({domain}): {e}")

    async def _run_full(self, domain: str):
        try:
            logger.info(f"[Scheduler] → Full scan: {domain}")
            await self.pipeline.run_full(domain)
        except Exception as e:
            logger.exception(f"[Scheduler] Full scan error ({domain}): {e}")

    async def _run_auto_selected_full(self):
        """ProgramSelector picks best target — runs full scan."""
        try:
            domain = await self._get_auto_selected_domain()
            if domain and domain not in self._manual_domains:
                logger.info(f"[Scheduler] Auto-selected: {domain}")
                await self.pipeline.run_full(domain)
            else:
                logger.info("[Scheduler] No new auto-selected target today")
        except Exception as e:
            logger.exception(f"[Scheduler] Auto-selected scan error: {e}")

    async def _run_daily_digest(self):
        """Send 9am daily finding digest via Telegram."""
        try:
            logger.info("[Scheduler] → Daily digest")
            await self.pipeline.telegram.send_daily_digest()
        except Exception as e:
            logger.exception(f"[Scheduler] Daily digest error: {e}")

    async def _run_payout_check(self):
        """Check H1 for new payouts and duplicate notifications."""
        try:
            logger.info("[Scheduler] → Payout check")
            new_payouts = await self.pipeline.payout.check_payouts()
            for payout in new_payouts:
                await self.pipeline.telegram.send_payout_received(
                    title=payout["title"],
                    amount=payout["amount"],
                    program=payout["program"],
                    h1_url=payout["h1_url"],
                )
            # Also check for newly duplicated reports
            duplicates = await self.pipeline.payout.check_duplicate_reports()
            for dup in duplicates:
                await self.pipeline.telegram.send_h1_duplicate_notification(
                    title=dup["title"],
                    report_id=dup["report_id"],
                    h1_url=dup["h1_url"],
                )
        except Exception as e:
            logger.exception(f"[Scheduler] Payout check error: {e}")

    async def _run_scope_monitor(self):
        """Check for scope changes and trigger scans on new domains."""
        try:
            logger.info("[Scheduler] → Scope monitor")
            changes = await self.pipeline.scope_mon.check_for_changes()
            for change in changes:
                # Alert via Telegram
                await self.pipeline.telegram.send_scope_change_alert(
                    program=change["program"],
                    new_domains=change["new_domains"],
                    platform=change["platform"],
                )
                # Auto-trigger incremental scan on first new domain
                if change.get("new_domains"):
                    first_domain = (
                        change["new_domains"][0]
                        .lstrip("*.")
                        .split("/")[0]
                    )
                    if first_domain and "." in first_domain:
                        logger.info(
                            f"[Scheduler] New scope — auto-scanning: "
                            f"{first_domain}"
                        )
                        asyncio.create_task(
                            self._run_incremental(first_domain)
                        )
        except Exception as e:
            logger.exception(f"[Scheduler] Scope monitor error: {e}")

    async def _run_health_check(self):
        """Check VPS health and alert if critical."""
        try:
            import psutil
            cpu = psutil.cpu_percent(interval=1)
            ram = psutil.virtual_memory()
            disk = psutil.disk_usage("/")

            # Alert if any resource is critical
            critical = (
                cpu > 90 or
                ram.percent > 90 or
                disk.percent > 85
            )
            if critical:
                logger.warning(
                    f"[Scheduler] VPS health critical — "
                    f"CPU: {cpu:.0f}%, RAM: {ram.percent:.0f}%, "
                    f"Disk: {disk.percent:.0f}%"
                )
                await self.pipeline.telegram.send_vps_health()
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"[Scheduler] Health check error: {e}")

    async def _run_retest_reminders(self):
        """Send retest reminders for old unresolved drafts."""
        try:
            conn = get_conn(self.db_path)
            cutoff = (
                datetime.utcnow() - timedelta(days=30)
            ).isoformat()
            stale = conn.execute("""
                SELECT id, title, severity, program, h1_draft_url
                FROM findings
                WHERE h1_status = 'drafted'
                AND first_seen < ?
                AND is_duplicate = 0
                ORDER BY ai_score DESC
                LIMIT 5
            """, (cutoff,)).fetchall()
            conn.close()

            if stale:
                findings = [dict(r) for r in stale]
                await self.pipeline.telegram.send_retest_reminder(findings)
                logger.info(
                    f"[Scheduler] Retest reminder: {len(findings)} findings"
                )
        except Exception as e:
            logger.exception(f"[Scheduler] Retest reminder error: {e}")

    async def _check_scan_trigger(self):
        """
        Watches for scan trigger file written by dashboard.
        When dashboard user clicks Scan button it writes
        ./output/.scan_trigger — we pick it up and run the scan.
        """
        trigger = Path("./output/.scan_trigger")
        if not trigger.exists():
            return
        try:
            data = json.loads(trigger.read_text())
            domain = data.get("domain", "")
            scan_type = data.get("scan_type", data.get("type", "incremental"))
            triggered_at = data.get("triggered_at", "")

            if not domain:
                trigger.unlink()
                return

            logger.info(
                f"[Scheduler] Dashboard trigger: {scan_type} scan on {domain}"
            )
            # Delete trigger file before starting scan
            trigger.unlink()

            # Send Telegram confirmation
            await self.pipeline.telegram._send_all(
                f"🚀 Scan triggered from dashboard\n"
                f"Target: `{domain}`\n"
                f"Type: `{scan_type}`"
            )

            # Run the scan
            if scan_type == "full":
                await self._run_full(domain)
            else:
                await self._run_incremental(domain)

        except Exception as e:
            logger.error(f"[Scheduler] Trigger error: {e}")
            try:
                trigger.unlink()
            except Exception:
                pass

    async def _run_immunefi_refresh(self):
        """Fetch top Immunefi programs and log recommendations."""
        try:
            programs = await self.pipeline.immunefi.recommend_programs(
                limit=5
            )
            if programs:
                top = programs[0]
                logger.info(
                    f"[Scheduler] Top Immunefi program today: "
                    f"{top['name']} (max ${top['max_bounty_usd']:,})"
                )
                await self.pipeline.telegram._send_all(
                    f"🌐 *Top Immunefi Programs Today*\n\n"
                    + "\n".join(
                        f"• **{p['name']}** — max ${p['max_bounty_usd']:,} "
                        f"| {p['contract_count']} contracts"
                        for p in programs[:5]
                    )
                    + "\n\nUse `/web3 [address] [chain]` to scan a contract."
                )
        except Exception as e:
            logger.debug(f"[Scheduler] Immunefi refresh error: {e}")

    async def _run_self_improvement(self):
        """Weekly self-improvement cycle — Sunday 03:00."""
        logger.info("[Scheduler] → Weekly self-improvement")
        try:
            results = await self.pipeline.improver.run_weekly_improvement()
            await self.pipeline.telegram.send_tool_update_complete(results)
            logger.info(
                f"[Scheduler] Self-improvement complete: "
                f"{results.get('tools_updated', 0)} tools, "
                f"{results.get('new_templates', 0)} templates"
            )
        except Exception as e:
            logger.exception(f"[Scheduler] Self-improvement error: {e}")

    # ── Startup ────────────────────────────────────────────────────────────

    def start(self):
        """Start scheduler + Telegram bot polling."""
        self.setup()
        loop = asyncio.get_event_loop()

        def shutdown(sig):
            logger.info(f"[Scheduler] {sig.name} — shutting down")
            self.scheduler.shutdown(wait=False)
            loop.stop()

        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, shutdown, sig)

        self.scheduler.start()

        logger.info(
            f"[Scheduler] 🚀 BugFlow Elite v6 running | "
            f"{len(self._manual_domains)} manual domains | "
            f"ProgramSelector active | "
            f"Telegram bot polling | "
            f"Self-improver: Sundays 03:00"
        )

        # Start Telegram bot polling in background
        if self.pipeline.telegram.enabled:
            loop.create_task(self.pipeline.telegram.start_polling())
            logger.info("[Scheduler] Telegram bot polling started")
        else:
            logger.warning(
                "[Scheduler] Telegram not configured — "
                "add TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID to .env"
            )

        # Run initial incremental scans on startup
        for domain in self._manual_domains:
            loop.create_task(self._run_incremental(domain))

        # Auto-selected scan if no manual domains
        if not self._manual_domains:
            loop.create_task(self._run_auto_selected_full())

        # Run initial scope check
        loop.create_task(self._run_scope_monitor())

        try:
            loop.run_forever()
        except KeyboardInterrupt:
            pass
        finally:
            logger.info("[Scheduler] Stopped")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    BugFlowScheduler().start()
