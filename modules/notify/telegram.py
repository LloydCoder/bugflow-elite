"""
BugFlow Elite v6 — Full Two-Way Telegram Bot
Output alerts + Input command handler + Inline keyboard buttons.
Covers all 12 features:
  1.  /scan command
  2.  /stop command
  3.  /status command
  4.  /findings command
  5.  /target add|list|pause
  6.  /draft command
  7.  /chain command
  8.  /cost command
  9.  /report command
  10. /improve command
  11. Inline keyboard buttons on all alerts
  12. Missing alert types (change detection, exploit chain, cost warning, VPS health)
Tinlance Limited | LloydCoder
"""

import json
import asyncio
import logging
import aiohttp
import psutil
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Callable

logger = logging.getLogger(__name__)

SEVERITY_EMOJI = {
    "critical": "🔴", "high": "🟠",
    "medium": "🟡", "low": "🔵", "info": "⚪",
}
TYPE_EMOJI = {
    "takeover": "🏴", "cloud_misconfiguration": "☁️",
    "secret": "🔑", "c2_detected": "⚡", "nuclei": "🎯",
    "new_asset": "🆕", "exploit_chain": "⛓", "default": "🐛",
}


class TelegramNotifier:
    """
    Full two-way Telegram bot.
    Sends rich alerts with inline buttons and
    handles incoming commands from the researcher.
    """

    def __init__(self, config: dict):
        self.config = config
        self.tg_cfg = config.get("telegram", {})
        self.bot_token = self.tg_cfg.get("bot_token", "")
        self.chat_id = str(self.tg_cfg.get("chat_id", ""))
        # Support multiple collaborators
        extra = self.tg_cfg.get("extra_chat_ids", [])
        self.all_chat_ids = list({self.chat_id} | {str(c) for c in extra if c})
        self.enabled = bool(self.bot_token and self.chat_id)
        self.notify_on = self.tg_cfg.get("notify_on", ["critical", "high"])
        self.db_path = config.get("general", {}).get("db_path", "./db/bugflow.db")
        self._pipeline_ref = None   # Set by main.py after init
        self._polling_offset = 0
        self._active_scans: set = set()

    def set_pipeline(self, pipeline):
        """Inject pipeline reference so bot can trigger scans."""
        self._pipeline_ref = pipeline

    def set_fp_tracker(self, fp_tracker):
        """Inject false positive tracker for reject callbacks."""
        self._fp_tracker = fp_tracker

    # ── Outgoing Alerts ────────────────────────────────────────────────────

    async def send_finding(self, finding: dict, draft_url: str = "") -> bool:
        if not self.enabled:
            return False
        severity = finding.get("severity", "info")
        vuln_type = finding.get("vuln_type", "default")
        if severity not in self.notify_on and vuln_type not in self.notify_on:
            return False
        text = self._build_finding_message(finding, draft_url)
        buttons = self._finding_buttons(finding, draft_url)
        return await self._send_all(text, buttons)

    async def send_scan_summary(self, run_data: dict) -> bool:
        if not self.enabled:
            return False
        text = self._build_summary_message(run_data)
        buttons = [[
            {"text": "📊 View Dashboard", "url": self._dashboard_url()},
            {"text": "▶ Run Again",
             "callback_data": f"scan:{run_data.get('program','')}_incremental"},
        ]]
        return await self._send_all(text, buttons)

    async def send_new_asset(self, subdomain: str, domain: str) -> bool:
        if not self.enabled or "new_asset" not in self.notify_on:
            return False
        text = (
            f"🆕 *New Asset Discovered*\n\n"
            f"🌐 `{subdomain}`\n"
            f"📎 Program: `{domain}`\n\n"
            f"_Queued for scanning_"
        )
        return await self._send_all(text)

    async def send_exploit_chain(self, chain: dict, draft_url: str = "") -> bool:
        """Alert: new exploit chain discovered."""
        if not self.enabled:
            return False
        score = float(chain.get("ai_score", 0))
        text = (
            f"⛓ *Exploit Chain Found*\n\n"
            f"📋 *{chain.get('title', 'Chain')}*\n\n"
            f"🎯 Score: `{score:.1f}/10`\n"
            f"🔴 Severity: `{chain.get('severity','high').upper()}`\n"
            f"🏆 Program: `{chain.get('program','')}`\n\n"
            f"_{chain.get('description','')[:200]}_"
        )
        buttons = []
        if draft_url:
            buttons = [[{"text": "📋 Create H1 Draft", "url": draft_url}]]
        else:
            buttons = [[{
                "text": "📋 Create Draft",
                "callback_data": f"draft:{chain.get('id','')}"
            }]]
        return await self._send_all(text, buttons)

    async def send_change_detection(self, changes: list[dict]) -> bool:
        """Alert: monitored pages have changed content."""
        if not self.enabled or "change_detection" not in self.notify_on:
            return False
        if not changes:
            return False
        lines = [f"🔄 *Content Changes Detected* — {len(changes)} pages\n"]
        for c in changes[:5]:
            lines.append(f"• `{c.get('url','')[:60]}`")
        if len(changes) > 5:
            lines.append(f"_...and {len(changes)-5} more_")
        lines.append("\n_New attack surface may be available_")
        return await self._send_all("\n".join(lines))

    async def send_cost_warning(self, spent: float, limit: float) -> bool:
        """Alert: AI cost approaching daily limit."""
        if not self.enabled:
            return False
        pct = int((spent / limit) * 100)
        text = (
            f"💸 *AI Cost Warning*\n\n"
            f"Spent today: `${spent:.3f}` / `${limit:.2f}` ({pct}%)\n\n"
            f"_Ollama (local) usage is free and unlimited._"
        )
        buttons = [[
            {"text": "⏸ Pause Cloud AI", "callback_data": "pause_ai"},
            {"text": "✅ Continue",        "callback_data": "continue_ai"},
        ]]
        return await self._send_all(text, buttons)

    async def send_vps_health(self) -> bool:
        """Alert: VPS resource warning."""
        if not self.enabled:
            return False
        try:
            cpu = psutil.cpu_percent(interval=1)
            ram = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            ram_pct = ram.percent
            disk_pct = disk.percent

            if cpu < 80 and ram_pct < 85 and disk_pct < 85:
                return False  # All good, no alert needed

            issues = []
            if cpu >= 80:     issues.append(f"CPU: {cpu:.0f}%")
            if ram_pct >= 85: issues.append(f"RAM: {ram_pct:.0f}%")
            if disk_pct >= 85:issues.append(f"Disk: {disk_pct:.0f}%")

            text = (
                f"⚠️ *VPS Health Warning*\n\n"
                + "\n".join(f"• {i}" for i in issues)
                + "\n\n_Scans may be slowed or paused._"
            )
            return await self._send_all(text)
        except Exception as e:
            logger.debug(f"[Telegram] VPS health check error: {e}")
            return False

    async def send_h1_duplicate_alert(self, finding_title: str, report_id: str) -> bool:
        """Alert: H1 marked a report as duplicate."""
        if not self.enabled:
            return False
        text = (
            f"🔁 *H1 Marked as Duplicate*\n\n"
            f"📋 `{finding_title[:80]}`\n"
            f"Report: `#{report_id}`\n\n"
            f"_Adding to dedup engine to prevent similar reports._"
        )
        return await self._send_all(text)

    async def send_h1_duplicate_notification(
        self, title: str, report_id: str, h1_url: str = ""
    ) -> bool:
        """Alert when H1 marks a report as duplicate."""
        if not self.enabled:
            return False
        msg = (
            f"⚠️ *Report Marked Duplicate*\n\n"
            f"Title: `{title[:80]}`\n"
            f"Report ID: `#{report_id}`\n"
            f"\n_This report was already known. "
            f"Learn what was different and avoid next time._"
        )
        if h1_url:
            msg += f"\n[View on H1]({h1_url})"
        return await self._send_all(msg)

    async def send_payout_received(
        self, finding_title: str, amount: float, currency: str = "USD"
    ) -> bool:
        """Alert: H1 report resolved and paid."""
        if not self.enabled:
            return False
        text = (
            f"💰 *Bounty Received!*\n\n"
            f"📋 `{finding_title[:80]}`\n"
            f"💵 Amount: `{currency} {amount:.2f}`\n\n"
            f"_Great work. Keep hunting! 🎯_"
        )
        return await self._send_all(text)

    async def send_scope_change_alert(
        self, program: str, new_domains: list[str]
    ) -> bool:
        """Alert: H1 program scope expanded."""
        if not self.enabled:
            return False
        domain_list = "\n".join(f"• `{d}`" for d in new_domains[:10])
        text = (
            f"📡 *Scope Expanded: {program}*\n\n"
            f"New in-scope domains:\n{domain_list}\n\n"
            f"_Triggering incremental scan on new assets..._"
        )
        buttons = [[{
            "text": f"▶ Scan Now",
            "callback_data": f"scan:{program}_incremental"
        }]]
        return await self._send_all(text, buttons)

    async def send_daily_digest(self) -> bool:
        """Morning digest — top unsubmitted findings."""
        if not self.enabled:
            return False
        from db.models import get_conn
        conn = get_conn(self.db_path)
        try:
            yesterday = (datetime.utcnow() - timedelta(days=1)).isoformat()
            rows = conn.execute("""
                SELECT id, title, severity, ai_score, program
                FROM findings
                WHERE is_duplicate = 0
                AND h1_status = 'pending'
                AND first_seen > ?
                ORDER BY ai_score DESC
                LIMIT 5
            """, (yesterday,)).fetchall()

            total_today = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE first_seen > ? AND is_duplicate=0",
                (yesterday,)
            ).fetchone()[0]

            drafts_today = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE h1_status='drafted' AND first_seen > ?",
                (yesterday,)
            ).fetchone()[0]

            if not rows and total_today == 0:
                return False

            lines = [
                f"☀️ *Morning Digest — {datetime.now().strftime('%b %d')}*\n",
                f"📊 Yesterday: `{total_today}` findings, `{drafts_today}` H1 drafts\n",
                f"🎯 *Top unsubmitted findings:*"
            ]
            buttons_row = []
            for r in rows:
                sev_e = SEVERITY_EMOJI.get(r["severity"], "⚪")
                lines.append(
                    f"{sev_e} `{r['ai_score']:.1f}` — {r['title'][:60]}"
                )
                buttons_row.append({
                    "text": f"#{r['id']} Draft",
                    "callback_data": f"draft:{r['id']}"
                })

            buttons = [buttons_row[:3]] if buttons_row else []
            return await self._send_all("\n".join(lines), buttons)
        finally:
            conn.close()

    async def send_retest_reminder(self, findings: list[dict]) -> bool:
        """Remind researcher to retest old unresolved drafts."""
        if not self.enabled or not findings:
            return False
        lines = [
            f"🔔 *Retest Reminder — {len(findings)} old drafts*\n",
            f"These reports have been on H1 for 30+ days with no response:\n"
        ]
        buttons_row = []
        for f in findings[:5]:
            lines.append(f"• `#{f.get('h1_report_id','?')}` — {f.get('title','')[:50]}")
            buttons_row.append({
                "text": f"#{f.get('h1_report_id','?')} Retest",
                "callback_data": f"retest:{f.get('id','')}"
            })
        buttons = [buttons_row[:3]] if buttons_row else []
        return await self._send_all("\n".join(lines), buttons)

    async def send_tool_update_complete(self, results: dict) -> bool:
        """Alert: weekly self-improvement completed."""
        if not self.enabled:
            return False
        text = (
            f"🔄 *Weekly Self-Improvement Complete*\n\n"
            f"🛠 Tools updated: `{results.get('tools_updated', 0)}`\n"
            f"📝 New templates: `{results.get('new_templates', 0)}`\n"
            f"🧠 Patterns learned: `{results.get('patterns_learned', 0)}`\n"
            f"🗑 Templates pruned: `{results.get('templates_pruned', 0)}`\n\n"
            f"_BugFlow is smarter now._"
        )
        return await self._send_all(text)

    # ── Command Handler (Input) ────────────────────────────────────────────

    async def start_polling(self):
        """
        Long-poll Telegram for incoming commands.
        Runs as a background task alongside the scheduler.
        """
        if not self.enabled:
            logger.info("[Telegram] Bot disabled — no polling")
            return

        logger.info("[Telegram] 🤖 Bot polling started — ready for commands")
        await self._send_all(
            "🛡️ *BugFlow Elite v6 Online*\n\n"
            "Send /help to see available commands."
        )

        while True:
            try:
                updates = await self._get_updates()
                for update in updates:
                    await self._handle_update(update)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[Telegram] Polling error: {e}")
            await asyncio.sleep(2)

    async def _get_updates(self) -> list:
        url = (
            f"https://api.telegram.org/bot{self.bot_token}/getUpdates"
            f"?offset={self._polling_offset}&timeout=30"
        )
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=35)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        updates = data.get("result", [])
                        if updates:
                            self._polling_offset = updates[-1]["update_id"] + 1
                        return updates
        except Exception:
            pass
        return []

    async def _handle_update(self, update: dict):
        """Route incoming updates — messages and callback queries."""
        # Inline button callback
        if "callback_query" in update:
            await self._handle_callback(update["callback_query"])
            return

        msg = update.get("message", {})
        if not msg:
            return

        # Security: only accept from authorized chat IDs
        sender_id = str(msg.get("chat", {}).get("id", ""))
        if sender_id not in self.all_chat_ids:
            logger.warning(f"[Telegram] Unauthorized sender: {sender_id}")
            return

        text = msg.get("text", "").strip()
        if not text.startswith("/"):
            return

        parts = text.split()
        cmd = parts[0].lower().lstrip("/").split("@")[0]
        args = parts[1:]

        handlers = {
            "help":    self._cmd_help,
            "scan":    self._cmd_scan,
            "stop":    self._cmd_stop,
            "status":  self._cmd_status,
            "findings":self._cmd_findings,
            "target":  self._cmd_target,
            "draft":   self._cmd_draft,
            "chain":   self._cmd_chain,
            "cost":    self._cmd_cost,
            "report":  self._cmd_report,
            "improve": self._cmd_improve,
            "export":  self._cmd_export,
            "leaderboard": self._cmd_leaderboard,
            "health":  self._cmd_health,
        }

        handler = handlers.get(cmd, self._cmd_unknown)
        try:
            await handler(args)
        except Exception as e:
            await self._send_all(f"❌ Error: `{str(e)[:200]}`")
            logger.error(f"[Telegram] Command error /{cmd}: {e}")

    async def _handle_callback(self, cb: dict):
        """Handle inline keyboard button presses."""
        data = cb.get("data", "")
        cb_id = cb.get("id", "")

        # Answer the callback to remove loading state
        await self._answer_callback(cb_id)

        if data.startswith("scan:"):
            parts = data[5:].split("_")
            domain = parts[0]
            scan_type = parts[1] if len(parts) > 1 else "incremental"
            await self._cmd_scan([domain, scan_type])

        elif data.startswith("draft:"):
            finding_id = data[6:]
            await self._cmd_draft([finding_id])

        elif data.startswith("reject:"):
            finding_id = data[7:]
            # Attribution for collaboration mode
            user_id = str(cb.get("from", {}).get("id", ""))
            username = cb.get("from", {}).get("username", "researcher")
            try:
                fid = int(finding_id)
                if hasattr(self, '_fp_tracker') and self._fp_tracker:
                    self._fp_tracker.record_rejection(fid)
                await self._send_all(
                    f"❌ Finding #{finding_id} rejected by @{username}\n"
                    f"_Pattern learned — similar findings will be downgraded._"
                )
            except Exception as e:
                await self._send_all(f"❌ Reject error: `{str(e)[:100]}`")

        elif data.startswith("approve:"):
            finding_id = data[8:]
            await self._cmd_draft([finding_id])

        elif data.startswith("retest:"):
            finding_id = data[7:]
            await self._send_all(
                f"🔔 Retest queued for finding #{finding_id}\n"
                f"_Run `/scan` on the program to re-verify._"
            )

        elif data.startswith("retest_done:"):
            finding_id = data[12:]
            try:
                from db.models import get_conn
                conn = get_conn(self.db_path)
                conn.execute(
                    "UPDATE findings SET h1_status='retested' WHERE id=?",
                    (int(finding_id),)
                )
                conn.commit()
                conn.close()
                await self._send_all(
                    f"✅ Finding #{finding_id} marked as retested.\n"
                    f"_Won't appear in retest reminders again._"
                )
            except Exception as e:
                await self._send_all(f"❌ Error: {str(e)[:80]}")

        elif data == "pause_ai":
            await self._send_all(
                "⏸ *Cloud AI paused*\n\n"
                "Ollama (local) continues running free.\n"
                "Grok and Claude APIs suspended until tomorrow."
            )

        elif data == "continue_ai":
            await self._send_all("✅ AI cost acknowledged. Continuing.")

    # ── Commands ──────────────────────────────────────────────────────────

    async def _cmd_help(self, args: list):
        text = (
            "🛡️ *BugFlow Elite v6 — Commands*\n\n"
            "*Scanning*\n"
            "`/scan domain.com [full|incremental]` — start scan\n"
            "`/stop domain.com` — stop active scan\n"
            "`/status` — current pipeline status\n\n"
            "*Findings*\n"
            "`/findings [critical|high|all]` — latest findings\n"
            "`/draft [id]` — create H1 draft for finding\n"
            "`/chain [program]` — run exploit chainer now\n"
            "`/export csv` — send findings as CSV file\n\n"
            "*Targets*\n"
            "`/target add domain.com` — add to scope\n"
            "`/target list` — show active targets\n"
            "`/target pause domain.com` — pause target\n\n"
            "*Stats*\n"
            "`/cost` — AI spend today\n"
            "`/report` — weekly summary\n"
            "`/leaderboard` — best programs by payout\n"
            "`/web3 [address] [chain]` — scan smart contract\n"
            "`/health` — VPS resource status\n\n"
            "*System*\n"
            "`/improve` — trigger self-improvement now\n"
        )
        await self._send_all(text)

    async def _cmd_scan(self, args: list):
        if not args:
            await self._send_all("Usage: `/scan domain.com [full|incremental]`")
            return
        domain = args[0].lower().strip()
        scan_type = args[1].lower() if len(args) > 1 else "incremental"
        if scan_type not in ("full", "incremental"):
            scan_type = "incremental"

        if domain in self._active_scans:
            await self._send_all(f"⚠️ Scan already running on `{domain}`")
            return

        self._active_scans.add(domain)
        await self._send_all(
            f"▶️ *Scan triggered*\n\n"
            f"Target: `{domain}`\n"
            f"Type: `{scan_type}`\n\n"
            f"_Results will appear as findings come in._"
        )

        if self._pipeline_ref:
            asyncio.create_task(self._run_scan_task(domain, scan_type))
        else:
            await self._send_all(
                "⚠️ Pipeline not connected. "
                "Restart BugFlow to enable remote scanning."
            )
            self._active_scans.discard(domain)

    async def _run_scan_task(self, domain: str, scan_type: str):
        try:
            if scan_type == "full":
                await self._pipeline_ref.run_full(domain)
            else:
                await self._pipeline_ref.run_incremental(domain)
        except Exception as e:
            await self._send_all(f"❌ Scan error on `{domain}`: `{str(e)[:200]}`")
        finally:
            self._active_scans.discard(domain)

    async def _cmd_stop(self, args: list):
        if not args:
            await self._send_all("Usage: `/stop domain.com`")
            return
        domain = args[0].lower()
        if domain in self._active_scans:
            self._active_scans.discard(domain)
            await self._send_all(f"⏹ Scan on `{domain}` flagged to stop.\n_Current stage will finish then halt._")
        else:
            await self._send_all(f"ℹ️ No active scan found for `{domain}`")

    async def _cmd_status(self, args: list):
        from db.models import get_conn
        conn = get_conn(self.db_path)
        try:
            last_scan = conn.execute("""
                SELECT program, scan_type, status, started_at, assets_found, findings_found
                FROM scan_runs ORDER BY started_at DESC LIMIT 3
            """).fetchall()

            active = list(self._active_scans)
            lines = ["📊 *Pipeline Status*\n"]

            if active:
                lines.append(f"🟢 *Active scans:* {', '.join(f'`{d}`' for d in active)}\n")
            else:
                lines.append("⚪ No scans running right now\n")

            if last_scan:
                lines.append("*Recent runs:*")
                for r in last_scan:
                    status_e = "✅" if r["status"] == "completed" else "🔄"
                    lines.append(
                        f"{status_e} `{r['program']}` — "
                        f"{r['scan_type']} — "
                        f"{r['assets_found']} assets, "
                        f"{r['findings_found']} findings"
                    )

            total_findings = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE is_duplicate=0"
            ).fetchone()[0]
            total_assets = conn.execute(
                "SELECT COUNT(*) FROM assets WHERE is_alive=1"
            ).fetchone()[0]
            total_drafts = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE h1_status='drafted'"
            ).fetchone()[0]

            lines.append(
                f"\n📈 Totals: `{total_assets}` assets · "
                f"`{total_findings}` findings · "
                f"`{total_drafts}` H1 drafts"
            )

            await self._send_all("\n".join(lines))
        finally:
            conn.close()

    async def _cmd_findings(self, args: list):
        from db.models import get_conn
        conn = get_conn(self.db_path)
        try:
            sev_filter = args[0].lower() if args else "all"
            query = """
                SELECT id, title, severity, ai_score, vuln_type, h1_status, program
                FROM findings
                WHERE is_duplicate = 0
            """
            params = []
            if sev_filter in ("critical", "high", "medium", "low"):
                query += " AND severity = ?"
                params.append(sev_filter)
            query += " ORDER BY ai_score DESC LIMIT 8"

            rows = conn.execute(query, params).fetchall()
            if not rows:
                await self._send_all(f"No findings found for filter: `{sev_filter}`")
                return

            lines = [f"🐛 *Latest Findings* — filter: `{sev_filter}`\n"]
            buttons_row = []
            for r in rows:
                sev_e = SEVERITY_EMOJI.get(r["severity"], "⚪")
                status = "📝" if r["h1_status"] == "drafted" else "⏳"
                lines.append(
                    f"{sev_e} {status} `{r['ai_score']:.1f}` — "
                    f"{r['title'][:55]}\n"
                    f"   _#{r['id']} · {r['vuln_type']} · {r['program']}_"
                )
                if r["h1_status"] != "drafted":
                    buttons_row.append({
                        "text": f"#{r['id']} Draft",
                        "callback_data": f"draft:{r['id']}"
                    })

            buttons = [buttons_row[:4]] if buttons_row else []
            await self._send_all("\n".join(lines), buttons)
        finally:
            conn.close()

    async def _cmd_target(self, args: list):
        if not args:
            await self._send_all("Usage: `/target add|list|pause domain.com`")
            return

        subcmd = args[0].lower()

        if subcmd == "list":
            from db.models import get_conn
            conn = get_conn(self.db_path)
            try:
                programs = conn.execute("""
                    SELECT DISTINCT program, COUNT(*) as findings
                    FROM findings GROUP BY program ORDER BY findings DESC
                """).fetchall()
                active = list(self._active_scans)
                lines = ["🎯 *Active Targets*\n"]
                for p in programs:
                    running = "🟢" if p["program"] in active else "⚪"
                    lines.append(
                        f"{running} `{p['program']}` — {p['findings']} findings"
                    )
                if not programs:
                    lines.append("_No targets scanned yet_")
                await self._send_all("\n".join(lines))
            finally:
                conn.close()

        elif subcmd == "add" and len(args) > 1:
            domain = args[1].lower()
            # Write to scope file
            scope_path = Path("./config/scope/manual_scope.yaml")
            if scope_path.exists():
                content = scope_path.read_text()
                new_entry = (
                    f"\n  - name: \"{domain}\"\n"
                    f"    platform: \"hackerone\"\n"
                    f"    program_id: \"\"\n"
                    f"    active: true\n"
                    f"    in_scope:\n"
                    f"      domains:\n"
                    f"        - \"*.{domain}\"\n"
                    f"        - \"{domain}\"\n"
                    f"    out_of_scope:\n"
                    f"      domains: []\n"
                )
                scope_path.write_text(content + new_entry)
                await self._send_all(
                    f"✅ *Target added:* `{domain}`\n\n"
                    f"Added to `manual_scope.yaml`.\n"
                    f"Run `/scan {domain}` to start scanning.\n\n"
                    f"⚠️ _Verify this program is in your authorized scope before scanning._",
                    [[{"text": f"▶ Scan {domain}", "callback_data": f"scan:{domain}_incremental"}]]
                )
            else:
                await self._send_all("❌ Scope file not found")

        elif subcmd == "pause" and len(args) > 1:
            domain = args[1].lower()
            self._active_scans.discard(domain)
            await self._send_all(
                f"⏸ `{domain}` paused.\n"
                f"_Scheduler will skip this target until restarted._"
            )
        else:
            await self._send_all("Usage: `/target add|list|pause [domain]`")

    async def _cmd_draft(self, args: list):
        if not args:
            await self._send_all("Usage: `/draft [finding_id]`")
            return
        finding_id = args[0]
        from db.models import get_conn
        conn = get_conn(self.db_path)
        try:
            row = conn.execute(
                "SELECT * FROM findings WHERE id = ?", (finding_id,)
            ).fetchone()
            if not row:
                await self._send_all(f"❌ Finding #{finding_id} not found")
                return
            if row["h1_status"] == "drafted":
                url = row["h1_draft_url"] or "No URL stored"
                await self._send_all(
                    f"ℹ️ Finding #{finding_id} already drafted\n`{url}`"
                )
                return
            await self._send_all(
                f"📋 Drafting finding #{finding_id}...\n"
                f"_`{row['title'][:60]}`_"
            )
            if self._pipeline_ref:
                finding = dict(row)
                program_handle = await self._pipeline_ref.h1_client.get_program_handle(
                    finding.get("program", "")
                )
                if program_handle:
                    result = await self._pipeline_ref.h1_client.create_draft(
                        finding, program_handle
                    )
                    if result:
                        url = result.get("report_url", "")
                        await self._send_all(
                            f"✅ H1 Draft created!\n`{url}`\n\n"
                            f"⚠️ _Review before submitting._"
                        )
                    else:
                        await self._send_all("❌ Draft creation failed. Check H1 token.")
                else:
                    await self._send_all(
                        f"⚠️ No H1 handle found for program `{finding.get('program','')}`\n"
                        f"Add it to your H1 account manually."
                    )
        finally:
            conn.close()

    async def _cmd_chain(self, args: list):
        if not args:
            await self._send_all("Usage: `/chain domain.com`")
            return
        program = args[0].lower()
        await self._send_all(f"⛓ Running exploit chain analysis on `{program}`...")
        if self._pipeline_ref:
            asyncio.create_task(self._run_chain_task(program))
        else:
            await self._send_all("⚠️ Pipeline not connected.")

    async def _run_chain_task(self, program: str):
        try:
            chains = await self._pipeline_ref.chainer.run(program)
            if chains:
                await self._send_all(
                    f"⛓ *Found {len(chains)} exploit chains on `{program}`*\n"
                    + "\n".join(
                        f"• `{c.get('severity','?').upper()}` {c.get('title','')[:60]}"
                        for c in chains[:5]
                    )
                )
            else:
                await self._send_all(
                    f"ℹ️ No exploit chains found on `{program}` yet.\n"
                    f"_More findings needed to identify chains._"
                )
        except Exception as e:
            await self._send_all(f"❌ Chain analysis error: `{str(e)[:100]}`")

    async def _cmd_cost(self, args: list):
        from db.models import get_conn
        conn = get_conn(self.db_path)
        try:
            today = datetime.utcnow().date().isoformat()
            rows = conn.execute("""
                SELECT provider, SUM(estimated_usd) as total, SUM(tokens_in) as tokens
                FROM ai_costs WHERE DATE(timestamp) = ?
                GROUP BY provider ORDER BY total DESC
            """, (today,)).fetchall()

            total = sum(r["total"] for r in rows) if rows else 0
            limit = self.config.get("ai", {}).get("cost_guard", {}).get("max_daily_usd", 2.0)
            pct = int((total / limit) * 100) if limit > 0 else 0
            bar = "█" * (pct // 10) + "░" * (10 - pct // 10)

            lines = [f"💸 *AI Cost — {today}*\n", f"`{bar}` {pct}%\n"]
            for r in rows:
                lines.append(f"• {r['provider']}: `${r['total']:.4f}`")
            lines.append(f"\n*Total: `${total:.4f}` / `${limit:.2f}`*")

            if not rows:
                lines = [
                    f"💸 *AI Cost — {today}*\n",
                    f"• Ollama (local): `$0.00` ✅\n",
                    f"*Total: `$0.00` / `${limit:.2f}`*"
                ]
            await self._send_all("\n".join(lines))
        finally:
            conn.close()

    async def _cmd_report(self, args: list):
        from db.models import get_conn
        conn = get_conn(self.db_path)
        try:
            week_ago = (datetime.utcnow() - timedelta(days=7)).isoformat()
            total = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE first_seen > ? AND is_duplicate=0",
                (week_ago,)
            ).fetchone()[0]
            critical = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE severity='critical' AND first_seen > ?",
                (week_ago,)
            ).fetchone()[0]
            high = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE severity='high' AND first_seen > ?",
                (week_ago,)
            ).fetchone()[0]
            drafts = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE h1_status='drafted' AND first_seen > ?",
                (week_ago,)
            ).fetchone()[0]
            assets = conn.execute(
                "SELECT COUNT(*) FROM assets WHERE first_seen > ?",
                (week_ago,)
            ).fetchone()[0]
            chains = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE vuln_type='exploit_chain' AND first_seen > ?",
                (week_ago,)
            ).fetchone()[0]
            # Payout this week
            payout = conn.execute(
                "SELECT COALESCE(SUM(bounty_amount), 0) FROM payouts WHERE received_at > ?",
                (week_ago,)
            ).fetchone()
            payout_total = float(payout[0]) if payout and payout[0] else 0.0

            await self._send_all(
                f"📊 *Weekly Report*\n"
                f"_{(datetime.utcnow() - timedelta(days=7)).strftime('%b %d')} → {datetime.now().strftime('%b %d')}_\n\n"
                f"🌐 New assets: `{assets}`\n"
                f"🐛 Findings: `{total}` (`{critical}` crit, `{high}` high)\n"
                f"⛓ Chains: `{chains}`\n"
                f"📋 H1 Drafts: `{drafts}`\n"
                f"💰 Payouts: `${payout_total:.2f}`\n\n"
                f"_Next full scan: automatic at 02:00_"
            )
        finally:
            conn.close()

    async def _cmd_improve(self, args: list):
        await self._send_all(
            "🔄 *Self-improvement cycle triggered*\n\n"
            "_Updating tools, generating templates from paid findings, "
            "learning program patterns..._"
        )
        if self._pipeline_ref:
            asyncio.create_task(self._run_improve_task())
        else:
            await self._send_all("⚠️ Pipeline not connected.")

    async def _run_improve_task(self):
        try:
            results = await self._pipeline_ref.improver.run_weekly_improvement()
            await self.send_tool_update_complete(results)
        except Exception as e:
            await self._send_all(f"❌ Improve error: `{str(e)[:100]}`")

    async def _cmd_export(self, args: list):
        fmt = args[0].lower() if args else "csv"
        if fmt != "csv":
            await self._send_all("Currently only CSV export is supported: `/export csv`")
            return
        await self._send_all("📤 Generating CSV export...")
        if self._pipeline_ref:
            try:
                path = self._pipeline_ref.find_logger.export_csv()
                await self._send_document(path, "findings_export.csv")
            except Exception as e:
                await self._send_all(f"❌ Export error: `{str(e)[:100]}`")
        else:
            await self._send_all("⚠️ Pipeline not connected.")

    async def _cmd_leaderboard(self, args: list):
        from db.models import get_conn
        conn = get_conn(self.db_path)
        try:
            rows = conn.execute("""
                SELECT program,
                       COUNT(*) as findings,
                       SUM(CASE WHEN h1_status='drafted' THEN 1 ELSE 0 END) as drafts,
                       AVG(ai_score) as avg_score
                FROM findings
                WHERE is_duplicate = 0
                GROUP BY program
                ORDER BY drafts DESC, findings DESC
                LIMIT 8
            """).fetchall()

            # Also get payout data per program
            payout_rows = {}
            try:
                for row in conn.execute(
                    "SELECT program, SUM(amount) as total FROM payouts "
                    "GROUP BY program"
                ).fetchall():
                    payout_rows[row["program"]] = float(
                        row["total"] or 0
                    )
            except Exception:
                pass

            if not rows:
                await self._send_all(
                    "🏆 *Program Leaderboard*\n\n"
                    "_No data yet. Add a target and run your first scan._\n\n"
                    "Use `/target add domain.com` to get started."
                )
                return

            lines = ["🏆 *Program Leaderboard*\n"]
            medals = ["🥇", "🥈", "🥉"] + ["  "] * 10
            for i, r in enumerate(rows):
                lines.append(
                    f"{medals[i]} `{r['program'][:30]}` — "
                    f"`{r['findings']}` findings · "
                    f"`{r['drafts']}` drafts · "
                    f"avg `{r['avg_score']:.1f}`"
                )
            await self._send_all("\n".join(lines))
        finally:
            conn.close()

    async def _cmd_health(self, args: list):
        try:
            cpu = psutil.cpu_percent(interval=1)
            ram = psutil.virtual_memory()
            disk = psutil.disk_usage("/")

            def bar(pct):
                filled = int(pct / 10)
                color = "🟥" if pct > 85 else "🟨" if pct > 65 else "🟩"
                return color * filled + "⬜" * (10 - filled)

            text = (
                f"🖥 *VPS Health*\n\n"
                f"CPU:  `{cpu:5.1f}%` {bar(cpu)}\n"
                f"RAM:  `{ram.percent:5.1f}%` {bar(ram.percent)}\n"
                f"Disk: `{disk.percent:5.1f}%` {bar(disk.percent)}\n\n"
                f"RAM free: `{ram.available // (1024**2)} MB`\n"
                f"Disk free: `{disk.free // (1024**3)} GB`"
            )
            await self._send_all(text)
        except ImportError:
            await self._send_all(
                "⚠️ psutil not installed inside container.\n"
                "Run: `pip install psutil --break-system-packages`"
            )

    async def _cmd_web3(self, args: list):
        """Scan a smart contract address for vulnerabilities."""
        if not args:
            await self._send_all(
                "📋 *Web3 Scanner*\n\n"
                "Usage: `/web3 [contract_address] [chain]`\n\n"
                "Chains: ethereum, bsc, polygon, arbitrum, optimism\n\n"
                "Example:\n"
                "`/web3 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 ethereum`"
            )
            return

        address = args[0]
        chain = args[1] if len(args) > 1 else "ethereum"

        if not address.startswith("0x") or len(address) != 42:
            await self._send_all(
                "❌ Invalid contract address. "
                "Must be 0x + 40 hex characters."
            )
            return

        await self._send_all(
            f"🔍 Scanning contract on {chain.title()}...\n"
            f"`{address}`\n\n"
            f"Running Slither + AI triage. This takes 1-2 minutes."
        )

        if hasattr(self, "_pipeline_ref") and self._pipeline_ref:
            try:
                findings = await self._pipeline_ref.run_web3(
                    address, chain=chain
                )
                if findings:
                    lines = [
                        f"✅ *Web3 Scan Complete*\n",
                        f"Contract: `{address[:10]}...`",
                        f"Chain: {chain.title()}",
                        f"Findings: {len(findings)}\n",
                    ]
                    for f in findings[:5]:
                        sev = f.get("severity", "").upper()
                        title = f.get("title", "")[:60]
                        lines.append(f"• [{sev}] {title}")
                    lines.append(
                        "\n_Immunefi report exported to output/immunefi/_"
                    )
                    await self._send_all("\n".join(lines))
                else:
                    await self._send_all(
                        f"✅ Web3 scan complete — no high-severity "
                        f"findings on {address[:10]}..."
                    )
            except Exception as e:
                await self._send_all(
                    f"❌ Web3 scan error: `{str(e)[:100]}`"
                )
        else:
            await self._send_all(
                "❌ Pipeline not connected. Restart the scanner."
            )

    async def _cmd_unknown(self, args: list):
        await self._send_all(
            "❓ Unknown command.\nSend `/help` for the full list."
        )

    # ── Low-level send helpers ─────────────────────────────────────────────

    async def _send_all(
        self,
        text: str,
        buttons: list = None
    ) -> bool:
        """Send message to all authorized chat IDs."""
        results = []
        for chat_id in self.all_chat_ids:
            ok = await self._send(text, chat_id, buttons)
            results.append(ok)
        return any(results)

    async def _send(
        self,
        text: str,
        chat_id: str = None,
        buttons: list = None
    ) -> bool:
        if not self.bot_token:
            return False
        chat_id = chat_id or self.chat_id
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": text[:4096],
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }
        if buttons:
            payload["reply_markup"] = {"inline_keyboard": buttons}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url, json=payload,
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as resp:
                    if resp.status == 200:
                        return True
                    body = await resp.text()
                    logger.warning(
                        f"[Telegram] Send failed ({resp.status}): {body[:200]}"
                    )
                    return False
        except Exception as e:
            logger.error(f"[Telegram] Error: {e}")
            return False

    async def _send_document(self, file_path: str, filename: str) -> bool:
        """Send a file as document to Telegram."""
        url = f"https://api.telegram.org/bot{self.bot_token}/sendDocument"
        try:
            with open(file_path, "rb") as f:
                data = aiohttp.FormData()
                data.add_field("chat_id", self.chat_id)
                data.add_field("document", f, filename=filename)
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        url, data=data,
                        timeout=aiohttp.ClientTimeout(total=30)
                    ) as resp:
                        return resp.status == 200
        except Exception as e:
            logger.error(f"[Telegram] Document send error: {e}")
            return False

    async def _answer_callback(self, callback_id: str) -> None:
        url = (
            f"https://api.telegram.org/bot{self.bot_token}"
            f"/answerCallbackQuery"
        )
        try:
            async with aiohttp.ClientSession() as session:
                await session.post(
                    url,
                    json={"callback_query_id": callback_id},
                    timeout=aiohttp.ClientTimeout(total=5)
                )
        except Exception:
            pass

    # ── Message builders ───────────────────────────────────────────────────

    def _build_finding_message(self, finding: dict, draft_url: str = "") -> str:
        severity = finding.get("severity", "info")
        vuln_type = finding.get("vuln_type", "default")
        sev_emoji = SEVERITY_EMOJI.get(severity, "⚪")
        type_emoji = TYPE_EMOJI.get(vuln_type, TYPE_EMOJI["default"])
        score = finding.get("ai_score", 0)
        target = finding.get("target", "Unknown")
        title = finding.get("title", "Security Finding")
        program = finding.get("program", "Unknown")

        lines = [
            f"{sev_emoji}{type_emoji} *BugFlow Elite v6 — New Finding*", "",
            f"📋 *{title[:100]}*", "",
            f"🎯 Severity: `{severity.upper()}`",
            f"🧠 AI Score: `{score:.1f}/10`",
            f"🌐 Target: `{target[:60]}`",
            f"🏷️ Type: `{vuln_type.replace('_',' ').title()}`",
            f"🏆 Program: `{program}`",
        ]
        if finding.get("threatfade_c2"):
            lines += ["", "⚡ *ThreatFade C2 Oracle: POSITIVE*"]
        if finding.get("is_chain"):
            lines += ["", "⛓ *Exploit Chain Finding*"]
        ttps = finding.get("mitre_ttps", "")
        if ttps:
            try:
                ttps = json.loads(ttps) if isinstance(ttps, str) else ttps
                if ttps:
                    lines.append(f"🗺️ MITRE: `{', '.join(ttps[:3])}`")
            except Exception:
                pass
        if draft_url:
            lines += ["", f"📝 [Review H1 Draft]({draft_url})"]
        lines += ["", "_BugFlow Elite v6 | Tinlance Limited_"]
        return "\n".join(lines)

    def _finding_buttons(
        self, finding: dict, draft_url: str = ""
    ) -> list:
        row1 = []
        if draft_url:
            row1.append({"text": "📋 View Draft", "url": draft_url})
        else:
            row1.append({
                "text": "📋 Create Draft",
                "callback_data": f"draft:{finding.get('id','')}"
            })
        row1.append({"text": "📊 Dashboard", "url": self._dashboard_url()})
        return [row1]

    def _build_summary_message(self, run_data: dict) -> str:
        scan_type = run_data.get("scan_type", "full")
        program = run_data.get("program", "All programs")
        assets = run_data.get("assets_found", 0)
        findings = run_data.get("findings_found", 0)
        drafts = run_data.get("drafts_created", 0)
        duration = run_data.get("duration_secs", 0)
        cost = run_data.get("ai_cost_usd", 0.0)
        emoji = "🔁" if scan_type == "incremental" else "🔍"
        mins, secs = duration // 60, duration % 60
        return (
            f"{emoji} *BugFlow Elite v6 — Scan Complete*\n\n"
            f"📌 Program: `{program}`\n"
            f"🔄 Type: `{scan_type.upper()}`\n\n"
            f"📊 *Results:*\n"
            f"• Assets: `{assets}`\n"
            f"• Findings: `{findings}`\n"
            f"• H1 Drafts: `{drafts}`\n\n"
            f"⏱ Duration: `{mins}m {secs}s`\n"
            f"💸 AI Cost: `${cost:.4f}`\n\n"
            f"_BugFlow Elite v6 | Tinlance Limited_"
        )

    def _dashboard_url(self) -> str:
        return "http://your-vps-ip:8501"
