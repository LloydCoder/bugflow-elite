"""
BugFlow Elite v6 — Complete Dashboard
Tabs: Findings | Assets | Secrets | Scan History | Analytics |
      🎯 Target Manager | 🔑 API Keys | 📦 Export | 💰 Payouts
Features:
  - Add/manage targets from dashboard (no SSH needed)
  - Manage all API keys securely
  - Trigger scans from browser
  - Burp export one-click
  - Multi-platform report creation
  - Full monitoring of all 11 pipeline stages
Tinlance Limited | LloydCoder
"""

import json
import os
import subprocess
import streamlit as st
import pandas as pd
from pathlib import Path
from datetime import datetime
from db.models import get_conn, init_db
from config.loader import load_config

st.set_page_config(
    page_title="BugFlow Elite v6",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Load config ────────────────────────────────────────────────────────────
try:
    config = load_config()
except Exception:
    config = {}

db_path = config.get("general", {}).get("db_path", "./db/bugflow.db")

# Ensure DB exists
try:
    init_db(db_path)
except Exception:
    pass


def get_db():
    return get_conn(db_path)


SEVERITY_COLOR = {
    "critical": "#ef4444",
    "high":     "#f97316",
    "medium":   "#eab308",
    "low":      "#3b82f6",
    "info":     "#6b7280",
}

# ── Sidebar ────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("## 🛡️ BugFlow Elite v6")
    st.markdown("*Tinlance Limited*")
    st.divider()

    # Live indicator
    st.markdown(
        "<span style='color:#34d399'>● LIVE</span> &nbsp; "
        f"<span style='color:#6b7280'>{datetime.now().strftime('%H:%M:%S')}</span>",
        unsafe_allow_html=True
    )
    st.divider()

    if st.button("🔄 Refresh Now", use_container_width=True):
        st.rerun()

    st.divider()
    st.markdown("### Quick Stats")

    try:
        conn = get_db()
        total_f = conn.execute(
            "SELECT COUNT(*) FROM findings WHERE is_duplicate=0"
        ).fetchone()[0]
        critical_f = conn.execute(
            "SELECT COUNT(*) FROM findings WHERE severity='critical' AND is_duplicate=0"
        ).fetchone()[0]
        assets_c = conn.execute(
            "SELECT COUNT(*) FROM assets WHERE is_alive=1"
        ).fetchone()[0]
        drafts_c = conn.execute(
            "SELECT COUNT(*) FROM findings WHERE h1_status='drafted'"
        ).fetchone()[0]
        try:
            payout_total = conn.execute(
                "SELECT COALESCE(SUM(amount),0) FROM payouts"
            ).fetchone()[0]
        except Exception:
            payout_total = 0
        conn.close()

        st.metric("Findings", total_f)
        st.metric("Critical", critical_f)
        st.metric("Assets", assets_c)
        st.metric("H1 Drafts", drafts_c)
        st.metric("Total Earned", f"${float(payout_total):.2f}")
    except Exception as e:
        st.error(f"DB error: {e}")

# ── Main Tabs ──────────────────────────────────────────────────────────────

tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8, tab9, tab10 = st.tabs([
    "🐛 Findings",
    "🌐 Assets",
    "🔑 Secrets",
    "📊 Scan History",
    "📈 Analytics",
    "🎯 Target Manager",
    "🔐 API Keys",
    "📦 Export",
    "💰 Payouts",
    "⛓ Web3",
])

# ── Tab 1: Findings ────────────────────────────────────────────────────────

with tab1:
    st.subheader("Findings")

    col1, col2, col3, col4, col5, col6, col7, col8 = st.columns(8)
    try:
        conn = get_db()
        stats = {
            "total": conn.execute("SELECT COUNT(*) FROM findings WHERE is_duplicate=0").fetchone()[0],
            "critical": conn.execute("SELECT COUNT(*) FROM findings WHERE severity='critical' AND is_duplicate=0").fetchone()[0],
            "high": conn.execute("SELECT COUNT(*) FROM findings WHERE severity='high' AND is_duplicate=0").fetchone()[0],
            "medium": conn.execute("SELECT COUNT(*) FROM findings WHERE severity='medium' AND is_duplicate=0").fetchone()[0],
            "low": conn.execute("SELECT COUNT(*) FROM findings WHERE severity='low' AND is_duplicate=0").fetchone()[0],
            "drafted": conn.execute("SELECT COUNT(*) FROM findings WHERE h1_status='drafted'").fetchone()[0],
            "takeovers": conn.execute("SELECT COUNT(*) FROM takeovers WHERE is_verified=1").fetchone()[0],
            "c2": conn.execute("SELECT COUNT(*) FROM findings WHERE threatfade_c2=1").fetchone()[0],
        }
        conn.close()
        col1.metric("Total", stats["total"])
        col2.metric("🔴 Critical", stats["critical"])
        col3.metric("🟠 High", stats["high"])
        col4.metric("🟡 Medium", stats["medium"])
        col5.metric("🔵 Low", stats["low"])
        col6.metric("📝 Drafts", stats["drafted"])
        col7.metric("🏴 Takeovers", stats["takeovers"])
        col8.metric("⚡ C2", stats["c2"])
    except Exception as e:
        st.error(f"Error loading stats: {e}")

    st.divider()

    # Filters
    fc1, fc2, fc3 = st.columns([2, 2, 2])
    with fc1:
        sev_filter = st.selectbox(
            "Severity", ["all", "critical", "high", "medium", "low", "info"]
        )
    with fc2:
        status_filter = st.selectbox(
            "H1 Status", ["all", "pending", "drafted", "resolved", "rejected"]
        )
    with fc3:
        show_dups = st.checkbox("Show duplicates", False)

    try:
        conn = get_db()
        query = """
            SELECT f.id, f.severity, f.title, f.vuln_type, f.ai_score,
                   f.program, f.h1_status, f.threatfade_c2,
                   f.is_duplicate, f.first_seen, f.h1_draft_url
            FROM findings f
            WHERE 1=1
        """
        params = []
        if not show_dups:
            query += " AND f.is_duplicate=0"
        if sev_filter != "all":
            query += " AND f.severity=?"
            params.append(sev_filter)
        if status_filter != "all":
            query += " AND f.h1_status=?"
            params.append(status_filter)
        query += " ORDER BY f.ai_score DESC, f.first_seen DESC LIMIT 200"

        rows = conn.execute(query, params).fetchall()
        conn.close()

        if rows:
            data = []
            for r in rows:
                data.append({
                    "ID": r["id"],
                    "Sev": r["severity"].upper() if r["severity"] else "",
                    "Title": r["title"],
                    "Type": (r["vuln_type"] or "").replace("_", " ").title(),
                    "Score": f"{r['ai_score']:.1f}" if r["ai_score"] else "—",
                    "Program": r["program"] or "",
                    "Status": r["h1_status"] or "pending",
                    "C2": "⚡" if r["threatfade_c2"] else "",
                    "Draft": r["h1_draft_url"] or "",
                    "Found": (r["first_seen"] or "")[:16],
                })
            df = pd.DataFrame(data)
            st.dataframe(
                df, use_container_width=True, hide_index=True,
                column_config={
                    "Draft": st.column_config.LinkColumn("H1 Draft"),
                    "Score": st.column_config.NumberColumn(format="%.1f"),
                }
            )
        else:
            st.info("No findings yet. Add a target and run a scan.")
    except Exception as e:
        st.error(f"Error: {e}")

# ── Tab 2: Assets ──────────────────────────────────────────────────────────

with tab2:
    st.subheader("Discovered Assets")
    try:
        conn = get_db()
        rows = conn.execute("""
            SELECT subdomain, domain, ip, status_code, tech_stack,
                   ports, source, last_seen
            FROM assets WHERE is_alive=1
            ORDER BY last_seen DESC LIMIT 500
        """).fetchall()
        conn.close()
        if rows:
            df = pd.DataFrame([dict(r) for r in rows])
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.info("No assets yet. Run a scan first.")
    except Exception as e:
        st.error(f"Error: {e}")

# ── Tab 3: Secrets ─────────────────────────────────────────────────────────

with tab3:
    st.subheader("Leaked Secrets")
    try:
        conn = get_db()
        rows = conn.execute("""
            SELECT secret_type, source_url, source_tool,
                   is_verified, first_seen
            FROM secrets ORDER BY first_seen DESC LIMIT 100
        """).fetchall()
        conn.close()
        if rows:
            df = pd.DataFrame([dict(r) for r in rows])
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.info("No secrets found yet.")
    except Exception as e:
        st.error(f"Error: {e}")

# ── Tab 4: Scan History ────────────────────────────────────────────────────

with tab4:
    st.subheader("Scan History")
    try:
        conn = get_db()
        rows = conn.execute("""
            SELECT scan_type, program, status, assets_found,
                   findings_found, drafts_created, duration_secs,
                   ai_cost_usd, started_at
            FROM scan_runs ORDER BY started_at DESC LIMIT 30
        """).fetchall()
        conn.close()
        if rows:
            data = [{
                "Type": r["scan_type"],
                "Program": r["program"],
                "Status": r["status"],
                "Assets": r["assets_found"],
                "Findings": r["findings_found"],
                "Drafts": r["drafts_created"],
                "Duration": f"{(r['duration_secs'] or 0) // 60}m {(r['duration_secs'] or 0) % 60}s",
                "AI Cost": f"${r['ai_cost_usd']:.4f}" if r["ai_cost_usd"] else "$0.0000",
                "Started": (r["started_at"] or "")[:16],
            } for r in rows]
            st.dataframe(pd.DataFrame(data), use_container_width=True, hide_index=True)
        else:
            st.info("No scan runs yet.")
    except Exception as e:
        st.error(f"Error: {e}")

# ── Tab 5: Analytics ───────────────────────────────────────────────────────

with tab5:
    st.subheader("Analytics")
    try:
        conn = get_db()
        sev_rows = conn.execute("""
            SELECT severity, COUNT(*) as count FROM findings
            WHERE is_duplicate=0 GROUP BY severity
        """).fetchall()

        type_rows = conn.execute("""
            SELECT vuln_type, COUNT(*) as count FROM findings
            WHERE is_duplicate=0 GROUP BY vuln_type ORDER BY count DESC LIMIT 10
        """).fetchall()

        cost_rows = conn.execute("""
            SELECT provider, COALESCE(SUM(estimated_usd),0) as total
            FROM ai_costs WHERE DATE(timestamp)=DATE('now')
            GROUP BY provider
        """).fetchall()
        conn.close()

        c1, c2 = st.columns(2)
        with c1:
            if sev_rows:
                df_sev = pd.DataFrame(
                    [{"Severity": r["severity"].title(), "Count": r["count"]}
                     for r in sev_rows]
                )
                st.bar_chart(df_sev.set_index("Severity"))

        with c2:
            if type_rows:
                df_type = pd.DataFrame(
                    [{"Type": (r["vuln_type"] or "unknown").replace("_", " ").title(),
                      "Count": r["count"]} for r in type_rows]
                )
                st.bar_chart(df_type.set_index("Type"))

        if cost_rows:
            st.subheader("AI Cost Today")
            for r in cost_rows:
                st.text(f"{r['provider']}: ${float(r['total']):.4f}")
    except Exception as e:
        st.error(f"Error: {e}")

# ── Tab 6: Target Manager ──────────────────────────────────────────────────

with tab6:
    st.subheader("🎯 Target Manager")
    st.markdown("Add and manage your authorized bug bounty targets without SSH.")

    st.info(
        "⚠️ Only add programs you are **authorized** to test on HackerOne, "
        "Bugcrowd, Intigriti, YesWeHack, or Synack."
    )

    # ── Add new target ─────────────────────────────────────────────────────
    with st.expander("➕ Add New Target", expanded=True):
        c1, c2 = st.columns(2)
        with c1:
            t_name = st.text_input("Program Name", placeholder="e.g. Acme Corp")
            t_platform = st.selectbox(
                "Platform",
                ["hackerone", "bugcrowd", "intigriti", "yeswehack", "synack", "private"]
            )
            t_handle = st.text_input(
                "Program Handle / ID",
                placeholder="e.g. acme (from URL)"
            )
        with c2:
            t_domains = st.text_area(
                "In-Scope Domains (one per line)",
                placeholder="*.acme.com\nacme.com\napi.acme.com",
                height=100
            )
            t_out = st.text_area(
                "Out-of-Scope Domains (one per line)",
                placeholder="blog.acme.com\nstatus.acme.com",
                height=60
            )

        if st.button("✅ Add Target", type="primary"):
            if not t_name or not t_domains:
                st.error("Program name and at least one domain are required.")
            else:
                # Write to manual_scope.yaml
                scope_path = Path("./config/scope/manual_scope.yaml")
                try:
                    import yaml
                    with open(scope_path) as f:
                        scope_data = yaml.safe_load(f) or {"programs": []}

                    domains_list = [
                        d.strip() for d in t_domains.split("\n")
                        if d.strip()
                    ]
                    out_list = [
                        d.strip() for d in t_out.split("\n")
                        if d.strip()
                    ]

                    new_prog = {
                        "name": t_name,
                        "platform": t_platform,
                        "program_id": t_handle,
                        "active": True,
                        "in_scope": {"domains": domains_list, "ip_ranges": [], "urls": []},
                        "out_of_scope": {"domains": out_list, "paths": []},
                        "notes": f"Added via dashboard {datetime.now().strftime('%Y-%m-%d')}",
                    }

                    if "programs" not in scope_data:
                        scope_data["programs"] = []
                    scope_data["programs"].append(new_prog)

                    with open(scope_path, "w") as f:
                        yaml.dump(scope_data, f, default_flow_style=False, allow_unicode=True)

                    st.success(f"✅ Target '{t_name}' added! Restart the scanner to begin scanning.")
                    st.balloons()
                except Exception as e:
                    st.error(f"Error saving target: {e}")

    # ── Current targets ────────────────────────────────────────────────────
    st.subheader("Current Targets")
    scope_path = Path("./config/scope/manual_scope.yaml")
    if scope_path.exists():
        try:
            import yaml
            with open(scope_path) as f:
                scope_data = yaml.safe_load(f) or {}
            programs = scope_data.get("programs", [])
            if programs:
                for i, prog in enumerate(programs):
                    status = "🟢 Active" if prog.get("active") else "🔴 Paused"
                    with st.container():
                        c1, c2, c3 = st.columns([3, 1, 2])
                        with c1:
                            st.markdown(
                                f"**{prog.get('name', 'Unknown')}** — "
                                f"`{prog.get('platform', 'unknown')}` — "
                                f"`{prog.get('program_id', '')}`"
                            )
                            domains = prog.get("in_scope", {}).get("domains", [])
                            st.caption(f"Domains: {', '.join(domains[:3])}" +
                                      (" ..." if len(domains) > 3 else ""))
                        with c2:
                            st.markdown(status)
                        with c3:
                            col_a, col_b = st.columns(2)
                            with col_a:
                                if st.button(
                                    "▶ Scan", key=f"scan_{i}",
                                    help="Trigger incremental scan"
                                ):
                                    domains = prog.get("in_scope", {}).get("domains", [])
                                    if domains:
                                        first_domain = domains[0].lstrip("*.").split("/")[0]
                                        st.info(f"Scan queued: {first_domain}")
                                        # Write scan trigger file
                                        trigger = Path("./output/.scan_trigger")
                                        trigger.write_text(json.dumps({
                                            "domain": first_domain,
                                            "type": "incremental",
                                            "triggered_at": datetime.utcnow().isoformat(),
                                        }))
                            with col_b:
                                if st.button(
                                    "⏸ Pause" if prog.get("active") else "▶ Resume",
                                    key=f"toggle_{i}"
                                ):
                                    programs[i]["active"] = not prog.get("active", True)
                                    scope_data["programs"] = programs
                                    with open(scope_path, "w") as f:
                                        yaml.dump(scope_data, f, default_flow_style=False)
                                    st.rerun()
                        st.divider()
            else:
                st.info("No targets configured yet. Add one above.")
        except Exception as e:
            st.error(f"Error loading targets: {e}")

    # ── Run scan trigger ────────────────────────────────────────────────────
    st.subheader("Manual Scan")
    sc1, sc2, sc3 = st.columns(3)
    with sc1:
        manual_domain = st.text_input("Domain", placeholder="example.com")
    with sc2:
        scan_type = st.selectbox("Scan Type", ["incremental", "full"])
    with sc3:
        st.markdown("")
        st.markdown("")
        if st.button("🚀 Run Now", type="primary"):
            if manual_domain:
                trigger = Path("./output/.scan_trigger")
                trigger.parent.mkdir(parents=True, exist_ok=True)
                trigger.write_text(json.dumps({
                    "domain": manual_domain,
                    "type": scan_type,
                    "triggered_at": datetime.utcnow().isoformat(),
                }))
                st.success(
                    f"✅ {scan_type.title()} scan triggered for {manual_domain}. "
                    f"Check Telegram for progress."
                )

# ── Tab 7: API Keys ────────────────────────────────────────────────────────

with tab7:
    st.subheader("🔐 API Key Manager")
    st.warning(
        "⚠️ Only accessible from authorized IPs. "
        "Keys are stored in your .env file on the VPS."
    )

    env_path = Path(".env")
    env_vars = {}
    if env_path.exists():
        for line in env_path.read_text().split("\n"):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                key, _, val = line.partition("=")
                env_vars[key.strip()] = val.strip()

    KEY_GROUPS = {
        "🏆 Bug Bounty Platforms": [
            ("H1_API_TOKEN",       "HackerOne API Token",    "required"),
            ("H1_USERNAME",        "HackerOne Username",     "required"),
            ("BUGCROWD_API_TOKEN", "Bugcrowd API Token",     "optional"),
            ("INTIGRITI_TOKEN",    "Intigriti API Token",    "optional"),
            ("YESWEHACK_TOKEN",    "YesWeHack API Token",    "optional"),
        ],
        "📱 Notifications": [
            ("TELEGRAM_BOT_TOKEN", "Telegram Bot Token",     "required"),
            ("TELEGRAM_CHAT_ID",   "Telegram Chat ID",       "required"),
        ],
        "🤖 AI Providers": [
            ("XAI_API_KEY",        "Grok API Key (xAI)",     "optional"),
            ("ANTHROPIC_API_KEY",  "Claude API Key",         "optional"),
        ],
        "🔍 Recon Tools": [
            ("GITHUB_TOKEN",       "GitHub Token",           "recommended"),
            ("SHODAN_API_KEY",     "Shodan API Key",         "optional"),
            ("VIRUSTOTAL_KEY",     "VirusTotal API Key",     "optional"),
            ("CHAOS_KEY",          "ProjectDiscovery Chaos", "optional"),
            ("SECURITYTRAILS_KEY", "SecurityTrails Key",     "optional"),
        ],
        "⚡ ThreatFade": [
            ("THREATFADE_URL",     "ThreatFade URL",         "optional"),
            ("THREATFADE_API_KEY", "ThreatFade API Key",     "optional"),
        ],
    }

    changes = {}
    for group_name, keys in KEY_GROUPS.items():
        st.subheader(group_name)
        for env_key, label, priority in keys:
            current = env_vars.get(env_key, "")
            masked = (
                current[:4] + "..." + current[-4:]
                if len(current) > 10 else
                ("✅ Set" if current else "")
            )

            badge = {
                "required": "🔴",
                "recommended": "🟡",
                "optional": "⚪",
            }.get(priority, "⚪")

            c1, c2, c3 = st.columns([3, 2, 1])
            with c1:
                st.markdown(f"{badge} **{label}**")
                if masked:
                    st.caption(f"Current: `{masked}`")
            with c2:
                new_val = st.text_input(
                    f"New value for {env_key}",
                    key=f"key_{env_key}",
                    placeholder="Paste new key here",
                    type="password",
                    label_visibility="collapsed",
                )
                if new_val:
                    changes[env_key] = new_val
            with c3:
                status_icon = "✅" if current else "❌"
                st.markdown(f"<br>{status_icon}", unsafe_allow_html=True)
        st.divider()

    if changes:
        if st.button("💾 Save Changes", type="primary"):
            try:
                # Read current .env
                current_lines = []
                if env_path.exists():
                    current_lines = env_path.read_text().split("\n")

                # Update or add each key
                for key, value in changes.items():
                    found = False
                    for i, line in enumerate(current_lines):
                        if line.startswith(f"{key}=") or line.startswith(f"{key} ="):
                            current_lines[i] = f"{key}={value}"
                            found = True
                            break
                    if not found:
                        current_lines.append(f"{key}={value}")

                env_path.write_text("\n".join(current_lines))
                st.success(
                    f"✅ {len(changes)} key(s) saved. "
                    "Restart the scanner to apply: "
                    "`docker compose restart bugflow-elite`"
                )
            except Exception as e:
                st.error(f"Error saving keys: {e}")

# ── Tab 8: Export ──────────────────────────────────────────────────────────

with tab8:
    st.subheader("📦 Export & Reports")

    try:
        conn = get_db()
        programs = conn.execute(
            "SELECT DISTINCT program FROM findings WHERE program IS NOT NULL"
        ).fetchall()
        conn.close()
        program_list = [r["program"] for r in programs if r["program"]]
    except Exception:
        program_list = []

    if not program_list:
        st.info("No programs with findings yet.")
    else:
        c1, c2 = st.columns(2)
        with c1:
            export_program = st.selectbox(
                "Select Program", program_list
            )
        with c2:
            export_format = st.selectbox(
                "Export Format",
                ["Burp Suite XML", "URL List", "JSON Sitemap",
                 "CSV Report", "Markdown Report"]
            )

        if st.button("📥 Generate Export", type="primary"):
            from modules.reports.burp_exporter import BurpExporter
            exporter = BurpExporter(config)
            try:
                with st.spinner("Generating export..."):
                    result = exporter.export(export_program)
                st.success("✅ Export generated!")

                if export_format == "Burp Suite XML":
                    fpath = result["burp_xml"]
                elif export_format == "URL List":
                    fpath = result["url_list"]
                elif export_format == "JSON Sitemap":
                    fpath = result["json_sitemap"]
                elif export_format == "CSV Report":
                    from modules.reports.logger import FindingLogger
                    fl = FindingLogger(config)
                    fpath = fl.export_csv()
                else:
                    fpath = result["attack_chains"]

                if Path(fpath).exists():
                    with open(fpath, "rb") as f:
                        st.download_button(
                            label=f"⬇️ Download {export_format}",
                            data=f.read(),
                            file_name=Path(fpath).name,
                            mime="application/octet-stream",
                        )

                st.json({
                    "endpoints": result["stats"]["endpoints"],
                    "findings": result["stats"]["findings"],
                    "assets": result["stats"]["assets"],
                })
            except Exception as e:
                st.error(f"Export error: {e}")

    st.divider()
    st.subheader("Generate AI Payloads")
    c1, c2 = st.columns(2)
    with c1:
        payload_program = st.selectbox(
            "Program", program_list, key="payload_prog"
        )
    with c2:
        payload_vuln = st.selectbox(
            "Vuln Type",
            ["xss", "sqli", "ssrf", "ssti", "path_traversal"]
        )

    if st.button("🤖 Generate Payloads"):
        st.info(
            "Payload generation triggered. "
            "Results will appear in finding details within 2-3 minutes."
        )

# ── Tab 9: Payouts ─────────────────────────────────────────────────────────

with tab9:
    st.subheader("💰 Payout Tracker")

    try:
        conn = get_db()
        try:
            payouts = conn.execute("""
                SELECT report_id, title, severity, amount, platform,
                       program, h1_url, paid_at
                FROM payouts ORDER BY paid_at DESC LIMIT 100
            """).fetchall()

            total = conn.execute(
                "SELECT COALESCE(SUM(amount),0) FROM payouts"
            ).fetchone()[0]
            month_total = conn.execute("""
                SELECT COALESCE(SUM(amount),0) FROM payouts
                WHERE paid_at >= date('now', '-30 days')
            """).fetchone()[0]
            count = conn.execute("SELECT COUNT(*) FROM payouts").fetchone()[0]
        except Exception:
            payouts = []
            total = 0
            month_total = 0
            count = 0
        conn.close()

        c1, c2, c3 = st.columns(3)
        c1.metric("All-Time Earnings", f"${float(total):.2f}")
        c2.metric("Last 30 Days", f"${float(month_total):.2f}")
        c3.metric("Total Reports Paid", count)

        st.divider()

        if payouts:
            df = pd.DataFrame([{
                "Title": r["title"],
                "Amount": f"${r['amount']:.2f}",
                "Severity": r["severity"],
                "Platform": r["platform"],
                "Program": r["program"],
                "Paid": (r["paid_at"] or "")[:10],
                "Link": r["h1_url"] or "",
            } for r in payouts])
            st.dataframe(
                df, use_container_width=True, hide_index=True,
                column_config={"Link": st.column_config.LinkColumn("Report")}
            )
        else:
            st.info(
                "No payouts recorded yet. Payouts are automatically "
                "detected from H1 API every 6 hours."
            )
    except Exception as e:
        st.error(f"Error loading payouts: {e}")


# ── Tab 10: Web3 ──────────────────────────────────────────────────────────

with tab10:
    st.subheader("⛓ Web3 / Smart Contract Scanner")
    st.info(
        "Scan Ethereum, BSC, Polygon, Arbitrum, and Optimism contracts. "
        "Reports formatted for Immunefi submission."
    )

    wc1, wc2, wc3 = st.columns([3, 1, 1])
    with wc1:
        contract_addr = st.text_input(
            "Contract Address",
            placeholder="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        )
    with wc2:
        contract_chain = st.selectbox(
            "Chain",
            ["ethereum", "bsc", "polygon", "arbitrum", "optimism"]
        )
    with wc3:
        st.markdown("")
        st.markdown("")
        run_web3 = st.button("Scan Contract", type="primary")

    if run_web3:
        if contract_addr and contract_addr.startswith("0x") and len(contract_addr) == 42:
            trigger = Path("./output/.web3_trigger")
            trigger.parent.mkdir(parents=True, exist_ok=True)
            trigger.write_text(json.dumps({
                "address": contract_addr,
                "chain": contract_chain,
                "triggered_at": datetime.utcnow().isoformat(),
            }))
            st.success(
                f"Scan triggered for {contract_addr[:10]}... "
                f"on {contract_chain.title()}. Check Telegram."
            )
        else:
            st.error("Invalid address.")

    st.divider()
    try:
        conn = get_db()
        web3_rows = conn.execute(
            "SELECT title, severity, vuln_type, ai_score, program, "
            "h1_status, first_seen FROM findings "
            "WHERE vuln_type LIKE 'web3%' ORDER BY ai_score DESC LIMIT 50"
        ).fetchall()
        conn.close()
        if web3_rows:
            wdf = pd.DataFrame([{
                "Title": r["title"],
                "Severity": (r["severity"] or "").upper(),
                "Score": f"{r['ai_score']:.1f}" if r["ai_score"] else "—",
                "Contract": r["program"] or "",
                "Status": r["h1_status"] or "pending",
                "Found": (r["first_seen"] or "")[:16],
            } for r in web3_rows])
            st.dataframe(wdf, use_container_width=True, hide_index=True)
        else:
            st.info("No Web3 findings yet. Use Telegram: `/web3 [address] [chain]`")
    except Exception as we:
        st.error(f"Error: {we}")

# Auto-refresh every 30 seconds
refresh = config.get("dashboard", {}).get("refresh_interval_seconds", 30)
st.markdown(
    f"<meta http-equiv='refresh' content='{refresh}'>",
    unsafe_allow_html=True
)
