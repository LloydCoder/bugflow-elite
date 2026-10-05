# BugFlow Elite v6

 > Governed security-research, vulnerability-intelligence, and disclosure-preparation platform.
> Built by Tinlance Limited — [github.com/LloydCoder](https://github.com/LloydCoder)

**LEGAL USE ONLY.** This tool is designed exclusively for authorized bug bounty programs on platforms such as HackerOne, Bugcrowd, and Intigriti. Never run against systems you do not have explicit written permission to test.

---

## What it does

BugFlow Elite v6 is a governed security-research and vulnerability-intelligence platform. It can discover assets, correlate attack-surface changes, generate vulnerability candidates, verify evidence, and prepare disclosure artifacts. External tool execution is bounded by scope, action policy, resource limits, and human disclosure approval.

**Research pipeline:**

1. **Recon** — BBOT recursive OSINT + crt.sh passive cert transparency. Discovers 20–50% more subdomains than single-tool approaches.
2. **Shodan Intelligence** — Passive port enrichment via InternetDB (free, no auth). Favicon hash pivot via FavFreak to identify running tech stack.
3. **Subdomain Takeover** — BadDNS + subjack across CNAME, NS, MX, SPF, A records + HTTP fingerprint matching against 20+ provider signatures.
4. **Cloud Asset Enum** — Discovers public AWS S3, GCS, Azure buckets via keyword permutations. Detection only — never writes.
5. **JS Intelligence** — gau → waymore → subjs → jsluice → manual regex. Extracts hidden API endpoints and leaked secrets from JavaScript files.
6. **Secret Scanning** — TruffleHog (URLs + GitHub org) + GitHound (GitHub Code Search). Flags AWS keys, JWT secrets, API tokens.
7. **Visual Recon** — Gowitness screenshots of all live subdomains. Flags admin panels, login pages, and exposed dashboards.
8. **Playwright Crawl + Param Discovery** — JS-rendered page crawling + Arjun parameter discovery. Flags high-value parameters for IDOR, SSRF, SQLi, RCE.
9. **Nuclei Scanning** — Curated high-ROI templates + AI-generated custom templates for discovered tech stacks.

**AI triage stack:** Ollama (local, free) → Grok → Claude. Every finding gets an exploitability score, MITRE TTP mapping, and a polished HackerOne draft summary.

**Research moat:** discovery × correlation × evidence × verification × novelty × continuous change detection × historical intelligence. ThreatFade is an intelligence signal source, not a severity authority.

---

## Quickstart

### Prerequisites

- Docker + Docker Compose
- Contabo VPS (or any Ubuntu 22/24 server with 4GB+ RAM)
- At least one active bug bounty program you're authorized to test

### Deploy

```bash
git clone https://github.com/LloydCoder/bugflow-elite.git
cd bugflow-elite

# Configure API keys
cp .env.example .env
nano .env   # Fill in your keys

# Configure your target program
nano config/scope/manual_scope.yaml
# Set active: true and add your in-scope domains

# Start everything
docker-compose up -d

# Watch logs
docker-compose logs -f bugflow
```

### Access the Dashboard

```
http://your-vps-ip:8501
```

### Manual scan (one-off)

```bash
# Incremental (fast, new assets only)
docker exec bugflow-elite python main.py example.com incremental

# Full scan
docker exec bugflow-elite python main.py example.com full
```

---

## Configuration

Everything lives in `config/config.yaml`. The most important settings:

| Setting | Default | Notes |
|---|---|---|
| `scheduler.incremental_interval_hours` | 6 | How often to run a light scan |
| `scheduler.full_scan_interval_hours` | 24 | How often to run a full scan |
| `ai.cost_guard.max_daily_usd` | 2.00 | Hard cap on AI API spend |
| `ai.scoring.min_score_for_draft` | 7.0 | Minimum score to create H1 draft |
| `hackerone.auto_submit` | false | **Must remain false; human approval is mandatory** |
| `network.verify_tls` | true | TLS verification for network probes |
| `scope.allowed_actions` | explicit allowlist | Capability classes are separately governed |
| `recon.bbot.enabled` | false | Requires an explicit trusted executable path |

All API keys can be set via environment variables. See `.env.example` for the full list.

---

## Scope configuration

Edit `config/scope/manual_scope.yaml`:

```yaml
programs:
  - name: "YourProgram"
    platform: "hackerone"
    active: true
    in_scope:
      domains:
        - "*.example.com"
        - "example.com"
    out_of_scope:
      domains:
        - "blog.example.com"
```

BugFlow also auto-fetches scope from [bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data) every 6 hours for HackerOne, Bugcrowd, and Intigriti programs.

---

## Safety guardrails

These are hardcoded and cannot be overridden by configuration:

- **Scope enforcer** runs before every single tool call. Any target not in scope raises `ScopeViolationError` and is immediately blocked.
- **`auto_submit = False`** is set in `HackerOneClient.__init__` directly in code — not from config. Every draft requires human review.
- **Cloud scanning** is detection only. The platform never writes to, deletes from, or modifies any storage bucket.
- **ThreatFade** reports detections — it never weaponizes or exploits C2 infrastructure.
- **Rate limiting + stealth delays** are applied on all outbound requests.

---

## Architecture

The repository is organized around a strict separation of concerns:

- `core/` — stable research contracts, evidence, graphing, execution fabric, intelligence, verification, disclosure, planning, benchmarking, security, and ecosystem interfaces.
- `modules/` — domain-specific adapters and existing research engines.
- `db/` — persistent state and schema.
- `docs/` — phase control records and threat model.

The target authority flow is:

`Scope/Capability Policy → Tool Fabric → Observation → Evidence → Candidate → Verification → Finding Intelligence → Disclosure Gate`

The Tinlance Agent Platform remains the authoritative execution-governance layer; BugFlow's domain modules must not recreate that authority.

```
bugflow-elite/
├── config/
│   ├── config.yaml              # Master config
│   └── scope/
│       └── manual_scope.yaml    # Your authorized programs
├── db/
│   └── models.py                # SQLite schema
├── modules/
│   ├── recon/
│   │   ├── bbot_engine.py       # BBOT + crt.sh
│   │   └── shodan_intel.py      # InternetDB + FavFreak
│   ├── crawler/
│   │   ├── js_hunter.py         # gau + waymore + subjs + jsluice
│   │   ├── playwright_crawl.py  # Headless browser crawl
│   │   └── param_intel.py       # Arjun + cariddi
│   ├── scanner/
│   │   ├── takeover.py          # BadDNS + subjack
│   │   ├── cloud_enum.py        # S3/GCS/Azure bucket enum
│   │   ├── nuclei_runner.py     # Nuclei v3 + AI template gen
│   │   └── trufflehog.py        # TruffleHog + GitHound
│   ├── triage/
│   │   └── ai_engine.py         # Ollama→Grok→Claude + dedup + ThreatFade
│   ├── reports/
│   │   └── hackerone.py         # H1 draft creation (never auto-submits)
│   ├── notify/
│   │   └── telegram.py          # Rich Telegram alerts
│   ├── scope/
│   │   └── scope_enforcer.py    # Hard scope gate
│   └── vision/
│       └── screenshots.py       # Gowitness + panel detection
├── dashboard/
│   └── app.py                   # Streamlit dashboard
├── scheduler/
│   └── tasks.py                 # APScheduler 6h/24h
├── main.py                      # Pipeline orchestrator
├── Dockerfile
└── docker-compose.yml
```

---

## Running tests

```bash
pip install -r requirements.txt
pytest tests/ -v
python -m compileall -q .
```

CI also runs dedicated release gates for every enterprise build program. The gate suite covers domain contracts, evidence integrity, tool execution, attack-surface graphing, API/detection contracts, verification, finding intelligence, disclosure quality, tenant/audit controls, autonomous research planning, benchmarking, self-security, and ecosystem integration.

The test suite covers: database CRUD, scope enforcement, H1 draft logic, AI JSON parsing, cost guard, cloud severity, takeover fingerprints, Telegram alerts, and config validation.

---

## Environment variables

| Variable | Required | Notes |
|---|---|---|
| `H1_API_TOKEN` | For drafts | HackerOne API token |
| `H1_USERNAME` | For drafts | Your HackerOne username |
| `TELEGRAM_BOT_TOKEN` | For alerts | Telegram bot token |
| `TELEGRAM_CHAT_ID` | For alerts | Target chat/channel ID |
| `XAI_API_KEY` | Optional | Grok API fallback |
| `ANTHROPIC_API_KEY` | Optional | Claude API fallback |
| `GITHUB_TOKEN` | Recommended | Better recon coverage |
| `SHODAN_API_KEY` | Optional | Favicon hash pivot |
| `THREATFADE_URL` | Optional | Your ThreatFade endpoint |

---

## ThreatFade integration

BugFlow integrates with [ThreatFade](https://github.com/LloydCoder/tinlance-threatfade), the C2 evasion detection engine built on Z-score analysis, MITRE TTP mapping, and entropy-based signature detection.

When ThreatFade is running at `THREATFADE_URL`, BugFlow checks every newly discovered host against the C2 oracle. A positive detection is recorded as an intelligence observation and correlated with independent evidence. It does not by itself set severity, create a verdict, or bypass verification.

Set `THREATFADE_URL` in your `.env` to enable this.

---

## Legal notice

This software is provided for use exclusively on systems and applications for which you have explicit, written authorization to perform security testing. Unauthorized use against systems you do not own or have permission to test is illegal and unethical.

Tinlance Limited and the contributors of BugFlow Elite accept no liability for misuse of this software.

---

*BugFlow Elite v6 | Tinlance Limited | [github.com/LloydCoder](https://github.com/LloydCoder)*


## Enterprise engineering status

The repository has completed the sequential enterprise build programs currently defined in docs/ROADMAP.md (Foundation through Ecosystem). Each program was implemented on a branch, audited, tested, and merged only after the full GitHub Actions suite was green. The dedicated phase gates remain in CI as regression guards.

See docs/ROADMAP.md for the authoritative mapping, and docs/FINAL-FORENSIC-AUDIT.md for the post-build audit.

The enterprise architecture separates:
- observation from evidence;
- evidence from finding candidates;
- candidates from findings and verdicts;
- discovery from governed execution;
- intelligence signals from severity decisions;
- report preparation from disclosure submission.

BugFlow consumes the Tinlance Agent Platform as the authoritative execution-governance layer. It does not duplicate identity, authorization, policy, approvals, sandboxing, secrets, budgets, audit, or runtime authority.

## Security standards

The engineering baseline references OWASP ASVS, OWASP WSTG, NIST SSDF, CVSS v4, and SLSA. Standards are used as engineering controls and traceability references, not as claims of certification.

## Phase 0 safety model

See docs/THREAT-MODEL.md. In particular, AI output is advisory, discovered infrastructure does not automatically become authorized scope, ThreatFade observations do not automatically become Critical findings, and no report is automatically submitted.
