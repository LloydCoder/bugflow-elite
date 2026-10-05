# BugFlow Elite — Security & Safety Model

## Trust boundaries

1. Operator or tenant — supplies authorized programs and policies.
2. BugFlow control plane — stores research state and coordinates bounded work.
3. Execution authority — Tinlance Agent Platform governs tools, approvals, secrets, budgets, sandboxing, and audit.
4. External targets — untrusted systems explicitly authorized by program scope.
5. External intelligence providers — untrusted or partially trusted data sources.
6. AI providers/models — untrusted advisory components.
7. Disclosure providers — external systems requiring explicit human approval.

## Non-negotiable invariants

- No target may be acted upon before scope and action authorization succeeds.
- Scope is not equivalent to authorization for every action; action class and rate policy are separate decisions.
- Out-of-scope resolution fails closed.
- AI output is never a security verdict by itself.
- ThreatFade/C2 observations never imply Critical severity by themselves.
- A finding must be traceable to evidence and provenance.
- Duplicate suppression may suppress draft work, but must not destroy source evidence or silently erase a candidate.
- No report is automatically submitted.
- Cloud enumeration remains detection-only unless a future explicitly authorized capability says otherwise.
- Credentials and secrets are never copied into logs, reports, telemetry, or model prompts in raw form.
- External provider failures must not cause an unsafe fallback.

## Evidence state machine

observation -> evidence -> finding_candidate -> finding -> verdict

Each transition requires explicit evidence and policy conditions. A model can recommend a transition; it cannot grant authority.

## Capability classes

- PASSIVE_RECON
- ACTIVE_RECON
- WEB_REQUEST
- PORT_SCAN
- FUZZING
- PARAM_DISCOVERY
- CLOUD_ENUM
- REPOSITORY_ANALYSIS

Each class is independently rate, budget, and policy controlled.

## Threats addressed

- Scope confusion and wildcard mistakes
- SSRF-like target pivoting through discovered infrastructure
- Tool argument injection
- Prompt injection through target-controlled content
- Credential leakage
- Evidence tampering
- Duplicate suppression hiding novel issues
- AI hallucinated verification
- Run replay and idempotency errors
- Provider API misuse
- Cross-tenant data leakage
- Unbounded scanning cost
- Unsafe autonomous disclosure

## Standards

OWASP ASVS is used for application-security control verification; OWASP WSTG informs test methodology; NIST SSDF informs secure-development process; CVSS v4 informs severity scoring; SLSA informs software supply-chain integrity.
