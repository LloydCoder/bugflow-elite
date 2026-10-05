# BugFlow Elite — Phase 0 Baseline

## Purpose

Phase 0 establishes the engineering contract for the repository before adding further scanners or autonomous behavior.

## Baseline findings

- The repository is Python-based and currently persists state in SQLite.
- Existing modules mix discovery, execution, evidence, AI triage, and reporting responsibilities.
- Scope enforcement exists and is a critical safety boundary, but Phase 0 treats it as a policy boundary that must be strengthened into explicit action authorization.
- Findings currently mix observations, evidence, AI scoring, and reporting metadata. The new core contracts separate observation, evidence, candidate, finding, and verdict states.
- CI previously failed because the workflow attempted to touch custom-templates/.gitkeep without creating the directory.
- The previous CI secret check also matched credential detector regexes such as AKIA in scanner source code. Phase 0 replaces that with high-confidence credential-shaped matching.
- No open PRs or open issues were present at the start of Phase 0.

## Phase 0 exit criteria

1. CI executes deterministically on Python 3.11 and 3.12.
2. Docker build succeeds.
3. Secret scanning does not produce detector-regex false positives.
4. Core domain contracts have unit coverage.
5. Safety invariants are documented.
6. No automatic disclosure submission is introduced.
7. AI remains advisory and cannot create authority.
8. Threat intelligence signals remain observations/correlation inputs, not automatic severity verdicts.

## Architecture boundary

BugFlow owns security-research domain semantics, discovery, analysis, verification, vulnerability intelligence, and disclosure preparation.

The Tinlance Agent Platform remains the authoritative governed execution layer for identity, authorization, policy, approvals, runtime, tool execution, sandboxing, secrets, budgets, evidence, audit, and observability. BugFlow must not recreate that authority.

## Research references

The implementation is aligned to OWASP ASVS 5.0.0, OWASP WSTG, NIST SSDF, CVSS v4, and SLSA 1.2 where applicable.
