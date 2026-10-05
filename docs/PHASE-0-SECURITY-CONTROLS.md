# BugFlow Elite — Phase 0 Security Controls

## Scope

This document records the controls established before additional autonomous research capabilities are enabled. It is an engineering control register, not a certification.

## Control baseline

| Control | Requirement | Implementation |
|---|---|---|
| Scope | No action against an unresolved target | ScopeEnforcer.assert_in_scope() |
| Action authorization | Scope and action class are separate gates | ScopeEnforcer.assert_action_allowed() |
| Research state | Observation/evidence/candidate/finding/verdict remain distinct | core.contracts |
| Evidence integrity | Evidence can be deterministically re-hashed | verify_evidence_hash() |
| AI authority | Model output cannot grant a verdict | AI triage returns advisory metadata |
| Threat intelligence | ThreatFade is correlation input, not severity authority | threatfade_observation |
| Disclosure | No automatic HackerOne submission | HackerOneClient.auto_submit = False |
| Secret handling | Credentials are not passed as process arguments | BBOT argv key injection removed |
| Executable trust | Optional reconFTW requires explicit enablement and path | reconftw.enabled + reconftw.path |
| Fail closed | Unknown action classes are denied | ScopeViolationError |
| Reproducibility | Canonical serialization and SHA-256 fingerprints | stable_hash() / canonical_json() |

## External baseline

BugFlow uses OWASP ASVS and WSTG for application-security control and testing methodology, NIST SSDF for secure-development practices, CVSS v4 for severity scoring, and SLSA for software-supply-chain integrity.

BBOT documentation recommends its protected secrets.yml for API keys; BugFlow therefore avoids putting BBOT API keys in command-line arguments, where they can be exposed through process inspection or diagnostics.

## Phase 0 non-goals

Phase 0 does not attempt to solve distributed execution, multi-tenancy, knowledge graphs, autonomous planning, or provider-specific disclosure workflows. Those are later phases and must consume these contracts rather than bypass them.

## Exit evidence

A phase is not considered complete until:

1. deterministic tests pass;
2. Python compilation succeeds;
3. CI quality and security jobs are green;
4. the phase documentation describes the implementation actually merged;
5. safety invariants have negative tests;
6. no new authority is created outside the Tinlance Agent Platform boundary.
