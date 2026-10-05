# BugFlow Elite — Phase 5 Finding Intelligence

## Objective

Turn raw and verified observations into historical, deduplicated research intelligence without allowing AI similarity or heuristics to silently suppress findings.

## Deduplication

Finding similarity combines target, vulnerability class, root cause, endpoint, parameters, impact, remediation, and optional semantic similarity. Semantic similarity is advisory. Decisions are explicit: SUPPRESS_FROM_DRAFT, REVIEW_REQUIRED, DEPRIORITIZE, or DISTINCT.

## Historical intelligence

A tenant-scoped finding history stores stable fingerprints, novelty keys, observation counts, status, and metadata. Re-observation is idempotent and increases history rather than creating duplicate records.

## Authority boundary

This phase does not declare a vulnerability confirmed. It supplies research-intelligence metadata to verification and disclosure phases. Final verdicts remain evidence-backed and policy/human controlled.
