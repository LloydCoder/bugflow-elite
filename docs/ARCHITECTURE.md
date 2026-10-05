# BugFlow Elite — Architecture

## Mission

BugFlow is a governed security-research and vulnerability-intelligence platform. Its domain authority ends at research semantics; execution authority remains with the Tinlance Agent Platform boundary.

## Data flow

`Scope/Capability Policy → Tool Fabric → Observation → Evidence → Candidate → Verification → Finding Intelligence → Disclosure Gate`

## Core layers

- `core.contracts`: stable domain types and validation.
- `core.evidence`: provenance, hashing, and evidence integrity.
- `core.tool_fabric`: bounded tool specifications and execution contracts.
- `core.attack_surface`: normalized asset graph and relationship model.
- `core.js_intelligence`: JavaScript acquisition/extraction intelligence contracts.
- `core.api_detection`: endpoint/parameter/API candidate normalization.
- `core.verification`: evidence-backed verification state.
- `core.finding_intelligence`: deduplication, novelty, history, and prioritization inputs.
- `core.disclosure`: report readiness, evidence packs, and explicit human approval.
- `core.tenant`: tenant namespace and governance audit primitives.
- `core.research_planner`: dependency-aware research planning; proposals do not grant authority.
- `core.benchmark`: deterministic benchmark/adversarial evaluation contracts.
- `core.self_security`: BugFlow's own release-control audit.
- `core.ecosystem`: typed advisory interfaces for TADS, ReconOS, FDSE, FDSE Toolkit, and World Intelligence.

## Legacy adapters

The `modules/` tree contains existing research adapters. They remain domain adapters, while new governed execution must use the core Tool Fabric and scope/capability policy. Migration is incremental because each external tool has different arguments, output schemas, evidence semantics, and operational constraints.

## Safety boundary

BugFlow must not infer authorization from a finding, threat signal, AI recommendation, or external integration. Scope and action policy are checked before execution. Disclosure is never automatic.
