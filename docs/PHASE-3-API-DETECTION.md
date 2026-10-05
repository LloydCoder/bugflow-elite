# BugFlow Elite — Phase 3 API and Detection Fabric

## Objective

Normalize API intelligence and detector output before it enters finding intelligence. API operations are represented independently of scanner implementation, and detector output remains a finding candidate rather than a verdict.

## API intelligence

The phase normalizes observed endpoints and OpenAPI operations into a common APIEndpoint contract with URL, method, parameters, source, and optional operation identity. Schema parsing is static and does not execute application code.

## Detection fabric

DetectionSpec defines detector identity, vulnerability class, action class, and minimum evidence requirements. Detector output is converted into FindingCandidate only when its evidence threshold is met. This prevents scanner output or model output from silently becoming a confirmed finding.

## Severity and authority

This phase deliberately does not grant severity or disclosure authority to detectors. Verification, confidence calibration, deduplication, severity calculation, and final verdict semantics remain downstream phases.

## Exit criteria

- API normalization tests are green.
- Evidence-gated candidate construction has negative tests.
- Full CI is green on Python 3.11 and 3.12.
- Detection contracts remain compatible with the Phase 0 observation/evidence model.
