# BugFlow Elite — Phase 4 Verification and Threat Intelligence

## Objective

Move from detector output to evidence-backed verification while preserving a strict boundary between intelligence signals and finding authority.

## Verification

Verification requires existing evidence, scope re-validation, bounded checks, and an explicit confidence/evidence result. Rejected or duplicate findings cannot become verified findings through re-probing.

## ThreatFade integration

ThreatFade/C2-like observations are represented as ThreatSignal correlation metadata. A high-confidence threat signal may increase research priority or trigger additional verification, but it does not assign severity and cannot create a verdict by itself.

## Network safety

Verification HTTP probes require explicit web-request capability and TLS verification is enabled by default. Later research phases may add narrowly scoped exceptions for test fixtures or controlled environments, but insecure TLS must never be the implicit production behavior.
