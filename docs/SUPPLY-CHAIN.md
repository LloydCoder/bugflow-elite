# BugFlow Elite — Supply-Chain Controls

BugFlow uses the following supply-chain controls:

- Python dependencies are version-pinned in `requirements.txt`.
- Playwright runtime and Python package versions are aligned.
- CI performs dependency vulnerability auditing with `pip-audit`.
- CI runs deterministic compilation, tests, phase gates, security checks, and Docker builds.
- Docker builds use an official Playwright runtime image rather than installing browser binaries from an ad-hoc source.
- External scanner binaries should be version-pinned before production promotion; `@latest` is not considered a reproducible production release policy.
- Build provenance should be attested for published production artifacts before external distribution, following SLSA provenance principles.

SLSA describes provenance as verifiable information about where, when, and how an artifact was produced. GitHub artifact attestations can establish provenance for container images and other build artifacts.

This repository’s CI gate is an engineering control, not a claim of SLSA certification.
