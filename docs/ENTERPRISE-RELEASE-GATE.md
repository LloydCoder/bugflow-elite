# BugFlow Elite — Enterprise Release Gate

## Required checks

1. Full CI is green on Python 3.11 and 3.12.
2. Code quality and secret scanning are green.
3. Every phase gate is green.
4. No automatic disclosure path is enabled.
5. Scope and action authorization fail closed.
6. Tool execution is bounded and auditable.
7. Evidence is traceable and integrity-verifiable.
8. Threat intelligence cannot become severity authority without independent evidence.
9. Tenant/audit controls are active for enterprise control-plane state.
10. Benchmark/adversarial regression tests are green.
11. README, roadmap, threat model, deployment guidance, and phase records match the implementation.

## Non-certification statement

Passing these gates is an engineering release criterion. It is not a claim of OWASP, NIST, ISO 27001, SOC 2, PCI DSS, or other external certification.

## Legacy migration boundary

Legacy research adapters are migrated incrementally into the Tool Fabric because each tool has distinct argument, output, and evidence semantics. Production SaaS multi-tenancy must use isolated database namespaces until all legacy tables receive tenant-aware constraints and migrations.
