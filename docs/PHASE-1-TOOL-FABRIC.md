# BugFlow Elite — Phase 1 Tool Fabric

## Objective

Provide one bounded execution abstraction for external security-research tools. Individual research modules may describe *what* to run, but the tool fabric owns executable identity, argv construction, environment allowlisting, timeouts, output limits, concurrency, pacing, and execution metadata.

## Security properties

- Registered tools only; unknown tool names fail closed.
- Executables must be absolute paths; implicit PATH discovery is not permitted by the fabric.
- `create_subprocess_exec()` is used with no shell interpretation.
- Tool secrets are accepted only through explicitly allowlisted environment keys.
- Executable SHA-256 pinning is supported and mismatches fail before execution.
- Argument size, output size, timeout, concurrency, and inter-run interval are bounded.
- POSIX process groups are terminated on timeout so child processes are not intentionally left running.
- Tool output is returned as structured data and is never logged by the fabric itself.
- Scope and action authorization remain upstream responsibilities; the fabric does not become a second policy authority.

## Current integration

BBOT is the first external tool migrated to the fabric. Production configuration now requires an explicit executable path and defaults BBOT to disabled until that identity is configured.

Other scanners still contain direct subprocess calls. They are intentionally migrated in their corresponding execution/detection phases so each migration can be audited with targeted tests rather than creating a large unreviewed change.

## Exit criteria

1. Tool fabric unit tests are green on Python 3.11 and 3.12.
2. Compile and lint gates are green.
3. Timeout, argv-only execution, executable integrity, environment allowlisting, and resource limits have negative tests.
4. At least one production recon adapter consumes the fabric.
5. Documentation reflects the actual trust boundary.
