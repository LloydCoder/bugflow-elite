# BugFlow Elite — Deployment

## Local / development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
pytest tests/ -q
python -m compileall -q .
```

## Docker

```bash
docker build -t bugflow-elite:local .
docker run --rm -it --env-file .env bugflow-elite:local
```

The image installs the application dependencies and Playwright Chromium. External security tools are adapters, not authorities; production execution must still pass BugFlow scope/capability policy.

## Compose

```bash
docker compose up --build
```

Review `config/config.yaml` and `config/scope/manual_scope.yaml` before enabling any active research capability.

## Production requirements

- Store secrets outside the repository and inject them through the deployment secret manager.
- Keep automatic disclosure disabled.
- Keep TLS verification enabled.
- Use explicit scope and action allowlists.
- Persist evidence and audit records on durable storage.
- Back up the database and test restoration regularly.
- Use tenant-isolated database namespaces for production multi-tenant SaaS until all legacy tables are migrated to tenant-aware constraints.
- Pin and continuously review external scanner versions before production promotion.

## Operational verification

The repository CI is the release gate. It runs Python 3.11/3.12 tests, security scanning, phase-specific gates, final forensic invariants, and a Docker build on `main`.

Passing CI is an engineering release criterion, not a regulatory or third-party certification.
