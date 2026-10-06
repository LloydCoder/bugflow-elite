# BugFlow Elite — Secure Operations

## Backup

Back up runtime state outside the Git repository. Never commit `db/bugflow.db`, findings exports, credentials, tokens, or runtime output.

For SQLite, use the SQLite online-backup mechanism against the live database and store the resulting artifact in encrypted durable storage. Keep a tested retention policy and periodically perform a restore drill in an isolated environment.

## Restore

1. Provision a trusted host from the maintained container/deployment definition.
2. Obtain the exact Git commit or release artifact that was approved by CI.
3. Inject secrets through the deployment secret manager; do not put credentials in shell history, Git remotes, or files tracked by Git.
4. Restore the encrypted database backup into the isolated runtime volume.
5. Start the application with automatic disclosure disabled and the explicit scope/action policy loaded.
6. Run health checks and a read-only verification before enabling scheduled research.
7. Record the restore event in the operational audit trail.

## Operational safety

- Do not use scripts that push runtime state directly to `main`.
- Do not store GitHub personal access tokens in plaintext credential files.
- Do not install software with unaudited `curl | sh` pipelines.
- Do not expose the Streamlit service directly to the public Internet; place it behind an authenticated reverse proxy or private access layer.
- Keep dashboard, API, scanner, and database network exposure minimal.
- Review scope and action policy after every restore.

The repository intentionally does not contain the former interactive VPS setup/backup/restore scripts because they mixed operational secrets, host mutation, Git writes, and deployment authority in unsafe ways.
