# Docker secrets security audit, 2026-11-03

Scope: how credentials reach the containers of the Docker Compose deployment, and where they could leak. Covered:
`docker-compose.yml`, the four Dockerfiles, `.env` / `.env.example`, the operator scripts (`scripts/*.sh`), the CI
workflow, the backend settings loader and the frontend bundle.

No secret value appears in this report. Secrets are named by their file / variable name only.

- **How secrets are managed now:** [SECRET_MANAGEMENT.md](SECRET_MANAGEMENT.md)
- **Container hardening:** [DOCKER_HARDENING.md](DOCKER_HARDENING.md)
- **Rotation:** [CREDENTIAL_ROTATION.md](CREDENTIAL_ROTATION.md)
- **Compromise:** [SECURITY_INCIDENT_RESPONSE.md](SECURITY_INCIDENT_RESPONSE.md)

## Summary

| Secret (name only) | Before | After |
|---|---|---|
| `POSTGRES_PASSWORD` | `.env`, interpolated into `postgres` env and into every service's `DATABASE_URL` | file `secrets/postgres_password`, mounted only into `postgres` (`POSTGRES_PASSWORD_FILE`) |
| database password of the services | same as the superuser's, inside `DATABASE_URL` | file `secrets/db_app_password`; URL carries no password; separate non-superuser role after `create-app-db-role.sh` |
| `CLICKHOUSE_PASSWORD` | `.env`, env of every backend service; `--password` on the CLI in backup / restore | file `secrets/clickhouse_password` (`*_FILE`); scripts read it inside the container into a 0600 client config |
| `SECRET_KEY` | `.env`, env of every backend service | file, mounted into `api` only |
| `TOKEN_ENCRYPTION_KEY` | `.env`, env of every backend service including `syslog` | file, mounted into `api`, `worker`, `traps`; rotation via `token_encryption_key_previous` + `app.rotate_keys` |
| `BOOTSTRAP_ADMIN_PASSWORD` | `.env`, env of every backend service | file, mounted into `migrate` only |
| `ANTHROPIC_API_KEY` | `.env`, env of every backend service | file (may be empty), mounted into `api` only |

Findings: 4 high, 4 medium, 4 low, 2 informational. 12 are fixed in the repository; DS-5 is backlog; DS-14 is an
operator action (rotation). Fixed items take effect on the server only after deployment and `migrate-secrets.sh`.

## Findings

Each finding: severity, location, category, mechanism, scenario, impact, remediation, verification, status.

### DS-1 — High — every secret exposed through container environment variables

- **Where:** `docker-compose.yml`, `x-backend` anchor and `postgres` / `clickhouse`; services api, worker, syslog, traps, migrate, postgres, clickhouse.
- **Category:** secret exposure via metadata.
- **Mechanism:** values from `.env` were interpolated into `environment:`. Docker stores them in the container
  configuration, so they appear in `docker inspect`, `docker compose config`, `/proc/<pid>/environ`, and in any crash
  report or debug dump that captures the environment. Child processes inherit them.
- **Scenario:** an operator pastes `docker inspect` or `docker compose config` output into a ticket or chat; a monitoring
  agent with read-only Docker API access collects container metadata; any code path that dumps `os.environ`.
- **Impact:** full database access, ability to forge sessions (`SECRET_KEY`), and decryption of every stored device credential (`TOKEN_ENCRYPTION_KEY`).
- **Remediation:** Compose file secrets mounted at `/run/secrets/<name>`, services read them through `<NAME>_FILE`
  (`app/secret_files.py`; the official postgres and clickhouse images support `_FILE` natively). `.env` holds no secret.
  A secret still found in the plain environment is honoured but each process logs a warning naming the variable.
- **Verification:** `tests/test_secret_files.py` asserts the compose file has no secret in `environment:` and no
  `${…PASSWORD|SECRET|KEY}` interpolation. In a local stack, every service's `inspect` output and `/proc/1/environ`
  were checked programmatically: no secret value present, only `*_FILE` paths. CI renders the compose file with
  throwaway secrets and fails if a plain secret variable appears.
- **Status:** fixed.

### DS-2 — High — secrets not scoped to the services that need them

- **Where:** `docker-compose.yml`, `x-backend` anchor.
- **Category:** least privilege.
- **Mechanism:** the shared anchor gave all backend services all secrets, including `syslog`, which parses
  unauthenticated network input, and `migrate`, which only runs once.
- **Scenario:** a parser bug in `syslog` leads to code execution; the attacker reads `TOKEN_ENCRYPTION_KEY` and `SECRET_KEY` from its environment.
- **Impact:** compromise of the most exposed service yields every device credential and the ability to sign admin sessions.
- **Remediation:** per-service `secrets:` lists (see the table in [SECRET_MANAGEMENT.md](SECRET_MANAGEMENT.md)). `syslog` holds only the database and ClickHouse passwords; `web` and `ingress` hold none.
- **Verification:** test asserts the exact per-service secret map; the mounted `/run/secrets` of each container in the local stack matched it.
- **Status:** fixed.

### DS-3 — High — database password embedded in `DATABASE_URL`

- **Where:** `docker-compose.yml`, `backend/app/config.py` (default URL).
- **Category:** secret exposure via connection string.
- **Mechanism:** the full URL including password was in the environment, and connection URLs are commonly logged in
  error messages and tracebacks. The code default also contained development credentials.
- **Impact:** database credential leak through logs as well as through DS-1.
- **Remediation:** `DATABASE_URL` carries no password; `DATABASE_PASSWORD_FILE` is added in memory with SQLAlchemy
  `URL.set(password=…)`. The settings field is `repr=False`. The default URL has no password.
- **Verification:** unit tests for injection (including "URL already has a password wins"), repr hiding and the default.
- **Status:** fixed.

### DS-4 — High — application services connect as the PostgreSQL superuser

- **Where:** `docker-compose.yml`, `DATABASE_URL` user.
- **Category:** database least privilege.
- **Mechanism:** a superuser can run `COPY … TO/FROM PROGRAM` (OS command execution as the postgres user), read server files and access every database.
- **Scenario:** an SQL injection anywhere in the application becomes command execution in the database container.
- **Impact:** escalation from an application bug to host-adjacent code execution and full data access.
- **Remediation:** `scripts/create-app-db-role.sh` creates `POSTGRES_APP_USER` (`NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS`), transfers ownership of the application schema objects so migrations keep working,
  writes `secrets/db_app_password` and points the services at the role. The password goes to `psql` on stdin, not argv.
  The superuser password is mounted only into `postgres`.
- **Verification:** in the local stack the script created the role (not a superuser), and api / worker reconnected as
  it with the API healthy and sign-in working. Production requires running the script once.
- **Status:** fixed in repository; operator step on the server.

### DS-5 — Medium — ClickHouse uses a single all-powerful user

- **Where:** `clickhouse` service, all backend services.
- **Category:** database least privilege.
- **Mechanism:** one user with access to the whole instance is shared by every service, including `syslog`.
- **Impact:** a compromised service can drop or alter any ClickHouse table and read all events.
- **Remediation (planned):** separate users — an insert-only user for `syslog` / `traps`, a read / write user for
  `api` / `worker`, the admin user for `migrate` and backups — defined in `users.d` with their own secret files.
- **Status:** backlog. Network exposure is reduced by DS-12 (internal network, no published port).

### DS-6 — Medium — backup / restore passed the ClickHouse password on the command line and sourced `.env`

- **Where:** `scripts/backup.sh`, `scripts/restore.sh`.
- **Category:** secret exposure via process list; unsafe configuration parsing.
- **Mechanism:** `clickhouse-client --password …` is visible in `ps` to any local user, and `source .env` executes the file as shell.
- **Remediation:** `scripts/lib-env.sh`: `envval` reads single keys without executing `.env`; `chq` runs the query
  inside the clickhouse container with a temporary 0600 client config built from `/run/secrets/clickhouse_password`,
  so the password never appears in argv or on the host.
- **Verification:** test asserts no script uses `--password` or sources `.env`; `chq` queries ran successfully in the local stack.
- **Status:** fixed.

### DS-7 — Medium — deployment sync would delete or overwrite server-side secrets

- **Where:** `scripts/deploy.sh` (rsync with `--delete`).
- **Category:** availability / secret handling.
- **Mechanism:** a `secrets/` directory that exists only on the server would be deleted by the sync; a developer's local `secrets/` would be copied up.
- **Remediation:** `/secrets/` is excluded from the sync. On first deploy without server secrets, the script runs
  `migrate-secrets.sh` (dry run, then `--apply` after confirmation). It refuses to deploy while the server's `.env` still contains a secret.
- **Status:** fixed.

### DS-8 — Medium — the syslog parser had internet egress

- **Where:** `docker-compose.yml`, `ingest` network.
- **Category:** network segmentation.
- **Mechanism:** `syslog` (untrusted input) shared a non-internal network with `ingress`, which gave it a default route out.
- **Impact:** a compromised parser could exfiltrate data or fetch tooling.
- **Remediation:** `ingest` is `internal: true`; `ingress` publishes its port through a separate `syslog_edge` network.
  `syslog` has an explicit `syslog` alias on `ingest`.
- **Verification:** in the local stack, `syslog` cannot reach an internet address; `ingress` resolves `syslog`; test asserts the network layout.
- **Status:** fixed.

### DS-9 — Low — settings object could print secrets

- **Where:** `backend/app/config.py`.
- **Category:** secret exposure via logs.
- **Mechanism:** pydantic includes fields in `repr()`, which ends up in tracebacks and debug logging.
- **Remediation:** every secret field is `Field(repr=False)`; `SecretError` messages name the variable, never the value.
- **Verification:** unit test renders `repr(settings)` and asserts no value appears.
- **Status:** fixed.

### DS-10 — Low — the ClickHouse image entrypoint writes the password into its own config

- **Where:** `clickhouse` image entrypoint.
- **Category:** secret at rest inside a container.
- **Mechanism:** with `CLICKHOUSE_PASSWORD_FILE`, the entrypoint still writes a `users.d` file containing the password inside the container's writable layer.
- **Impact:** limited: readable only by someone who already has exec or host access to the clickhouse container, where `/run/secrets` is readable anyway.
- **Remediation:** accepted; resolved together with DS-5 by shipping explicit `users.d` files that reference hashed passwords.
- **Status:** accepted risk.

### DS-11 — Low — default development credentials in code

- **Where:** `backend/app/config.py`.
- **Category:** hardcoded credentials.
- **Remediation:** default URL without password (see DS-3); `gen-secrets.sh` refuses to run while `.env` still holds secret keys.
- **Status:** fixed.

### DS-12 — Low — writable root filesystems, full capabilities, flat network

- **Where:** all services.
- **Category:** container hardening.
- **Remediation:** `cap_drop: [ALL]`, `no-new-privileges`, `read_only: true` with a small `/tmp` tmpfs for app services
  and `web`; networks `backend` (internal, databases), `frontend` (web ↔ api), `egress` (api / worker / traps to
  devices and feeds), `ingest` (internal), `syslog_edge`. Details in [DOCKER_HARDENING.md](DOCKER_HARDENING.md).
- **Verification:** writing `/` fails and `/tmp` works in api, worker, syslog, traps and web; `web` cannot resolve either database; `postgres` has no internet route.
- **Status:** fixed.

### DS-13 — Info — frontend and API do not expose secrets

- The frontend reads no build-time environment; CI scans the built bundle and source maps for secret patterns.
- Device credentials are write-only in the API and redacted in the audit log.
- Dockerfiles copy only application code, use no secret `ARG` / `ENV`, and the backend runs as an unprivileged user.
  `.env` and `secrets/` are outside the build contexts; CI runs gitleaks, hadolint, trivy (images and config) and checkov.
- **Status:** no action.

### DS-14 — Info — old values persist after migration

Moving secrets out of `.env` does **not** remove them from:
- existing container metadata (until those containers are recreated) and anything that already captured it;
- the `.env.pre-secrets.<ts>.bak` backup that `migrate-secrets.sh` writes;
- earlier backups, snapshots and copies of `.env`;
- terminal scrollback, shell history, tickets or chat where `inspect` / `config` output was pasted;
- source control history, if `.env` was ever committed (it is ignored; check with `git log --all -- .env`).

**Action:** rotate every secret after migrating ([CREDENTIAL_ROTATION.md](CREDENTIAL_ROTATION.md)). Rotation is the only control that makes the old values worthless.

## Verification log (local Podman stack with generated throwaway secrets)

| Check | Result |
|---|---|
| `gen-secrets.sh` creates `secrets/` 0700, files 0444, never overwrites | pass |
| postgres / clickhouse start from `*_FILE`; `migrate` reads its secrets from files and exits 0 | pass |
| no secret value in `inspect` output or `/proc/1/environ` of any service | pass |
| `/run/secrets` per container matches the intended map | pass |
| read-only root in api, worker, syslog, traps, web; `/tmp` writable | pass |
| api reaches postgres and clickhouse; web cannot resolve either; worker has egress; postgres and syslog have none | pass |
| ingress resolves `syslog` on the internal `ingest` network | pass (after adding the explicit alias) |
| ingress relay forwards to `syslog` over the internal network (rsyslog `to_siem` action: processed, 0 failed) | pass |
| `chq` helper authenticates via the in-container secret | pass |
| `create-app-db-role.sh`: role created non-superuser, api / worker reconnect as it, API healthy | pass |
| sign-in with the bootstrap password from its file (session signed with `secret_key` from its file) | pass |
| backend test suite | 492 passed, 1 skipped |

The local stack ran on Podman, where nginx's Docker-specific resolver (`127.0.0.11`) cannot resolve `api`, so the
browser path through `web` was checked by calling the API from inside the `web` container instead. The CI security job (gitleaks, hadolint, trivy, checkov, SBOM) has not run yet; it runs on the next push.
