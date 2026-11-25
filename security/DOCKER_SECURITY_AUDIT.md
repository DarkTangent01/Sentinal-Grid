# Docker security audit

Two passes: **secrets** (2026-11-03, DS-1…DS-14) and **container / supply-chain hardening** (2026-11-04…10, DS2-1…DS2-15,
at the end).

Scope: how credentials reach the containers of the Docker Compose deployment, and where they could leak. Covered:
`docker-compose.yml`, the four Dockerfiles, `.env` / `.env.example`, the operator scripts (`scripts/*.sh`), the CI
workflow, the backend settings loader and the frontend bundle.

No secret value appears in this report. Secrets are named by their file / variable name only.

- **How secrets are managed now:** [SECRETS_MANAGEMENT.md](SECRETS_MANAGEMENT.md)
- **Container hardening:** [DOCKER_HARDENING.md](DOCKER_HARDENING.md)
- **Rotation:** [CREDENTIAL_ROTATION.md](CREDENTIAL_ROTATION.md)
- **Compromise:** [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md)

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

Findings: 4 high, 4 medium, 4 low, 2 informational. 13 are fixed in the repository (DS-5 in the second pass, DS2-4); DS-14 is an
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
- **Remediation:** per-service `secrets:` lists (see the table in [SECRETS_MANAGEMENT.md](SECRETS_MANAGEMENT.md)). `syslog` holds only the database and ClickHouse passwords; `web` and `ingress` hold none.
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
- **Remediation:** the services use their own account (`scripts/create-clickhouse-app-user.sh`, `CLICKHOUSE_APP_USER`,
  secret `clickhouse_app_password`), limited to the application database and `system.parts` / `system.tables`; the admin
  password is mounted only into `clickhouse` and used by operators and backups. See DS2-4.
- **Status:** fixed in the second pass (operator step: run the script once per installation).

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

---

# Second pass: container, image, edge and supply-chain hardening (2026-11-04 … 2026-11-10)

Scope: every Dockerfile and compose file, nginx, the database containers, backups, CI and the git history. Method:
source review, the scanners below, and a lab copy of the stack (Podman, the real images, existing data volumes upgraded
in place). Severity follows the first pass. "Fixed" means changed in the repository **and** verified in the lab; nothing
here is deployed yet.

| ID | Severity | Finding | Status |
|---|---|---|---|
| DS2-1 | High | ClickHouse 24.8 LTS is past end of support (last patch Feb 2025); production ran 24.8.11.5 | mitigated (24.8.14.39); 25.8 LTS upgrade open |
| DS2-2 | High | base images 1-2 years behind on patches; one end-of-life (Alpine 3.20) | fixed |
| DS2-3 | Medium | web, postgres, clickhouse kept the default capability set; nginx and postgres master ran as root | fixed |
| DS2-4 | Medium | every service used the ClickHouse admin account (= DS-5) | fixed (operator step) |
| DS2-5 | Medium | backups unencrypted and never pruned | fixed (opt-in key) |
| DS2-6 | Medium | GitHub Actions pinned to movable tags; scanner images pinned to tags | fixed |
| DS2-7 | Medium | no gate between a failed check and a deploy | fixed |
| DS2-8 | Low | TLS 1.2 used OpenSSL's default cipher list; session tickets on; no header / body timeouts or connection limit | fixed |
| DS2-9 | Low | no process (pid) limits | fixed |
| DS2-10 | Low | dotfiles and source maps would be served if present; access log recorded query strings | fixed |
| DS2-11 | Low | thin `.dockerignore` files (frontend: none for `.env` / keys); tacacs and ingress contexts had none | fixed |
| DS2-12 | Low | images with named `USER` (not verifiable as non-root without resolving names) | fixed |
| DS2-13 | Low | production and development settings mixed: no safe way to run a lab copy | fixed (`docker-compose.dev.yml`) |
| DS2-14 | Info | gitleaks history scan: 7 findings, all false positives | reviewed, suppressed by fingerprint |
| DS2-15 | Info | Podman re-owns an empty named volume to the next container user (TACACS+ logs) | fixed |

### DS2-1 — High — ClickHouse 24.8 is past end of support
- **Evidence:** Docker Hub: the newest `24.8.*` tag is `24.8.14.39` (2025-02-19); the supported LTS line is `25.8`
  (`25.8.33.6`, 2026-08). Production ran `24.8.11.5`.
- **Impact:** security fixes after early 2025 are not backported; the database holds every event.
- **Remediation now:** the last 24.8 patch, pinned by digest. **Open:** upgrade to 25.8 LTS as its own change, first on a
  copy of the production data (one LTS jump is supported in place; check settings changed between the two).
- **Verification:** the lab opened data written by 24.8.11.5 with 24.8.14.39 in place; migrations and the TACACS+ end-to-end
  suite passed.

### DS2-2 — High — outdated base images, one end-of-life
- **Evidence:** `python:3.12.8-slim`, `node:22.12.0`, `nginx:1.27.3`, `alpine:3.20.3` (EOL 2026-04), `debian:12.7`,
  `postgres:16.6`.
- **Remediation:** `python:3.12.16-slim-bookworm`, `node:22.23.4-alpine3.24`, `nginx:1.30.6-alpine` (stable branch),
  `alpine:3.24.3` with `rsyslog 8.2604.0` / `conntrack-tools 1.4.9` (versions pinned), `debian:12.15-slim`,
  `postgres:16.15-alpine` (same major: data-compatible), each pinned by multi-arch digest; Dependabot proposes updates.
- **Verification:** all four images rebuilt and checked inside (versions, numeric users); PostgreSQL 16.15 started on
  16.6 data (96 tables intact); Trivy results below.

### DS2-3 — Medium — default capabilities and root processes in web / postgres / clickhouse
- **Evidence:** no `cap_drop` on those three services; nginx and the postgres entrypoint started as root.
- **Remediation:** postgres runs as `70:70` with no capabilities (the entrypoint needs none when not root). nginx runs as
  the TLS key's owner (`WEB_UID`, default 101) on 8443 / 8080 with no capabilities, its own main configuration and no
  entrypoint scripts. ClickHouse: `cap_drop: ALL` plus exactly `CHOWN SETUID SETGID DAC_OVERRIDE FOWNER` for its
  entrypoint; the server runs as 101.
- **Verification:** lab, by `/proc/<pid>/status`: postgres 70, ClickHouse server 101, every nginx process 101, app 10001,
  ingress 10002; fresh initialisation and in-place upgrade both work. `tests/test_secret_files.py` asserts the settings.

### DS2-4 — Medium — services used the ClickHouse admin account (DS-5)
- **Remediation:** `scripts/create-clickhouse-app-user.sh` creates `siem_ch_app` (only the SHA-256 of its password reaches
  ClickHouse and its query log) with `SELECT, INSERT, ALTER, CREATE TABLE, CREATE VIEW, DROP TABLE, DROP VIEW, TRUNCATE,
  OPTIMIZE, SHOW` on the application database and `SELECT` on `system.parts` / `system.tables`.
  `CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1` lets the admin manage users.
- **Verification (lab, as `siem_ch_app`):** allowed: application data, `system.parts`, CREATE / DROP TABLE, re-running
  migration 16. Denied: `file()`, `url()` (incl. a cloud metadata address), `remote()`, `s3()`, CREATE / DROP DATABASE,
  CREATE USER, GRANT, SYSTEM, `system.users`. 0 access-denied errors from the services; TACACS+ suite 59 / 59.

### DS2-5 — Medium — backups unencrypted and kept forever
- **Remediation:** `backup.sh` encrypts both files to `BACKUP_GPG_RECIPIENT` (public key only on the server; private key
  offline) and removes the plaintext; `BACKUP_KEEP_DAYS` (14) prunes local copies; the backup directory is 0700;
  `restore.sh` refuses encrypted files with the decrypt commands.
- **Verification:** script syntax checked; the encryption path needs a key on the server (operator step, see
  PRODUCTION_DEPLOYMENT.md). Unencrypted backups print a warning.

### DS2-6 — Medium — CI supply chain
- **Evidence:** `actions/checkout@v4`, `trivy-action@0.28.0` etc. (tags can be moved); scanner images by tag.
- **Remediation:** every action pinned to a full commit SHA (resolved from the release tag), `persist-credentials: false`,
  read-only token, scanner images (Trivy, Gitleaks, Hadolint) by digest, Dependabot for actions, images and dependencies.
- **Verification:** a test asserts every `uses:` is a 40-hex SHA.

### DS2-7 — Medium — no deploy gate
- **Remediation:** CI `security-gate` job (needs every job; the one required check). `deploy.sh` runs the static container /
  secrets policy tests locally and refuses to deploy on failure.

### DS2-8 — Low — TLS and request limits
- **Remediation:** Mozilla-intermediate TLS 1.2 ciphers (ECDHE + AEAD only), TLS 1.3, `ssl_session_tickets off`, header /
  body / send / keep-alive timeouts, 50 connections per client, 429 on rate limits; HSTS on the HTTP redirect as well.
- **Verification (lab):** TLS 1.0 / 1.1 refused; a CBC suite refused; no ticket issued; slow-header connection closed at 15 s;
  1.1 MB body → 413; login burst → 429 after 6 attempts.

### DS2-9 … DS2-13 — Low
- **DS2-9:** `deploy.resources.limits.pids` 128-512 per service (ClickHouse exempt: its threads count as pids).
- **DS2-10:** `.env`, other dotfiles and `*.map` return 404 (verified); the access log keeps the path without query string.
- **DS2-11:** `.dockerignore` in every build context (`.env*`, keys, certificates, caches, VCS); tacacs and ingress allow-list
  only the files they copy.
- **DS2-12:** numeric `USER` (10001, 10002, 101).
- **DS2-13:** `docker-compose.yml` is the production configuration; `docker-compose.dev.yml` only moves published ports to
  unprivileged loopback ports and publishes the API on loopback for the Vite dev server (a test asserts loopback only).

### DS2-14 — Info — gitleaks history findings
- **Evidence:** 7 `generic-api-key` matches across 4 commits: SNMP counter names in `app/wireless/collect.py`, a fixed dummy
  `SECRET_KEY` in `tests/conftest.py` and `tools/bench_api.py`, a deliberately wrong SNMPv3 password in
  `tests/test_switches.py`. The working tree also matches `.dev/dev.env` and a ruff cache file: both git-ignored, never
  committed.
- **Remediation:** `.gitleaksignore` lists the 7 exact fingerprints (commit + file + rule + line) with the reason; anything
  else, including a real secret added to the same files, is still reported. History scan: clean.

### DS2-15 — Info — Podman empty-volume ownership
- **Evidence:** in the lab, the worker's mount re-owned the empty `tacacs_logs` volume to uid 10001; tac_plus-ng could not
  write logs (detected by the agent's `logs_writable` check). Docker does not do this.
- **Remediation:** the tacacs entrypoint leaves a marker file in each volume. **Verification:** recreating the worker no
  longer changes the owner.

## Scanner results (second pass)

| Scanner | Scope | Result |
|---|---|---|
| Gitleaks 8.30.1 | whole git history | 7 findings, all false positives (DS2-14); clean with `.gitleaksignore` |
| Hadolint 2.15.1 | 4 Dockerfiles | no errors; warnings DL3008 (apt versions unpinned: base digest-pinned instead; exact Debian pins break when the archive moves on), DL3003 (`cd` in the tacacs build stage); DL3066 fixed |
| Trivy 0.69.3 | 4 images, HIGH / CRITICAL | see "Trivy image results" below |
| Trivy 0.69.3 config | Dockerfiles, compose, workflows (HIGH / CRITICAL) | clean with `.trivyignore.yaml` (one scoped exception: DS-0002, tacacs runs its entrypoint as root, see below); 1 MEDIUM (DS-0013, `cd` in the tacacs *build* stage, not in the runtime image) accepted |
| Checkov | Dockerfiles, workflows, secrets | 235 passed, 5 failed: 4 × CKV_DOCKER_2 (no `HEALTHCHECK` in the Dockerfile: by design, one backend image runs four services with different checks, all defined in compose), CKV_DOCKER_3 (tacacs, as DS-0002); 2 × CKV_SECRET_6 in `deploy/firewalls.example.json` are environment-variable **names** (`token_env`), not tokens |

### Trivy image results (HIGH / CRITICAL)

| Image | First scan | Fixable | After the fixes | Fixable |
|---|---|---|---|---|
| fortisiem-backend | 2 critical, 67 high | 11 (`pyasn1` 0.6.1, `apt`) | 2 critical, 56 high | **0** |
| fortisiem-web | 1 critical, 6 high | 7 (`brotli-libs`, `curl`, `libexpat`) | none | **0** |
| fortisiem-ingress | 8 high | 8 (`rsyslog` 8.2604.0) | none | **0** |
| fortisiem-tacacs | 2 critical, 73 high | 2 (`apt`) | 2 critical, 71 high | **0** |

No embedded secret in any image. Fixes: `pyasn1` 0.6.5 (SNMP tests pass), `rsyslog` 8.2608.0, and the images now apply
the distribution's security updates at build time (`apt-get upgrade` / `apk upgrade`; the base stays digest-pinned).
Every remaining finding has **no fixed version published** (Debian 12): the two criticals are `zlib1g` CVE-2023-45853
(in minizip, which nothing here uses) and `libsqlite3-0` CVE-2025-7458. CI fails only on fixable HIGH / CRITICAL
(`--ignore-unfixed`), so these surface again automatically when Debian ships a fix. Docker Scout was not used: it
needs a Docker Hub login; Trivy covers the same image scan.

