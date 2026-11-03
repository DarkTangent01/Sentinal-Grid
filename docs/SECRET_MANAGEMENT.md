# Secret management

How the platform stores and injects credentials, per environment.
- **Findings and their status:** [DOCKER_SECRETS_SECURITY_AUDIT.md](DOCKER_SECRETS_SECURITY_AUDIT.md)
- **Rotation:** [CREDENTIAL_ROTATION.md](CREDENTIAL_ROTATION.md)
- **Compromise:** [SECURITY_INCIDENT_RESPONSE.md](SECURITY_INCIDENT_RESPONSE.md)

## The secrets

| File (`./secrets/…`) | What it protects | Used by |
|---|---|---|
| `postgres_password` | PostgreSQL superuser (`POSTGRES_USER`) | `postgres` container; operators (`backup.sh`, `create-app-db-role.sh` use the in-container socket instead) |
| `db_app_password` | the services' database role (`POSTGRES_APP_USER`, a non-superuser after `create-app-db-role.sh`) | api, worker, syslog, traps, migrate |
| `clickhouse_password` | ClickHouse user | clickhouse, api, worker, syslog, traps, migrate; `backup.sh` / `restore.sh` read it inside the clickhouse container |
| `secret_key` | session token signing (HS256) | api |
| `token_encryption_key` | Fernet key for every stored device credential: FortiGate / PAN-OS tokens, SNMP communities and USM keys, notification secrets, TACACS+ keys, IaC configuration backups | api, worker, traps |
| `token_encryption_key_previous` | earlier key(s), decryption only, during a rotation; normally empty | api, worker, traps |
| `bootstrap_admin_password` | the first administrator account (only used while no user exists) | migrate |
| `anthropic_api_key` | optional AI assistant; empty = feature off | api |

**Credentials kept in the database.** Device credentials that operators enter in the UI (firewall tokens, SNMP profiles, SMTP / webhook secrets, TACACS+ keys) live in PostgreSQL, encrypted with `token_encryption_key`.
- The API never returns them. Fields are write-only.
- The audit log records that a value changed, never the value itself.

## How secrets reach the services

```
./secrets/<name>  (host, dir 0700, files 0444, never in git or the image)
    │  Compose `secrets:`; read-only bind mount, only into the services that need it
    ▼
/run/secrets/<name>  (inside the container)
    │  <NAME>_FILE=/run/secrets/<name>  (the environment holds the PATH, not the value)
    ▼
app/secret_files.py → Settings  (read once at start-up; hidden from repr; never logged)
```

- **No secret in the environment.** `.env` holds non-secret settings only. `docker inspect`, `docker compose config`
  and `/proc/<pid>/environ` show `*_FILE` paths, never values. A secret left in `.env` (or any plain `<NAME>` variable)
  is still honoured for compatibility, but every process logs a warning naming it.
- **Database URL.** `DATABASE_URL` carries no password. The services add it from `DATABASE_PASSWORD_FILE` in memory.
- **Fail closed.** A `*_FILE` that is missing, empty (for required secrets), unreadable or over 64 KB stops the process
  with a message naming the variable, never the value or the path content.
- **Scoped mounts.** Each service gets only its own secrets: `syslog` (which parses untrusted network input) holds no
  signing or encryption key; `web` and `ingress` hold none.
- **Not in images.** Dockerfiles copy only `app/`, `rules/`, `migrations/` and `requirements.txt`, and use no `ARG` /
  `ENV` secrets. `.env` and `secrets/` sit outside the build contexts, and CI scans the built images (trivy).
- **Not in the frontend.** The UI reads no build-time environment, and CI scans the built bundle and its source maps
  for secret patterns.

### Limits of plain Docker Compose secrets (read this)

**What file mounts stop:** secrets leaking through container metadata, `docker compose config`, other processes' environments, crash dumps of environments and CI logs.

**What file mounts don't stop:**
- **`docker exec`.** Anyone who can `docker exec` into a service can `cat /run/secrets/…` for the secrets mounted there.
- **Docker host access.** Membership of the `docker` group is root-equivalent on the host.
- **Host file access.** Anyone who can read `./secrets` on the host (the deploy user, root) can read them.

**Plain Compose isn't Swarm.** Without Swarm, Compose secrets are bind mounts of host files. They aren't encrypted at rest, and `uid` / `gid` / `mode` options are ignored. That is why the files are `0444` inside a `0700` directory: the containers run as different users (app 10001, postgres 70, clickhouse 101).

**Keep the circle small.**
- Limit `docker` group membership to administrators.
- Put the host's disk on encrypted storage.
- Back up `./secrets` to a vault, separately from data backups.

## Environments

| Environment | How secrets are supplied |
|---|---|
| **Development** (`python -m app.devserver`) | plain environment variables or `.dev/dev.env` (dummy values only), or `*_FILE` pointing to local files |
| **Tests / CI** | throwaway values generated per run; CI creates `secrets/` with random values just to render and build |
| **Local Docker Compose** | `./scripts/gen-secrets.sh` → `./secrets/*` (this document) |
| **Production, Docker Compose on one host** (current deployment) | `./secrets/*` on the server, created once by `gen-secrets.sh` (new) or `migrate-secrets.sh` (existing); never copied by `deploy.sh` |
| **Docker Swarm** | `docker secret create <name> -` from stdin, then reference the same names as `external: true` secrets. Swarm encrypts them in the Raft log, honours `uid` / `gid` / `mode: 0400`, and mounts them in tmpfs. The `*_FILE` variables stay the same |
| **Kubernetes** | one `Secret` per name with encryption at rest enabled (`EncryptionConfiguration`, ideally a KMS provider), mounted as a read-only volume at `/run/secrets` with `defaultMode: 0400` and `fsGroup: 10001`. Prefer External Secrets Operator or the Vault Agent injector so values originate in a vault. Restrict `get secret` RBAC to the namespace's service accounts |
| **Vault / cloud secret manager** | render the same files with Vault Agent (`template` → `/run/secrets/<name>`) or a CSI driver. The application only needs the files |

## Installation (Ubuntu Server, Docker Compose)

```bash
sudo apt-get install -y docker.io docker-compose-v2 openssl
```

```bash
git clone <repo> sentinel && cd sentinel
```

```bash
cp .env.example .env && ./scripts/gen-secrets.sh
```

`gen-secrets.sh` writes `./secrets` (0700) and makes `.env` mode 600.

```bash
./scripts/gen-selfsigned-cert.sh siem.example.internal
```

Replace that certificate with one from your internal CA.

```bash
docker compose up -d --build
```

Give the services their own database role (recommended):

```bash
./scripts/create-app-db-role.sh
```

```bash
docker compose up -d
```

The first administrator's password is in `secrets/bootstrap_admin_password`; read it there. It is used only while no
user exists. After the first sign-in, change the password in Settings: the file then holds a password that no longer
works anywhere. Overwrite it anyway so it isn't left on disk:
`(umask 077; openssl rand -hex 24 > secrets/bootstrap_admin_password.new) && chmod 444 secrets/bootstrap_admin_password.new && mv secrets/bootstrap_admin_password.new secrets/bootstrap_admin_password`.

## Migrating an existing installation (secrets in `.env`)

```bash
./scripts/migrate-secrets.sh
```

That is a dry run: it lists which `.env` values will move.

```bash
./scripts/migrate-secrets.sh --apply
```

`--apply` writes `./secrets`, backs `.env` up to `.env.pre-secrets.<ts>.bak` (mode 600) and removes the secrets from `.env`.

```bash
docker compose up -d
```

The services now read the files.

```bash
./scripts/create-app-db-role.sh && docker compose up -d
```

That step is optional but recommended: the services stop using the superuser.

`deploy.sh` does the migration step on the server for you (with a confirmation prompt) the first time it finds no
`./secrets` there, and refuses to deploy while the server's `.env` still holds a secret.

**After migrating:**
- **Delete the `.env` backup** once the stack is healthy.
- **Plan a rotation** ([CREDENTIAL_ROTATION.md](CREDENTIAL_ROTATION.md)). The old values have been visible to anyone with `docker inspect` access, and they may still exist in older backups, terminal scrollback or copies of `.env`. Removing them from `.env` doesn't remove them from those places.

## Database accounts

| Account | Privileges | Where its password is |
|---|---|---|
| `POSTGRES_USER` (superuser) | everything | `secrets/postgres_password`, mounted only into `postgres` |
| `POSTGRES_APP_USER` (`siem_app`) | owns the `public` schema of the application database (migrations work); `NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`: no `COPY … PROGRAM`, no server file access, no other databases | `secrets/db_app_password` |
| ClickHouse user | single user (`CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=0`) | `secrets/clickhouse_password` |

**ClickHouse.** It still has a single user with access to the whole instance. A separate least-privilege ClickHouse account is backlog item DS-5 in the audit.

**Network exposure.** Neither database publishes a port. Both sit on the internal `backend` network, which has no route off the host, and the `web` container can't reach them.
