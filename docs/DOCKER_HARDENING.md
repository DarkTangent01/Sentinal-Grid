# Docker hardening

Container-level controls in `docker-compose.yml` and the Dockerfiles. Secrets handling is in
[SECRET_MANAGEMENT.md](SECRET_MANAGEMENT.md); the findings that led here are in
[DOCKER_SECRETS_SECURITY_AUDIT.md](DOCKER_SECRETS_SECURITY_AUDIT.md).

## Per-service controls

| Service | Runs as | Capabilities | Root filesystem | Secrets | Networks | Published ports |
|---|---|---|---|---|---|---|
| postgres | image default (postgres) | image default, `no-new-privileges` | writable (data volume) | `postgres_password` | backend | none |
| clickhouse | image default (clickhouse) | image default, `no-new-privileges` | writable (data volume) | `clickhouse_password` | backend | none |
| migrate | `siem` (uid 10001) | none (`cap_drop: ALL`), `no-new-privileges` | read-only, `/tmp` tmpfs | db, clickhouse, `bootstrap_admin_password` | backend | none |
| api | `siem` | none | read-only, `/tmp` tmpfs | db, clickhouse, `secret_key`, token keys, `anthropic_api_key` | backend, frontend, egress | none (reached through web) |
| worker | `siem` | none | read-only, `/tmp` tmpfs | db, clickhouse, token keys | backend, egress | none |
| traps | `siem` | none | read-only, `/tmp` tmpfs | db, clickhouse, token keys | backend, egress | SNMP trap UDP |
| syslog | `siem` | none | read-only, `/tmp` tmpfs | db, clickhouse | backend, ingest | none |
| ingress (rsyslog relay) | image default, unprivileged port 5514 inside | none (`cap_drop: ALL`), `no-new-privileges` | writable (disk queue volume) | none | ingest, syslog_edge | host 514 udp/tcp → 5514, bound to `SYSLOG_BIND_IP` (loopback by default) |
| web (nginx) | image default | `no-new-privileges` | read-only; tmpfs for nginx cache, `/var/run`, `/tmp` | none | frontend | 443 / 80 |
| tacacs (optional `tacacs` profile) | image default | `cap_drop: ALL` + `CHOWN SETUID SETGID FOWNER NET_BIND_SERVICE DAC_OVERRIDE` (the daemon drops privileges itself) | writable | its own config volume | default | 49/tcp on `TACACS_BIND` |

All services use the shared `logging` anchor (json-file, 50 MB × 5 files) so logs cannot fill the disk, and every long-running service has `deploy.resources.limits` for CPU and memory.

**Why `0444` secret files.** Plain Compose (not Swarm) bind-mounts secret files and ignores `uid` / `gid` / `mode`.
The containers run as different users (app 10001, postgres 70, clickhouse 101), so the files are world-readable
inside a `0700` host directory: only root and the deploy user can reach them on the host. Swarm or Kubernetes allow
`0400` with the right owner; see the environments table in SECRET_MANAGEMENT.md.

## Networks

| Network | `internal` | Members | Purpose |
|---|---|---|---|
| `backend` | yes (no route off the host) | databases, migrate, api, worker, syslog, traps | data access |
| `frontend` | no | web, api | the UI proxies `/api` to the api |
| `egress` | no | api, worker, traps | outbound to firewalls / switches / feeds; traps' published UDP port |
| `ingest` | yes | ingress, syslog (alias `syslog`) | relay from rsyslog to the parser; the parser handles untrusted input and has no route out |
| `syslog_edge` | no | ingress | carries ingress's published syslog port |

Consequences:
- `web` cannot resolve or reach either database.
- Neither database has a route off the host.
- `syslog` cannot reach the internet, only the databases and the relay.

The explicit `aliases: [syslog]` on `ingest` is there because some runtimes (seen with Podman) register the service name only on the service's first network; Docker resolves it either way.

## Images

- Pinned base images: `python:3.12.8-slim`, `node:22.12.0-alpine` (build stage only), `nginx:1.27.3-alpine`.
- Backend runs as `USER siem`; it copies only `app/`, `rules/`, `migrations/` and `requirements.txt`.
- No `ARG` / `ENV` carries a secret; `.env` and `secrets/` are outside the build contexts. A test enforces this.
- The frontend is a static bundle with no build-time environment.

## CI checks (`.github/workflows/ci.yml`)

| Check | Fails the build |
|---|---|
| gitleaks over the repository (`--redact`) | yes |
| hadolint on the Dockerfiles | yes |
| `docker compose config` with throwaway secrets; no plain secret variable in the rendered output | yes |
| frontend bundle and source maps scanned for secret patterns | yes |
| trivy image scan (HIGH / CRITICAL with a fix available, plus embedded secrets) and trivy config scan (HIGH / CRITICAL) | yes |
| checkov on the compose / Dockerfiles | no (report only) |
| SBOM (anchore/sbom-action) per image | no (artifact) |

## Host recommendations (outside the repository)

- Keep the `docker` group to administrators: membership is root-equivalent.
- Put Docker's data root and the deployment directory on encrypted storage.
- Restrict SSH to the deploy host; do not expose the Docker API socket over TCP.
- Back up `./secrets` to a vault, separately from data backups.
- Consider user-namespace remapping (`userns-remap`) and an AppArmor / seccomp profile beyond Docker's default.

## Remaining gaps

- **DS-5:** a single ClickHouse user (backlog).
- `web`, `postgres`, `clickhouse` keep their image's default capability set (no `cap_drop: ALL`): their entrypoints switch users at start-up.
- `tacacs` runs with `no-new-privileges:false` because its daemon changes user after binding port 49.
