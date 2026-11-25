# Docker hardening

Container-level controls in `docker-compose.yml` and the Dockerfiles. Secrets handling is in
[SECRETS_MANAGEMENT.md](SECRETS_MANAGEMENT.md); the findings that led here are in
[DOCKER_SECURITY_AUDIT.md](DOCKER_SECURITY_AUDIT.md).

## Per-service controls

| Service | Runs as | Capabilities | Root filesystem | Secrets | Networks | Published ports |
|---|---|---|---|---|---|---|
| postgres | `postgres` (uid 70, `user: "70:70"`; the entrypoint never needs root) | none (`cap_drop: ALL`), `no-new-privileges` | read-only; tmpfs `/var/run/postgresql`, `/tmp`; data volume | `postgres_password` | backend | none |
| clickhouse | `clickhouse` (uid 101, `user: "101:101"`) from the start (third pass) | none, `no-new-privileges` | read-only; tmpfs `users.d`, logs, `/tmp`; data volume | `clickhouse_password` (admin) | backend | none |
| migrate | `siem` (uid 10001) | none (`cap_drop: ALL`), `no-new-privileges` | read-only, `/tmp` tmpfs | db, `clickhouse_app_password`, `bootstrap_admin_password` | backend | none |
| api | `siem` | none | read-only, `/tmp` tmpfs | db, clickhouse, `secret_key`, token keys, `anthropic_api_key` | backend, frontend, egress, aaa | none (reached through web) |
| worker | `siem` | none | read-only, `/tmp` tmpfs | db, clickhouse, token keys | backend, egress, aaa | none |
| traps | `siem` | none | read-only, `/tmp` tmpfs | db, clickhouse, token keys | backend, egress | SNMP trap UDP |
| syslog | `siem` | none | read-only, `/tmp` tmpfs | db, clickhouse | backend, ingest | none |
| ingress (rsyslog relay) | `ingress` (uid 10002), unprivileged port 5514 inside | none (`cap_drop: ALL`), `no-new-privileges` | read-only; `/tmp` tmpfs; disk queue volume | none | ingest, syslog_edge | host 514 udp/tcp → 5514, bound to `SYSLOG_BIND_IP` (loopback by default) |
| web (nginx) | the TLS key's owner (`WEB_UID`, default 101), unprivileged ports 8443 / 8080, own main config, no entrypoint scripts | none (`cap_drop: ALL`), `no-new-privileges` | read-only; `/tmp` tmpfs (pid, buffers) | none (the TLS key is a 0600 bind mount) | frontend | host 443 / 80 → 8443 / 8080 on `WEB_BIND_IP` |
| tacacs (optional `tacacs` profile) | `tacacs` (uid 10003, group tacshare 10050) from the start (third pass) | none, `no-new-privileges`; port 49 via the namespaced sysctl `net.ipv4.ip_unprivileged_port_start=49` | read-only; `/tmp` tmpfs; config / log volumes | its own config volume | aaa | 49/tcp on `TACACS_BIND` |

All services use the shared `logging` anchor (json-file, 50 MB × 5 files) so logs cannot fill the disk. Every long-running service has `deploy.resources.limits` for CPU, memory and process count (`pids`: 128-512, a fork-bomb guard; ClickHouse is exempt because each of its threads counts). Docker's default seccomp profile applies everywhere (no `seccomp=unconfined`); no service uses host networking, host PID / IPC, devices or the Docker socket (a test enforces this).

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
| `aaa` | no | tacacs, api, worker | TACACS+: AAA tests (api), health checks (worker); tac_plus-ng's LDAP / AD egress and published TCP/49. tacacs has no route to the databases |

Consequences:
- `web` cannot resolve or reach either database.
- Every service shares a network with each service it connects to (a test asserts the pairs). The first segmentation left `tacacs` alone on the default network, which broke TACACS+ health checks and tests until the `aaa` network was added (2026-11-03).
- Neither database has a route off the host.
- `syslog` cannot reach the internet, only the databases and the relay.

The explicit `aliases: [syslog]` on `ingest` is there because some runtimes (seen with Podman) register the service name only on the service's first network; Docker resolves it either way.

## Images

- Base images are pinned to a patch release **and a digest** (multi-arch index), so a re-pushed tag cannot change a build:
  `python:3.12.16-slim-bookworm`, `node:22.23.4-alpine3.24` (build stage only), `nginx:1.30.6-alpine` (stable branch),
  `alpine:3.24.3` with `rsyslog 8.2604.0` (ingress), `debian:12.15-slim` (tacacs), and in compose `postgres:16.15-alpine`
  and `clickhouse-server:24.8.14.39`. Dependabot (`.github/dependabot.yml`) proposes digest and version updates weekly;
  CI builds and scans each proposal before review.
- Numeric `USER` (backend 10001, ingress 10002, web 101) so a runtime can verify "not root" without resolving names.
- Backend copies only `app/`, `rules/`, `migrations/`, `alembic.ini` and `requirements.txt`; application files are
  root-owned and read-only to the process. The web image replaces nginx's main configuration (no `user` directive, pid
  and temporary files in `/tmp`) and runs `nginx -g 'daemon off;'` directly, exec form, with `STOPSIGNAL SIGQUIT`.
- Every build context has a `.dockerignore` excluding `.env*`, keys, certificates, caches and VCS data; the tacacs and
  ingress contexts allow only the files their Dockerfile copies.
- No `ARG` / `ENV` carries a secret; `.env` and `secrets/` are outside the build contexts. A test enforces this.
- The frontend is a static bundle with no build-time environment.

## CI checks (`.github/workflows/ci.yml`)

| Check | Fails the build |
|---|---|
| gitleaks over the whole git history (`--redact`; reviewed false positives suppressed by exact fingerprint in `.gitleaksignore`) | yes |
| hadolint on the four Dockerfiles (errors) | yes |
| production and development compose files render (`docker compose config`) | yes |
| `docker compose config` with throwaway secrets; no plain secret variable in the rendered output | yes |
| frontend bundle and source maps scanned for secret patterns | yes |
| trivy image scan of all four images (HIGH / CRITICAL with a fix available, plus embedded secrets); JSON reports kept 30 days | yes |
| trivy config scan (Dockerfiles, compose, workflows; HIGH / CRITICAL) | yes |
| checkov on Dockerfiles, workflows and secrets | no (report only) |
| SBOM (SPDX) for the backend and web images | no (artifact) |
| `security-gate`: depends on every job above; the one required check for merging and deploying | yes |

Every action is pinned to a full commit SHA (`actions/checkout@3d3c42e5…  # v7.0.1`), checkouts use
`persist-credentials: false`, the workflow token is read-only, and scanner images are pinned by digest. `deploy.sh` also
runs the static container / secrets policy tests locally and refuses to deploy if they fail.

## Host recommendations (outside the repository)

- Keep the `docker` group to administrators: membership is root-equivalent.
- Put Docker's data root and the deployment directory on encrypted storage.
- Restrict SSH to the deploy host; do not expose the Docker API socket over TCP.
- Back up `./secrets` to a vault, separately from data backups.
- Consider user-namespace remapping (`userns-remap`) and an AppArmor / seccomp profile beyond Docker's default.

## Validation (lab, 2026-11-03)

| Check | Result |
|---|---|
| every process non-root | postgres 70, ClickHouse server 101, all nginx processes 101, app 10001, ingress 10002 |
| capabilities | none on app, web, postgres, ingress; five on the ClickHouse entrypoint |
| fresh PostgreSQL initialisation as uid 70 with no capabilities | healthy |
| TLS | 1.0 / 1.1 refused; 1.2 (forward-secret AEAD only, CBC suite refused) and 1.3 accepted; no session tickets |
| headers | HSTS, CSP, nosniff, DENY framing, no-referrer, permissions and COOP policies |
| abuse limits | `.env` / source maps 404; 1.1 MB body 413; login burst → 429 after 6; slowloris dropped at 15 s |
| ClickHouse least privilege | file / url / remote / s3, CREATE / DROP DATABASE, CREATE USER, GRANT, SYSTEM, `system.users` all denied; data, `system.parts`, CREATE / DROP TABLE and migration 16 allowed |
| TACACS+ end to end through the hardened stack | 59 / 59 (scripts/lab/tacacs_e2e.py) |

All services also run `init: true`, and every tmpfs is `noexec,nosuid,nodev` (third pass, CONTAINER_SECURITY_ASSESSMENT.md).

## Remaining gaps

- **ClickHouse 24.8 is past end of support** (DS2-1): upgrade to 25.8 LTS as its own change, tested on a copy of the data.
- **SELinux confinement:** Docker on the production host runs without SELinux support enabled (C3-1); enabling it is a
  scheduled host change (CONTAINER_HARDENING_RUNBOOK.md §2).
- **Port exposure:** published ports listen on all interfaces; restrict them with the firewall (runbook §3).
- **Secret file modes:** plain Compose cannot apply `0400` / owner to secret files (see SECRETS_MANAGEMENT.md). The
  Kubernetes manifests mount them 0440 with the pod's group.
