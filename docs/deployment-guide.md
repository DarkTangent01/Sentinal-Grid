# Deployment guide

Deploy one service, several services, or whatever changed. Nothing else restarts, and the databases are never touched.
The design is in [deployment-architecture.md](deployment-architecture.md).

## From the workstation (normal use)

```bash
./scripts/deploy.sh                          # dry run: what rsync would copy / delete; changes nothing
./scripts/deploy.sh --apply                  # sync, then deploy only what changed (auto)
./scripts/deploy.sh --apply ui               # web UI only: atomic switch, nginx keeps running
./scripts/deploy.sh --apply api              # API only: rolling, no downtime
./scripts/deploy.sh --apply poller           # SNMP pollers, one at a time
./scripts/deploy.sh --apply worker           # alert / job worker (seconds)
./scripts/deploy.sh --apply syslog           # syslog processing (the ingress buffers meanwhile)
./scripts/deploy.sh --apply backend          # migrations + every backend service, each with its own strategy
./scripts/deploy.sh --apply all              # backend + playbook runner + UI (+ proxy / ingress / TACACS+ if they changed)
./scripts/deploy.sh --apply api --no-cache   # rebuild the image from scratch
SKIP_BACKUP=1 ./scripts/deploy.sh --apply …  # skip the pre-deployment backup (only right after a completed one)
./scripts/rollback.sh api                    # previous image of one service (see rollback-guide.md)
./scripts/rollback.sh --status               # versions, previous versions, health
```

**Targets:** `ui`, `api`, `poller`, `worker`, `access`, `syslog`, `traps`, `flows`, `ansible`, `edge` (the nginx proxy),
`ingress`, `tacacs`, `migrate`, `backend`, `all`, `auto` (default).

**`deploy.sh --apply` steps:**
1. Run the container / secrets policy tests locally.
2. Ask for confirmation.
3. Take a backup on the server, unless the targets cannot change the database (`ui`, `edge`, `ingress`, `tacacs`) or `SKIP_BACKUP=1` is set.
4. rsync the allowlisted files (`scripts/deploy-files.rsync`). The server keeps its own `.env`, secrets, certificates, backups and `deploy/state`.
5. Run `scripts/release.sh deploy <targets>` on the server, then print `release.sh status`.

## On the server

```bash
cd /home/siem/fortisiem
./scripts/release.sh deploy ui               # same targets as above
./scripts/release.sh status                  # deployed tag, previous tag, container states; what changed since build
./scripts/release.sh history 30              # last 30 deployment steps (JSON lines)
./scripts/release.sh build backend           # build only (tag printed); deploys nothing
./scripts/release.sh rollback ui             # see rollback-guide.md
```

### What each target does

| Target | Build | Steps | Interruption |
|---|---|---|---|
| `ui` | web image (if the UI source changed) | `ui-release` copies the release into the `ui` volume, checks assets, switches `current` atomically, then checks `/` and `/api/ready` through nginx; failure switches back | none |
| `api` | backend image | per replica (2): new container off nginx's network → `/api/ready` → warm-up → joins → old drains (SIGTERM, up to 30 s) → public check; any failure returns every replica to the previous version | none (measured: 0 failed of 444, one request 2.1 s) |
| `poller` | backend | the same, per replica; no DNS wait | none; polling continues |
| `worker`, `access`, `syslog`, `traps`, `flows`, `ansible` | backend / ansible | `up --force-recreate` (stop, then start) → health check; unhealthy restores the previous tag | seconds, service-specific (architecture §6) |
| `edge` | web | `nginx -t` with the new image and the real certificates → replace the proxy → health check; failure restores it | 1–3 s |
| `migrate` | backend | `app.migrate_check` (refuses destructive revisions) → `app.migrate` with the new image | none; services switch afterwards |
| `backend` | backend | migrate → api → poller → worker → access → syslog → traps → flows | as above |
| `auto` | changed images only | services whose running image was built from a different source; `ui` / `edge` when the UI or nginx configuration changed | as above |

**Order and failure handling:**
- All builds finish before anything is switched, so **a failed build changes nothing**.
- A backend deployment always runs the migration step first when the migration image differs.
- Each service is switched independently. A failure stops the run there: services already switched keep their new version, and the failed one keeps its old one.

### Typical changes

| Change | Command | Effect |
|---|---|---|
| Frontend only (`frontend/src`) | `deploy.sh --apply ui` (or `auto`) | Backend, pollers, ingestion and databases untouched. The new web image is built while the old UI keeps being served. |
| API code only | `deploy.sh --apply api` | One extra container for about a minute; the UI and everything else untouched. Other backend services keep their image even though it is the same repository. |
| Polling code | `deploy.sh --apply poller` | Pollers one at a time; the API and UI untouched. |
| Alert rules / worker loops | `deploy.sh --apply worker` | |
| Syslog parsing | `deploy.sh --apply syslog` | The ingress buffers; nothing lost. |
| A migration | `deploy.sh --apply migrate`, then the services that need it, or `backend` | |
| nginx configuration (`frontend/nginx*.conf`, `*.inc`) | `deploy.sh --apply edge` | |

## Environment and secrets

- Settings: the server's `.env`, non-secret only. `deploy.sh` refuses to continue if a secret is found there.
- Secrets: `./secrets/` on the server, mounted per service as files (`/run/secrets/…`). They are never in images, build logs, `deploy/state`, or command lines.
- Image tags: `*_TAG` lines at the end of `.env` (block "deployed image tags"), written by `release.sh`. Don't edit them by hand; use `release.sh rollback`.
- Tunables (environment of `release.sh`):

  | Variable | Default | Purpose |
  |---|---|---|
  | `HEALTH_TIMEOUT` | 180 s | health gate |
  | `DNS_SETTLE` | 5 s | API switch (nginx re-resolves every 2 s) |
  | `KEEP_IMAGES` | 5 | images kept per repository |

## Troubleshooting

| Symptom | Where to look / what to do |
|---|---|
| A step failed | `deploy/state/deploy.log` and `./scripts/release.sh history`; build output in `deploy/state/build-<image>-<tag>.log` |
| "another deployment is running" | One runs already. If none does (a killed shell), delete `deploy/state/.lock`. |
| New API never healthy | The printed container log (last 30 lines). Usually a configuration / migration mismatch; the old API kept serving. |
| UI shows the old version | Hard-refresh (index is `no-store`, so it should not happen). `docker compose run --rm ui-release --list` shows the current release. |
| `nginx -t` failed on edge | Fix the configuration; the running proxy was not touched. |
| Migration refused | A destructive revision is pending: split it (expand now, contract later), or take a backup and rerun with `--allow-destructive`. |
| Disk filling with images | Lower `KEEP_IMAGES`; images in use are never removed. |

## Recovery

- **Host reboot:** containers restart from their restart policy with the deployed tags (`.env`); the UI volume keeps its current release.
- **Manual full restart:** `docker compose up -d` starts exactly the deployed versions. It never rebuilds, because every image tag exists.
- **Lost `deploy/state`:** deployments still work; history starts again. Tags are in `.env`.
- **Database restore:** `scripts/restore.sh` (see `docs/OPERATIONS.md`). Restoring older data under a newer application is safe because migrations are expand-only; run `release.sh deploy migrate` afterwards.
