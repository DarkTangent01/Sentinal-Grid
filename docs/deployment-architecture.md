# Deployment architecture

How Sentinel NMS and Sentinel Grid are deployed on the production Docker host without stopping the stack. Covers:
- the audit of the previous process (section 1);
- the chosen design (sections 2–9);
- the measured interruption per service (section 10).

Commands are in [deployment-guide.md](deployment-guide.md), rollback in [rollback-guide.md](rollback-guide.md), and service
dependencies in [service-dependencies.md](service-dependencies.md).

## 1. Audit of the previous process

**Environment:**
- one host: 24 vCPU, 15 GB RAM (about 6 GB available), 125 GB free disk;
- Docker 29.9 and Docker Compose 5.6;
- one Compose project with 15 containers;
- no Kubernetes in production. The repository's `k8s/` manifests are not deployed.

**What `scripts/deploy.sh --apply` did:**
1. rsync the code;
2. `docker compose build` (every image);
3. `nginx -t`;
4. `docker compose up -d` (every service whose image or configuration changed).

**Root causes of the downtime:**

| Finding | Effect |
|---|---|
| All images were rebuilt on every deployment | A UI-only change still rebuilt the backend (and the reverse); minutes of build per deployment |
| One fixed tag for every backend service (`fortisiem-backend:1.0.0`, reused) | Any backend change recreated **api, worker, access, three pollers, syslog, traps, flows and migrate at the same time**; there was no previous image to go back to |
| `docker compose up -d` stops a container, then starts its replacement | A single **api** was absent until the new one was healthy: **502** from nginx for tens of seconds |
| The UI was baked into the nginx image | A UI-only change recreated **web**, the only process holding ports 80 / 443: **connection refused** while it restarted |
| `api` / `worker` waited for `migrate` | A slow migration kept the API down longer (the 5-minute rollup back-fill took 70 s) |
| No health gate and no rollback | A bad image replaced a good one and stayed |
| Previously in place | Databases were not recreated (their images are pinned and unchanged), and the **syslog ingress** (rsyslog with a disk spool) kept receiving logs while the processing service restarted |

**Health checks before this change:**
- api: `/api/health` (liveness only);
- worker / pollers / syslog / traps / flows: heartbeat files;
- web: its own `/api/health` through itself.

**Infrastructure:**
- PostgreSQL and ClickHouse are on named volumes, with no published ports.
- There is no Redis and no message broker. Work is coordinated through PostgreSQL: device poll leases, job tables, the alert engine's dedup keys.

## 2. Decision: stay on Docker Compose, deploy per service

Kubernetes / K3s is **not** introduced:
- the platform is a single host;
- Compose already provides health checks, restart policies, resource limits and secrets;
- the missing pieces were process and topology, not the orchestrator.

The workflow below adds what Compose lacks:
- per-service versioning;
- health-gated switches;
- rolling replacement of the API;
- atomic UI releases;
- automatic rollback;
- deployment history.

The existing nginx stays the reverse proxy.

```
            workstation                                   server (scripts/release.sh)
  ./scripts/deploy.sh --apply [target]   ──rsync──►   build only changed images (tag <UTC date>-<source hash>)
                                                       │
                                                       ├─ migrate     expand-only check → migrations (old version keeps running)
                                                       ├─ api         rolling: api#2 (new) → /api/ready → nginx sees both → api#1 drains, stops
                                                       ├─ poller      rolling, one replica at a time (device leases: no double polls)
                                                       ├─ worker / access / syslog / traps / flows / ansible   stop → start → health gate
                                                       ├─ ui          publish release into the "ui" volume → verify assets → atomic switch
                                                       └─ edge        nginx -t with the new image → replace the proxy (only when nginx changes)
                         failure at any step → the previous container / release / image is restored; databases never touched
```

## 3. Independent images and versioning

- **Tags:** `fortisiem-<image>:<UTC yyyymmdd-HHMM>-<source hash>`, for example `fortisiem-backend:20261126-0712-3fa1c2e9b0d4`.
- **Labels:** each image carries `sentinel.source` (the hash of its build context), `sentinel.edge` (the hash of the nginx configuration, web image only) and `org.opencontainers.image.version`.
- **No rebuild of an unchanged source:** if an image with the same source hash exists, it is reused (`--no-cache` forces a rebuild).
- **Independent services:** every service has its own tag variable in the server's `.env`:
  - `API_TAG`, `WORKER_TAG`, `POLLER_TAG`, `ACCESS_TAG`, `SYSLOG_TAG`, `TRAPS_TAG`, `FLOWS_TAG`, `MIGRATE_TAG`;
  - `ANSIBLE_TAG`, `WEB_TAG` (the proxy), `UI_TAG` (the UI release), `INGRESS_TAG`, `TACACS_TAG`;
  - `BACKEND_TAG`: the fallback for backend services never deployed independently.

  `docker-compose.yml` interpolates these variables, so a plain `docker compose up -d` (after a host reboot, say) always starts exactly the deployed versions.
- **Version visibility:** the running API reports its version (`SENTINEL_VERSION`) on the Deployments page.
- **Rollback images:** the previous image of every service stays on the host. Pruning keeps the images in use plus the newest 5 per repository (`KEEP_IMAGES`).
- **Source control:** the deployment checkout isn't a Git working copy, so the source hash identifies the code. If one is added, a `git-<sha>` tag can be added in `release.sh build`.

## 4. UI releases without restarting nginx

The web image now places the built UI under `/srv/ui`:

| Path | Contents |
|---|---|
| `releases/<release>/` | `index.html`, unhashed public files, and the asset list `.assets` |
| `assets/` | content-hashed bundles shared by releases |
| `current` | symlink to the release nginx serves |

**How a release is published:**
- In Compose, `/srv/ui` is the named volume `ui`, mounted **read-only** into `web`.
- The one-shot service `ui-release` runs the *new* web image as uid 10101, with no capabilities and a read-only root filesystem.
- `publish-ui` copies the release and adds its assets to the pool, without overwriting.
- It verifies that every asset `index.html` references exists, then renames a symlink onto `current`. That rename is atomic: a request sees the old release or the new one, never a mix.

**Caching:**
- `index.html` is served `no-store`.
- `/assets/*` is `immutable` for 30 days. The assets of the last 5 releases stay in the pool, so a browser still running the previous release loads its lazy chunks after the switch: no blank page, no 404.
- Kubernetes (`k8s/`) keeps working: the image contains the same layout with `current → releases/image`.

## 5. Rolling API

The API runs as **two single-process containers** (`API_REPLICAS`, default 2; `uvicorn --workers 1`).

**Why single-process:** a multi-worker uvicorn master accepts connections before its workers are ready, and keeps accepting while it shuts down. Requests then queue instead of being refused, which the first production test measured: 2 s+ stalls. A single process listens only once the app has started, and closes its socket at once on SIGTERM.

**Start-up warm-up:** at start-up the API opens its PostgreSQL and ClickHouse connections before it listens.

**`release.sh deploy api`, per replica:**
1. Create the new container (`docker compose up --no-deps --no-recreate --scale api=N+1`), and **detach it from nginx's network** until it is ready.
2. Wait for its health check, which is now `/api/ready` (PostgreSQL and ClickHouse). If it never becomes healthy, it is removed; nothing else changed.
3. Send it five warm-up requests from inside the container, then attach it to the network with the alias `api`.
4. Wait 5 s. nginx re-resolves `api` every **2 s** (`frontend/upstream.inc`) and balances across all containers.
5. Stop the old container (`docker stop -t 30`). On SIGTERM, uvicorn stops listening and finishes in-flight requests (`--timeout-graceful-shutdown 25`).
6. Retry stale addresses quickly:
   - A request nginx sends to an address it still has cached gets a refusal, or no answer once the container is gone.
   - nginx gives up on such a connect after **2 s** (`proxy_connect_timeout`) and retries the other container (`proxy_next_upstream error timeout http_502 http_503`).
   - Requests already sent are never replayed for POST.
7. Wait 5 s, then check the public path through nginx (`/api/ready`, `/`). If it fails, the old container is started again.
8. **If any step fails on any replica, every replica is returned to the previous version.** A rollback in the middle of a roll used to leave mixed versions; the first production test found that, and it is fixed.

**Two APIs at once is safe:** the API holds no singleton work. The access gateway runs in its own service, and background loops live in the worker.

**Request limits:**
- A request that takes longer than the 25 s drain is cut when its container stops. One existing endpoint, `/api/system/coverage`, currently runs into ClickHouse's 60 s limit; it should be fixed separately.

## 6. Workers, pollers and collectors

**Pollers** (3 replicas): rolling, one at a time.
- Each replica claims devices through a database lease (`UPDATE … WHERE lease expired`), so the old and new containers never poll the same device. Polling continues at two-thirds or more of capacity during the switch.
- A poll cut short by SIGTERM leaves its lease to expire; the device is polled again on the next cycle. Its counter baseline is in PostgreSQL, so no rate is lost or invented, and the gap is flagged.

**Worker** (alert evaluation, retention, jobs, SOC summaries, identity index …): stop, then start.
- Its loops are singletons without a leader election, so two workers at once would evaluate alerts twice.
- Loops are periodic over time windows, so a pass skipped for a few seconds is covered by the next one. Alert deduplication prevents duplicates.
- SIGTERM sets the stop event; loops finish their current step (grace 30 s).

**Access gateway:** stop, then start.
- It closes "orphaned" terminal sessions at start-up, so two instances would end each other's sessions.
- **Live SSH / Telnet sessions end** when it is deployed: deploy it outside busy hours.

**Syslog processing:** stop, then start.
- The **syslog ingress** (rsyslog, its own container, not redeployed) keeps receiving on UDP / TCP 514 and spools to disk while processing restarts. Nothing is lost.
- Messages are delivered in order once processing is back.
- Event chunks ClickHouse rejects go to the dead-letter volume (`python -m app.ingest.deadletter`).

**SNMP traps / flows:** stop, then start.
- Both bind host UDP ports (162; 2055 / 4739 / 6343), so two instances cannot run.
- Datagrams that arrive during the few seconds of the switch are lost (UDP has no retransmission). Flow data is sampled telemetry, and traps are complemented by polling.

**Ansible runner:** stop, then start; a running playbook is signalled and recorded as interrupted.

## 7. Database protection and migrations

**Databases are never touched by a deployment:**
- PostgreSQL and ClickHouse are never built, recreated, stopped or restarted by `release.sh`.
- Their data lives on named volumes (`pgdata`, `chdata`).
- Backups: `scripts/backup.sh`. `deploy.sh` takes a backup before any deployment that may change the database, and skips it for UI / proxy-only deployments.

**Migrations** run as their own step before backend services switch, using the new image's migrate job:
- **Check first:** `python -m app.migrate_check` lists the pending revisions and **refuses destructive ones** (drop / rename table or column, type changes, DROP / TRUNCATE / DELETE SQL) unless `--allow-destructive` is given.
- **On failure** nothing else changes: services keep the previous version.

**Expand and contract** for breaking schema changes:
1. Add new tables / columns / indexes (nullable or defaulted).
2. Deploy code that works with old and new.
3. Backfill.
4. Deploy code that uses only the new schema.
5. Remove the old schema in a **later** release, with `--allow-destructive` after a backup.

**History:** every revision since 0028 is expand-only. 0024 and 0027 contained drops; they are applied everywhere, and the check skips the refusal on an empty database.

**Rollback** never reverses migrations: the previous version runs on the expanded schema.

## 8. Health checks

| Service | Check | What it proves |
|---|---|---|
| api | `/api/ready` → status ok | process up, PostgreSQL and ClickHouse reachable (rolling switches gate on it) |
| web (proxy) | `https://127.0.0.1:8443/api/health` through itself | nginx serving TLS and reaching an api |
| worker, poller | heartbeat file younger than 120 s | the main loop is turning (the loop monitor writes it) |
| syslog | heartbeat younger than 30 s | the receiver and its writer are alive |
| traps, flows | heartbeat younger than 180 s | listener loop alive |
| access | `/api/nms/access/health` | gateway API up |
| ingress | rsyslogd pid alive | front end receiving |
| postgres / clickhouse | `pg_isready` / `/ping` | databases accept queries |
| UI release | every asset index.html references exists; `/` and `/api/ready` through nginx after the switch | the release loads |

Health endpoints return no secrets or versions. Versions are shown only on the administrator-only Deployments page.

## 9. Deployment state, history and UI

`deploy/state/` on the server holds:
- `versions.env`: current tags;
- `versions.prev.env`: the previous tag per service;
- `status.json`: container state and health after the last run;
- `history.jsonl`: every step, with result, from/to tags and duration;
- `deploy.log` and per-build logs.

**Shown in the app:** Administration → **Deployments** (administrators only) shows versions, the previous version kept for rollback, health, update strategy and history. It reads the state read-only through `/api/admin/deployments`.

**Locking:** a lock file prevents two deployments at once.

## 10. Measured on production (2026-11-26)

**Measurement method:**
- A probe on the server requested `https://127.0.0.1/api/ready` (which queries both databases) and `https://127.0.0.1/` every 0.2 s throughout, with a 10 s timeout.
- Ingestion: events per minute in ClickHouse.
- Polling: devices sampled per minute.

| Test | Requests | Failed (API / UI) | Slow > 1 s | Notes |
|---|---|---|---|---|
| API deploy, final design (two replicas, warm-up off-network) | 444 | **0 / 0** | 1 (2.1 s) | the one slow request is the stale-address retry after the old container stops |
| API rollback, then forward again (before the off-network warm-up) | 270 + 264 | **0 / 0** | 3 + 3 (≤ 5.2 s) | cold first requests of a new process, fixed by the warm-up step |
| UI release | 569 (incl. the proxy switch) | 0 / 0 during the switch | 0 | atomic; no restart |
| UI rollback and forward | — | 0 / 0 | — | 6 s and 3 s, no rebuild |
| Proxy replacement (edge) | 575 | 9 / 9 | — | **≈ 2 s** of refused connections; only when nginx changes |
| Worker | 134 | 0 / 0 | 1 (2.3 s) | replaced in 42 s including the health gate |
| Pollers (3, one at a time) | 244 | 0 / 0 | 0 | at least 9 of the usual 14 devices polled in every minute |
| Syslog processing | — | — | — | the ingress paused forwarding for 35 s and resumed; its disk-assisted queue retries forever; no minute without events (lowest 272k vs median 306k / minute) |
| Unhealthy new API (simulated) | — | 0 | — | new container removed after 6 s; the serving containers unchanged (same IDs) |
| Failed build (simulated) | — | 0 | — | stopped in 2 s; nothing switched |
| Failed migration (simulated) | — | 0 | — | stopped; no service switched; the migrate tag unchanged |
| Public check failing after a switch (real) | — | — | — | reverted automatically; mixed versions afterwards, since fixed (§5) and retested |

**Over the whole 74-minute session**, with 16 deployments, rollbacks and failures:
- every minute had syslog events;
- SNMP polling never fell below 9 of 14 devices in any minute;
- PostgreSQL and ClickHouse were not restarted.

**Expected interruption by change:**

| Change | WebUI | API | Polling | Syslog ingestion |
|---|---|---|---|---|
| UI | none | none | none | none |
| API | none | none (one request may take about 2 s) | none | none |
| Pollers | none | none | continues | none |
| Worker | none | none | none | none (alerts / jobs pause for seconds) |
| Syslog processing | none | none | none | buffered by the ingress, delivered after |
| Traps / flows | none | none | none | UDP traps / flows for seconds |
| Access gateway | none | terminal API seconds; live sessions end | none | none |
| Proxy (edge) | about 2 s (only when nginx changes) | same | none | none |
| Databases | never by a deployment | — | — | — |

**Host resources:**
- During an API roll a third API container runs for about a minute (about 400 MB); a fourth poller runs briefly (about 150 MB).
- The second permanent API replica costs about 200 MB. The host has about 6 GB available.
- Builds run on the host: backend about 10 s with cached layers, web 3–4 minutes. Nothing is stopped during a build.

## 11. Limits and next steps

- The proxy itself has no second instance (one host, ports 80 / 443). An nginx version or configuration change costs 1–3 s.
  - **Option to remove that:** a host-level keepalived / second nginx bound through `SO_REUSEPORT`, or moving TLS termination in front of the host.
- Traps and flows lose datagrams for the few seconds of their own deployment.
- The worker is a singleton: its deployment pauses alerting for seconds. A leader election (advisory lock) would allow rolling it like the API.
- Image scanning: `scripts/security/docker-security-audit.sh` and the CI Trivy job, unchanged. `deploy.sh` still runs the container / secrets policy tests before anything leaves the workstation.
