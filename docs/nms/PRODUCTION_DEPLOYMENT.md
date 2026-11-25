# Production deployment: Sentinel NMS device access

Nothing in this release is deployed automatically. These are the steps for when you decide to deploy.

## What changes

| Item | Change |
|---|---|
| PostgreSQL | Migration **0036** (additive, extensions: discovery methods, Telnet / HTTPS-pin columns, console servers, wireless integrations, playbooks; [NMS_EXTENSIONS.md](NMS_EXTENSIONS.md)) after migration **0035** (additive): `users.nms_roles`, `switches.access_platform`, `device_ssh_credentials.kind / owner / rotated_at`, and 8 new `nms_*` tables. No ClickHouse migration. |
| New service | `ansible` (playbook runner, own image `backend/Dockerfile.ansible`: ansible-core and pinned network collections, fetched from PyPI and Ansible Galaxy at build; limits 2 CPU / 1 GB; networks backend + egress). The server's build must reach galaxy.ansible.com, and this image has not yet been built in Docker. |
| New service | `access` (Device Access Gateway): `python -m app.access`, port 8100 (internal), limits 1 CPU / 512 MB / 256 PIDs |
| `api` | `ACCESS_GATEWAY_INPROCESS=false` (the access routes move to `access`) |
| `web` (nginx) | `location /api/nms/access/` → `access:8100` with WebSocket upgrade (`proxy_access.inc`), a `map $http_upgrade` in `nginx-main.conf`, and `$access_upstream` in `upstream.inc` |
| Frontend | New dependencies `@xterm/xterm 5.5.0` and `@xterm/addon-fit 0.10.0` (exact versions, loaded only by the terminal chunk) |
| Worker | Config-backup housekeeping also purges expired recordings and expires unused tickets |
| Kubernetes | `web-upstream` ConfigMap points `$access_upstream` at the api Service (in-process mode). There is no separate Deployment yet. |

The deployment files were backed up before editing to `backups/pre-nms-access-2026-11-20/` (git-ignored, never
synced).

## Settings (all optional; defaults shown)

```
ACCESS_TERMINAL_ENABLED=true          # browser terminal (permissions still required)
ACCESS_ALLOWED_ORIGINS=               # empty = same host only (via X-Forwarded-Host from nginx)
ACCESS_MAX_SESSIONS=50  ACCESS_MAX_SESSIONS_PER_USER=5  ACCESS_MAX_SESSIONS_PER_DEVICE=3
ACCESS_IDLE_TIMEOUT_SECONDS=900  ACCESS_MAX_SESSION_SECONDS=14400  ACCESS_CONNECT_TIMEOUT_SECONDS=15
ACCESS_RECORDING=commands             # off | commands | full
ACCESS_RECORDING_RETENTION_DAYS=90  ACCESS_RECORDING_MAX_BYTES=2000000
ACCESS_COMMAND_TIMEOUT_SECONDS=60  ACCESS_BULK_CONCURRENCY=10  ACCESS_BULK_MAX_DEVICES=500
NMS_CONFIG_CHANGES_ENABLED=false      # approved changes; keep false until you have reviewed the change procedures
NMS_CHANGE_CONFIRM_MINUTES=5          # Junos commit confirmed window
```

## Steps

1. **Pre-check:**
   - backend tests;
   - frontend typecheck, tests and build;
   - `docker compose config -q` on the server after sync.
2. **Deploy** with the usual command:

   ```bash
   printf 'yes\nyes\nyes\n' | ./scripts/deploy.sh --apply
   ```

   It syncs the allowlisted files, including the new `frontend/proxy_access.inc`, then builds, migrates and restarts.
3. **Verify:**
   - `docker compose ps`: `access` is healthy;
   - `docker compose logs access`: no tracebacks;
   - `alembic current` = 0036;
   - `docker compose ps ansible` is healthy (heartbeat);
   - `curl -k https://<host>/api/nms/access/health` → `{"status":"ok"}`;
   - in the UI, NMS → Device Access loads.
4. **Enable for people:**
   - Administration → NMS roles: give engineers `network_engineer` (or `network_operator`) and approvers
     `nms_admin` / `site_admin`;
   - Credential vault: add a read-only SSH account; assign it per device or per group;
   - add the devices' management networks if they are not there.
5. **First connection per device** pins its host key. For critical devices, compare the fingerprint with the device
   (`show ip ssh` / `show crypto key mypubkey`) before the first session.
6. **Changes:** only after review, set `NMS_CONFIG_CHANGES_ENABLED=true` and restart `access`. Use a separate,
   privileged change account in the vault where that is the policy.

## Capacity

- **Measured on the development machine:** 100 concurrent simulated terminals at about 0.5 MB each. The service limit
  of 512 MB covers the default cap of 50 sessions with a wide margin.
- **Existing services:** no limits of the existing syslog, worker or ClickHouse services were changed. Their memory
  pressure is ingest-driven and separate (docs/performance).
- **More headroom:** raise `ACCESS_MAX_SESSIONS` together with the `access` memory limit, and measure first.

See [ROLLBACK_PLAN.md](ROLLBACK_PLAN.md) for reverting.
