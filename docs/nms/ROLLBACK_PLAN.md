# Rollback plan: Sentinel NMS device access

Every change in this release can be reverted without data loss to the existing SIEM / NMS.

| Risk | Fast mitigation (no redeploy) | Full rollback |
|---|---|---|
| A terminal problem | `ACCESS_TERMINAL_ENABLED=false`, restart `access` | — |
| A change-workflow problem | `NMS_CONFIG_CHANGES_ENABLED=false` (the default), restart `access`; approvals stay recorded | — |
| Gateway instability | `docker compose stop access`: device access is unavailable, and everything else is unaffected (nginx returns 502 for `/api/nms/access/*` only) | Redeploy the previous release |
| nginx configuration | — | Restore `frontend/nginx.conf`, `nginx-main.conf`, `upstream.inc` and `Dockerfile` from `backups/pre-nms-access-2026-11-20/`, then rebuild `web` |
| Compose file | — | Restore `docker-compose.yml` from the same backup; `docker compose up -d --remove-orphans` removes `access` |
| Extensions (0036) | `ACCESS_TELNET_ENABLED=false`; disable wireless integrations; `docker compose stop ansible` (queued runs wait) | `alembic downgrade 0035` drops console servers / ports, wireless integrations, playbooks and runs, and the new columns (export first anything you need) |
| Database | The new tables and columns are unused by the previous release, so leaving them in place is safe | `alembic downgrade 0034` drops the 8 `nms_*` tables and the 5 new columns. **This deletes access audit records, session history, diagnostic results and change requests:** export the audit first (`/api/nms/access/audit/export.csv`) |
| Kubernetes | — | Restore `k8s/applications/frontend/web.yaml` from the backup (`k8s-web.yaml`) |

## Procedure: full rollback to the previous release

1. Export the access audit (CSV) if any device access has happened.
2. Restore the backed-up deployment files, or redeploy the previous code revision with `scripts/deploy.sh`.
3. `docker compose up -d --remove-orphans`.
4. Optional, only if the schema must be identical to 0034:

   ```bash
   docker compose run --rm migrate alembic downgrade 0035   # extensions only
   docker compose run --rm migrate alembic downgrade 0034   # also device access
   ```

5. Verify:
   - `/api/health` returns 200;
   - NMS pages load;
   - syslog counters advance;
   - the worker heartbeat is fresh.

## Devices

- Diagnostics and read-only terminals make no changes on devices.
- Changes made through approved change requests are not reverted by a software rollback. Roll them back first, from
  each request (**Roll back**), or by hand from the stored before-backup and diff.
