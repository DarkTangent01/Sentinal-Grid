# Rollback guide

## Automatic rollback (during a deployment)

`scripts/release.sh` never leaves a service on an unhealthy version.

| Situation | What happens |
|---|---|
| Build fails | Nothing is switched; every service keeps running its image |
| Migration check refuses / migration fails | No service is switched |
| New api / poller never healthy | The new container is removed. The old one never stopped serving. |
| Public check fails right after the api switch | The old api container (stopped, not removed) is started again and the new one removed |
| worker / access / syslog / traps / flows / ansible / edge unhealthy after replacement | Recreated with the previous tag |
| UI release missing an asset | Not switched |
| UI release fails the check through nginx after the switch | Switched back to the previous release |

Every case is recorded in `deploy/state/history.jsonl` with result `rolled back`, `failed` or `refused`, and shown on
Administration → Deployments. The command exits non-zero.

## Manual rollback (after a deployment)

From the workstation:

```bash
./scripts/rollback.sh api        # also: ui, worker, poller, access, syslog, traps, flows, ansible, edge, ingress, tacacs
./scripts/rollback.sh --status   # current and previous version of every service
```

On the server: `./scripts/release.sh rollback <service>`.

**Behaviour:**
- **Target version:** the service returns to the tag recorded in `deploy/state/versions.prev.env`, the version before its last change.
- **No rebuild:** the image is already on the host (the newest 5 per repository and every image in use are kept).
- **Same safety as a deployment:** the same strategy is used (rolling for api / poller, replace with a health gate for the others), with the same automatic rollback.
- **UI:** switches the `current` symlink back to the previous release on the volume. It's instant and nothing restarts. The last 5 releases are kept.
- **Repeating:** a second rollback of the same service toggles back to the version you rolled back from.

## What is never rolled back automatically

**Database migrations.** They are expand-only (enforced by `app.migrate_check`), so the previous application version runs
on the newer schema. If a migration itself must be undone:
1. take a backup (`scripts/backup.sh`);
2. write a new forward migration that reverses the change, or restore from a backup taken before it (`scripts/restore.sh`);
3. deploy `migrate`.

Alembic `downgrade` is not run in production.

## Rolling back several services

Roll back in reverse dependency order:
1. the proxy;
2. the UI;
3. the collectors;
4. the worker and pollers;
5. the API.

Each command is independent:

```bash
for s in ui flows traps syslog access worker poller api; do ./scripts/rollback.sh "$s"; done
```

## When the previous image is gone

If `rollback` reports the image is no longer on the server, check out the earlier source on the workstation and run
`./scripts/deploy.sh --apply <service>`. The source hash produces a new tag for the old code.
