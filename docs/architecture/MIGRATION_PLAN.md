# Migration plan

## Decisions (2026-11-23)

| Question | Decision |
|---|---|
| How NMS gets firewall / network logs | **Relay fan-out** (option A): own NMS receiver and store; CPU and memory measured on production volume before switching |
| User accounts | **Separate per product**, seeded once from today's accounts (hashes and roles kept); SSO can be added later |
| How users reach the products | **Two host names** (for example `siem.<domain>` and `nms.<domain>`), each with its own certificate and cookie |
| Scope now | **Phases 3–4**, tested locally; nothing deployed and no files moved on disk yet |

Principles:
- Each phase is a reviewable, revertible change with its own tests.
- Production keeps working after every phase.
- Nothing destructive happens to data: copies are verified before anything is switched, and old tables and data are
  left in place, read-only, until you approve their removal separately.
- ⚠ marks a step that needs your approval before it runs on production.

## Phase 3: boundaries inside the current tree (no behaviour change, low risk)

**Status (2026-11-23): done locally, not deployed.** Behaviour changes are listed in REMOVAL_LOG.md.

1. **Remove the 31 direct imports** listed in SEPARATION_AUDIT §2.1:
   - move helpers to platform: time helpers, the SLA timer, `rss_mib`, GeoIP reader;
   - give NMS its own event-query module (`EventFilter` / `table` equivalent) used by `hardening`, `isp`, `policies`
     and `policy/store`; until phase 6 it reads the same ClickHouse tables;
   - remove the behavioural cross-links: drift → SIEM incidents, BGP → watchlists, SIEM context → drift, SIEM ops
     page → firewall health. Before removing each one, list where it shows in the UI.
2. **Split the hubs into frameworks plus product registrations:** alerts engine, reports, retention, worker loop plans,
   bootstrap.
3. **Add a CI import contract test.** GRID modules may not import NMS modules and vice versa; both may import
   platform. It fails the build on any new cross-import.
4. **Check:** full backend suite, frontend build, and a lab run of both products.

## Phase 4: two applications from the same image (low–medium risk)

**Status (2026-11-23): steps 1–4 done locally (`docker-compose.products.yml`); step 5 (deploy) waits for approval.**

1. `create_app("grid")` and `create_app("nms")`, each mounting only its own routers, with its own `/api/health`,
   OpenAPI document and settings class.
2. Worker entry points `app.worker --product grid|nms`.
3. The frontend gets two Vite entry points (`grid`, `nms`) built from the same source tree, each with only its own
   routes and navigation. Shared pages are split: Alerts, Reports, Notifications and Settings per product; Assets and
   Log Sources go to GRID. The product selector stays only as a link to the other product's address when configured.
4. **Compose:** `grid-api`, `grid-worker`, `grid-web` and `nms-api`, `nms-worker`, `nms-web`. Both still use today's
   databases in this phase.
5. ⚠ **Deploy.** URLs change (two web front ends: host names or ports to be decided). The old single web front end can
   stay as a redirector.

## Phase 5: physical repository layout (mechanical, medium risk)

1. `git mv` into `products/sentinel-grid`, `products/sentinel-nms` and `products/shared` with import rewrites.
2. Split the test suites; each product's CI job runs only its own tests plus the shared library tests.
3. Separate Dockerfiles and `requirements.txt` per product; NMS keeps `pysnmp`, `asyncssh` and `weasyprint`, GRID
   keeps `anthropic` and `maxminddb`. Two `package.json` files, plus the shared UI package.
4. Update `deploy.sh` and its allowlist, CI and Kubernetes overlays.
5. ⚠ **Deploy** (no data change).

## Phase 6: database and ingestion separation (high risk: approval at each ⚠)

1. **New databases and users** `sentinel_nms` (PostgreSQL and ClickHouse), with least-privilege grants. Each product
   gets its own Alembic history, starting from a baseline migration that matches today's schema for its tables.
2. ⚠ **Copy NMS tables to `sentinel_nms`.**
   - PostgreSQL: dump and restore the NMS table set inside a maintenance window for NMS writers (poller, worker,
     access, ansible stopped; the SIEM keeps running).
   - ClickHouse: `INSERT … SELECT` into the new database for the NMS tables. `RENAME TABLE` is avoided, so the originals
     stay.
   - Verify row counts and checksums, switch NMS to `sentinel_nms`, and keep the originals read-only.
3. ⚠ **Users:** copy accounts and roles into each product's `users` table (passwords keep their hashes). From then on
   accounts are managed per product, unless you choose SSO.
4. ⚠ **Syslog fan-out** (option A):
   - the relay forwards to both receivers, each with its own disk queue;
   - the NMS receiver pre-filters network-operational classes and writes `sentinel_nms.events`;
   - historical NMS-relevant rows (`event_type` VPN / SD-WAN / BGP / netdev, last N days) are copied with
     `INSERT … SELECT`;
   - **measure CPU and memory first** against current production volume.
5. Split notification channels, report definitions and alert tables by product: copy, then switch.
6. ⚠ **Old tables:** each product revokes its access to the other's old tables. Physical drops happen only on a
   separate request from you.

## Phase 7: cleanup

- Remove the product-boundary code (`products.py` path table, product selector) and the duplicate shared pages.
- Remove compatibility shims from phase 3.
- Every removal goes into REMOVAL_LOG.md, with its references checked: imports, routes, dynamic imports, workers,
  migrations, deploy files, tests.

## Phase 8: security and performance review

- Per-product secrets: each product has its own `SECRET_KEY` and `TOKEN_ENCRYPTION_KEY`.
- Re-encrypt NMS vault secrets under the NMS key.
- Run the container hardening checks per service.
- Measure ingestion CPU with the fan-out.

## Phase 9: optional integration, tests, documents

- Build the integration (off by default).
- Isolation tests: each product starts, runs and passes its tests with the other stopped.
- Database permission tests.
- Write the remaining architecture documents: BACKEND_SEPARATION, FRONTEND_SEPARATION, DATABASE_SEPARATION,
  SHARED_COMPONENTS, SIEM_NMS_INTEGRATION, DEPLOYMENT_GUIDE, REMOVAL_LOG, TEST_RESULTS, FINAL_SEPARATION_REPORT.

## Rollback per phase

| Phase | Rollback |
|---|---|
| 3–5 | Code-only changes: redeploy the previous release |
| 6 | The originals stay untouched and read-only, so pointing NMS back at the original database restores the previous state. The NMS rows written after the switch would then be lost, so phase 6 includes a tested reverse-copy script. |
