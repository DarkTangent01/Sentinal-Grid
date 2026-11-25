# Removal and behaviour-change log

Every removal, move or behaviour change made by the product separation, with what was checked before it was made
(imports, routes, dynamic imports, workers, migrations, deploy files, tests). Phases 3–4 are local only: nothing here
is deployed yet.

## Phase 3 – boundaries inside the tree (2026-11-23)

### Moves to the shared `app/platform` package (no behaviour change)

| From | To | Callers updated |
|---|---|---|
| `app/analytics/filters.py` | `app/platform/eventquery.py` | every importer; the SIEM query language registers itself (`analytics/ql.py` → `eventquery.QL_COMPILER`) instead of being imported by the platform |
| `app/enrich/geo.py` | `app/platform/geoip.py` | enricher, analytics, NMS users |
| `rss_mib`, `release_memory` (`ingest/pipeline.py`) | `app/platform/procstats.py` | pipeline, selfmon |
| `ch_time`, `to_utc` (vpnmon, identity, policy store, assets) | `app/platform/timeutil.py` | same; `policy/store.py` keeps `to_utc` as a re-export |
| `_hour_bounds` (`policy/store.py`) | `app/platform/timeutil.py hour_bounds` | `alerts/siem.py`; `policy/store.py` keeps `_hour_bounds` as a re-export |
| SLA timer (`incidents.py`) | `app/platform/sla.py` | incidents, wan, api/wan |
| `coverage`, `_iso`, `_clean` (`analytics/queries.py`) | `app/platform/eventquery.py` | `api/admin.py /system/coverage`; `analytics/queries.py` re-exports them |
| `Mitre` badge, `TACTIC_NAMES` (`pages/Incidents.tsx`) | `components/Mitre.tsx` | Alerts, Settings; Incidents re-exports them |

### Routes moved between routers (same paths, same responses)

| Routes | From | To |
|---|---|---|
| `/api/fwhealth/*`, `/api/vpn-tunnels/*`, `/api/bgp/*` | `api/ops.py` (SIEM) | `api/netops.py` (NMS) |
| `/api/drift/*` | `api/context.py` (SIEM) | `api/netops.py` (NMS) |
| `/api/notifications/*` | `api/soc.py` (SIEM) | `api/notifications.py` (shared) |
| `/api/reports/*` | `api/soc.py` (SIEM) | `api/reports.py` (shared) |
| `/api/alert-rules/stats` | `api/soc.py` (SIEM) | `api/alerts.py` (shared) |

New: `GET/PUT /api/bgp/critical-prefixes` (NMS; PUT administrators only, audited) and an editor on the BGP page.

### Hubs split into frameworks plus product registrations

- **Alert engine.** `alerts/engine.py` is now the framework (Detection, grouping / dedup / suppression, rule registry,
  hooks, `run_rules(product=…)`). SIEM rules, the custom (`cq_`) and YAML (`yml_`) runners, asset-criticality severity
  and correlation / notification / automation live in `alerts/siem.py`. NMS rules (firewall health, ISP, ICMP, IPsec,
  BGP, IaC drift, risky change) and the NMS module rule sets live in `alerts/nms.py`, with maintenance-window admission,
  auto-resolve and notification. `alerts/rules.py` holds only SIEM definitions. `alerts/combined.py` keeps the combined
  deployment's behaviour.
- **Reports.** `reports.py` is the framework (section registry, rendering, scheduling, PDF). Sections live in
  `analytics/report_sections.py` (SIEM) and `nms/report_sections.py` (NMS).
- **Composition.** `app/composition.py load(product)` is the only place that decides which registrations a process
  loads (API, worker, seeding, tests).
- **Worker.** `PRODUCT` selects the loops (`LOOP_PRODUCT`, `JOB_PRODUCT`); `WORKER_SHARED_JOBS` selects the one worker
  that runs notification delivery and retention.

### Behaviour changes

| Change | Where it shows | Combined deployment (today's) | Separated products |
|---|---|---|---|
| Drift detections are no longer correlated into SIEM incidents (`drift.correlate_alerts` removed) | Incidents page: risky-change alerts no longer join an incident | changed | changed |
| `risky_config_change` alerts are NMS alerts (`products.NMS_RULES`) | listed under Network Alerts instead of Grid Alerts | changed | changed |
| BGP critical prefixes come from the NMS setting, not the SIEM watchlist `bgp_critical_prefixes` (migration 0037 copied the list; the watchlist is left untouched) | BGP page and `bgp_critical_prefix` rule | changed (same prefixes) | changed |
| Report section order: in a combined report, "Firewall policy hygiene" now follows "Compliance evidence" | report layout only | changed | — |
| NMS alerts are correlated into SIEM incidents, trigger SIEM automation and get asset-criticality severity | Incidents, Automation | **unchanged** (`alerts/combined.py`) | NMS alerts are only notified; cross-product correlation becomes the optional integration (phase 9) |
| TACACS+ security detections (`tacacs_auth_failures`, `tacacs_success_after_failures`, …) are computed by the NMS TACACS+ module but listed as Grid alerts | Grid Alerts | **unchanged** | produced by the NMS process; reaching the SIEM needs the integration (phase 9) |
| Report definitions mixing SIEM and NMS sections | scheduled reports | **unchanged** | run by Grid, without the NMS sections, until definitions are split (phase 6) |
| `/api/health` adds `"product"` (`grid`, `nms` or `combined`) | health checks (they look for `ok`) | additive | additive |

Nothing was deleted from the databases. No route path changed.

## Phase 4 – two applications from one tree (2026-11-23, not deployed)

- `create_app(product="grid" | "nms")` mounts the shared routers (auth, alerts, admin, notifications, reports) plus
  that product's routers; `create_app()` (the Dockerfile's default) is unchanged. `create_product_app` reads `PRODUCT`.
- Frontend: `npm run build:grid` / `build:nms` build one product into `dist-grid` / `dist-nms`. The other product's
  routes, navigation and page chunks are not in the bundle. In the NMS build, Assets and Log Sources are left out
  (their APIs are Grid's). `npm run build` still builds the combined app.
- `docker-compose.products.yml` (overlay, not used by `deploy.sh`): `grid-api`, `grid-worker`, `grid-web`, `nms-api`,
  `nms-worker`, `nms-web`; the combined `api` / `worker` / `web` move to profile `combined`. The `frontend/Dockerfile`
  build argument `PRODUCT` (default empty = combined) selects the build.
- CI contract: `tests/test_product_boundaries.py` fails on any import between products, any product import from a
  shared module, any import of a composition hub, and any unclassified module.
