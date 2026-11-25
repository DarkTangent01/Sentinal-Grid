# Target architecture

The target is two products that build, deploy, restart, scale and fail independently. They share only business-free
libraries and, optionally, the same database servers with separate databases and users.

## Repository layout

```
products/
  shared/                    business-free libraries (Python package "sentinel_platform", TS package "@sentinel/ui")
    python/sentinel_platform/
      auth/        password hashing, session JWT, CSRF, rate limiter, RBAC helpers
      crypto/      TokenCipher (Fernet), secret files
      db/          PostgreSQL / ClickHouse connection helpers, migration runner
      logparsing/  vendor log formats → normalised records (pure functions; no storage)
      alerting/    rule registry, evaluation loop, suppression, dedupe (no rules)
      notify/      channels (email, webhook, Slack, Teams …)
      reports/     scheduling, HTML / PDF rendering, email delivery (no sections)
      observability/, logging/, netguard/ (SSRF / address checks)
    ui/            React primitives, charts, theme, API client, layout shell
  sentinel-grid/
    backend/app/   ingestion (receiver, pipeline, sink), analytics, detection, threat_intel, incidents, response,
                   identity, zeek, hunting, soc, compliance, assets, log_sources, api/, models/, worker.py, main.py
    backend/migrations/      own Alembic history (starts from a baseline of today's GRID tables)
    backend/tests/
    frontend/                security pages only
  sentinel-nms/
    backend/app/   inventory (switches), discovery, snmp (poller, traps), vendors (fortigate, paloalto, adapters),
                   wireless (+ integrations), topology (L2 / L3), routing (bgp), wan (isp, icmp, sdwan, vpn),
                   flows, configuration (backup, drift, iac, compliance, change requests), access (gateway),
                   automation (playbooks), tacacs, ingestion (network-operational receiver), alerts, api/,
                   models/, worker.py, main.py
    backend/migrations/
    backend/tests/
    frontend/                network pages only
infrastructure/
  compose/ shared-infrastructure.yml (postgres, clickhouse, ingress relay)
           sentinel-grid.yml, sentinel-nms.yml
  kubernetes/ (one overlay per product)
docs/architecture/
```

## Runtime

```
                  syslog / HTTP ingest
                          │
                   ingress relay (rsyslog, shared edge) ──► fan-out (both targets have their own disk queue)
                  ┌───────┴───────────────────────────┐
           grid-syslog                          nms-logs (network classes only:
      (security pipeline)                       VPN / SD-WAN / BGP / interface / routing /
                  │                              system / config change / netdev)
       ClickHouse db sentinel_grid               ClickHouse db sentinel_nms
                  │                                        │
grid-api, grid-worker ── PG db sentinel_grid     nms-api, nms-worker, poller, traps, flows, access, ansible,
                  │                              tacacs ── PG db sentinel_nms
            grid-web (SIEM UI)                    nms-web (NMS UI)
                  └──────── optional integration (off by default) ────────┘
```

## Contracts between the products

- **None are needed to run.** Either product runs with the other stopped or not installed.
- **Optional integration** (SIEM_NMS_INTEGRATION.md, to be written in phase 9):
  - versioned HTTP contract `/api/v1/integration/...`;
  - each product holds a token for the other;
  - disabled by default; calls time out and fail open;
  - every call audited.

  Uses:
  - NMS publishes network fault events and a device lookup (name, address, site, role);
  - the SIEM links incidents and events to NMS devices by address and offers cross-links.

## Data ownership

| Store | GRID | NMS |
|---|---|---|
| PostgreSQL | database `sentinel_grid`, user `grid_app` | database `sentinel_nms`, user `nms_app` |
| ClickHouse | database `sentinel_grid` (events, rollups, rejects, …), user `grid_app` | database `sentinel_nms` (metrics, wireless, flows, traps, network events, self-metrics), user `nms_app` |
| Users | own `users` table (seeded by copying today's accounts that have the `grid` product) | own `users` table (accounts with `nms`, plus their NMS / IaC / TACACS roles) |

Neither database user has any grant on the other product's database.

## API

Each product serves its own `/api/*`, so the existing paths keep working behind each product's own host name or port
(backward compatible). Versioned aliases (`/api/v1/security/...` for the SIEM, `/api/v1/devices|...` for NMS) are added
next to the existing paths and documented. The existing paths are not removed in this project.
