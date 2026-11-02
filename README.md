# Sentinel Platform: Sentinel Grid (SIEM) and Sentinel NMS (network monitoring)

Sentinel is a self-hosted security and network operations platform for a multi-site estate of FortiGate firewalls,
Cisco / Ruckus / Fortinet / Juniper network devices, Cisco Catalyst 9800 wireless controllers and ISP circuits. It
ships as two products that share one sign-in, API, database and set of background workers:

| Product | What it is for | Entry |
|---|---|---|
| **Sentinel Grid** | SIEM: firewall log analytics, threat detection, threat intelligence, incidents, hunting, identity, compliance evidence | `/grid` |
| **Sentinel NMS** | Network monitoring: SNMP device monitoring (any vendor), wireless and RF, ISP / WAN, firewall health, BGP, VPN, service checks, analytics, traps, TACACS+ AAA, policy and configuration management | `/nms` |

Each account is granted Grid, NMS or both. Administrators always see both, and analysts can be limited to specific NMS sites.

**Stack:** Python 3.12 · FastAPI · SQLAlchemy 2 (async) + Alembic · PostgreSQL 16 · ClickHouse 24.8 · pysnmp 7 ·
React 18 + TypeScript + Vite + Tailwind + TanStack Query + ECharts · nginx · rsyslog (ingress relay) · Docker Compose.

**Read-only by design:**
- The platform only reads from firewalls (REST GET), switches and controllers (SNMP GET / GETBULK) and Palo Alto devices (PAN-OS `show` / config `get`).
- The only path that can change a device is the opt-in, approval-gated **Infrastructure as Code** module. It is off unless `IAC_DEVICE_WRITES=true` *and* it is enabled in the IaC settings.
- TLS certificates are always verified.

---

## Contents

1. [Features](#features)
2. [Architecture](#architecture)
3. [Quick start (Docker)](#quick-start-docker)
4. [Connecting data sources](#connecting-data-sources)
5. [Configuration reference](#configuration-reference)
6. [Security model](#security-model)
7. [Observability and health](#observability-and-health)
8. [Deployment, backup and rollback](#deployment-backup-and-rollback)
9. [Local development](#local-development)
10. [Tests and CI](#tests-and-ci)
11. [Project layout](#project-layout)
12. [Documentation index](#documentation-index)
13. [Verification status and known limits](#verification-status-and-known-limits)

---

## Features

### Sentinel Grid (SIEM)

| Area | What it does |
|---|---|
| **Log analytics** | Traffic, DNS-filter, web-filter, IPS, AV, app-control, VPN and system events from FortiGate (and Palo Alto). Dashboards, top sources / destinations / ports, web / URL, DNS, geography and an event explorer with a query language: `src_ip:10.0.0.0/8 AND action:deny AND dst_port:445`, OR / NOT, ranges, wildcards. |
| **Detections** | 42 built-in security rules (port scans, deny bursts, host sweeps, beaconing, DNS tunnelling, NXDOMAIN bursts, new domains / countries / ports, outbound volume against a 7-day per-host baseline, VPN brute force, impossible travel, Windows auth rules, admin and configuration changes), plus custom rules and **Sigma** import. Every rule is mapped to MITRE ATT&CK. |
| **Threat intelligence** | abuse.ch Feodo, Spamhaus DROP, CERT Polska, IPsum and a manual IOC list, matched at ingest on IPs, CIDRs, DNS queries and hostnames, plus retroactive **Hunt**. |
| **Incidents and cases** | Alerts about one entity within 24 h are correlated into incidents. Severity rises with the number of tactics. Cases have assignees, SLA timers, comments, a timeline, closure verdicts, MTTA / MTTR and per-rule false-positive rates. |
| **Investigation** | IP investigation pages, an entity graph, hunting queries, bookmarks, workbooks, watchlists and saved / scheduled searches. |
| **Identity and assets** | Learned assets (hostname, MAC, OS, user) with criticality; an alert involving a critical asset is raised one severity level. VPN users, impossible travel, administrator activity. |
| **Automation** | SOAR-style playbooks: trigger → conditions → actions on SIEM data (assign, notify, enrich, watchlist). `suggest_block` only generates CLI for review. |
| **Notifications** | Slack, Microsoft Teams, SMTP email and HMAC-signed webhooks. Routing by event type and severity, quiet hours, de-duplication, persistent outbox with retries. |
| **Compliance evidence** | CERT-In, ISO 27001:2022, PCI DSS 4.0 and NIST CSF 2.0 controls, computed from live configuration (evidence support, not certification). |
| **AI assistant (optional)** | Turns a plain-English question into a query and summarises incidents, via the Claude API (`ANTHROPIC_API_KEY`). Event data is sent only if `AI_ALLOW_DATA_SHARING=true`. |

### Sentinel NMS (network monitoring)

| Area | What it does | Docs |
|---|---|---|
| **Network dashboard** | One page across WAN, device health, availability, service checks, capacity risk, firewalls, switches, VPN, BGP, TACACS+, open alerts and incidents | [NMS.md](docs/NMS.md) |
| **Multi-vendor SNMP monitoring** | One engine with vendor adapters for **Cisco** (Catalyst, Nexus, ISR / ASR, Catalyst 9800), **Fortinet** (FortiGate, FortiSwitch), **Juniper** (EX, QFX, SRX, MX) and **Ruckus** (ICX), plus standard-MIB monitoring of any other SNMP device. See below. | [SNMP.md](docs/SNMP.md), [SWITCHES.md](docs/SWITCHES.md) |
| **Interfaces and hardware** | Interfaces (64-bit counters, wrap / reset / reboot safe), errors, discards, CRC, CPU, memory, disks / flash, temperature, fans, PSUs, sensors, stacking, PoE, LACP, STP, VLANs, MAC table, LLDP / CDP topology and path check, OSPF / BGP neighbours | [SWITCHES.md](docs/SWITCHES.md) |
| **Vendor health** | FortiGate HA sync, IPsec tunnels, SD-WAN health checks and sessions; Junos chassis alarms, components and SRX flow sessions | [SNMP.md](docs/SNMP.md) |
| **SNMP traps** | v1 / v2c / v3 traps and informs. Only inventory devices using their own credentials are accepted. Traps are normalised, de-duplicated, stored and alerted on, with raise / clear pairing. | [SNMP.md §8](docs/SNMP.md) |
| **MIB / OID tools** | Built-in metric registry with on / off switches, OID search, read-only OID test against a device, versioned custom OIDs with rollback, MIB import (parsed as text, never executed), support matrix of what devices actually answered | [SNMP.md §6](docs/SNMP.md) |
| **Wireless and RF** | Catalyst 9800: APs, radios, clients, WLANs, roaming, troubleshooting; frequency engine, channel utilisation heatmap, noise / interference, DFS radar, RRM neighbours, RF findings | [WIRELESS.md](docs/WIRELESS.md) |
| **ISP / WAN** | Circuits, ICMP probing state machine, SD-WAN health, outages, ISP incidents with root cause, availability and incident analytics, maintenance | [WAN.md](docs/WAN.md) |
| **Firewalls** | FortiGate health (CPU, memory, sessions, reboots, log-feed gaps), VPN tunnels, BGP peers / flaps / prefix anomalies / route leaks | [OPERATIONS.md](docs/OPERATIONS.md) |
| **Service checks** | TCP, HTTP(S) (status codes, expected text), DNS lookups and TLS certificate expiry, with latency history | [NMS.md](docs/NMS.md) |
| **Network analytics** | Explainable device health scores, availability and SLA (device / site / service), capacity forecasting (days until a threshold is reached), PoE headroom, top-N and 95th percentile, inventory and lifecycle (firmware drift, unused ports, long uptime), alert analytics | [NMS.md](docs/NMS.md) |
| **Operations** | Maintenance windows (one-off or weekly, time zone aware); device dependencies (no alert storm behind a down parent) | [NMS.md](docs/NMS.md) |
| **Network alerts** | 73 built-in rules (switches, wireless, WAN, BGP, firewall health, VPN, TACACS+, service checks, traps, vendor conditions), with persistence thresholds, hysteresis, auto-resolve and recovery notifications | [SNMP.md §9](docs/SNMP.md) |
| **TACACS+ AAA** | tac_plus-ng: servers, device clients, identities, roles and command authorization, accounting, approval-gated deployment | [TACACS.md](docs/TACACS.md) |
| **Policy and configuration** | Policy usage analytics, shadow / redundant policy detection, configuration drift, hardening plans (CLI generation), Infrastructure as Code | [IAC.md](docs/IAC.md), see [below](#policy-analytics-and-shadow-policy-detection) |

**How the SNMP engine works:**
- **Scheduling:**
  - One request in flight per device.
  - A global concurrency limit.
  - Per-group intervals (system and interfaces every poll; environment, PoE, STP and others every 5 min; VLANs and MAC tables every 15 min; inventory hourly).
  - Leases prevent the same device being polled twice.
- **Failing devices:**
  - Adaptive backoff: normal cadence for the first 2 failures, then doubling up to 15 min.
  - Availability is never overstated while a device is backing off.
  - Wireless controllers are polled in the background on their own time budget.
- **Device identification:**
  - A fingerprint registry identifies vendor and product line from sysObjectID first, then sysDescr.
  - Each result carries a confidence level, and administrators can override it.
- **Missing data:** a metric a device does not report is *unsupported* or null, never 0.

---

## Architecture

```
                 FortiGate / Palo Alto syslog            SNMP traps (UDP 162)        Browsers (HTTPS 443)
                          │ 514 udp/tcp                         │                             │
                ┌─────────▼─────────┐                   ┌───────▼───────┐             ┌───────▼───────┐
                │ ingress (rsyslog) │  disk spool,       │ traps          │             │ web (nginx)   │
                │ owns port 514     │  survives deploys  │ (pysnmp)       │             │ SPA + /api    │
                └─────────┬─────────┘                   └───────┬───────┘             └───────┬───────┘
                          │ relay                               │                             │
                ┌─────────▼─────────┐                           │                     ┌───────▼───────┐
                │ syslog            │ parse → normalise →        │                     │ api (FastAPI, │
                │ receiver+parsers  │ enrich (TI, geo, assets)   │                     │ 2 workers)    │
                └─────────┬─────────┘ batch insert, backpressure,│                     └───────┬───────┘
                          │           dead-letter spool          │                             │
                          ▼                                      ▼                             ▼
                ┌───────────────────────────────────────────────────────────────────────────────────────┐
                │ ClickHouse: events, minute / hourly roll-ups, switch / interface metrics, ICMP, BGP,  │
                │ wireless / RF telemetry, service results, traps, policy counters (TTL retention)      │
                │ PostgreSQL: users, devices, credentials (encrypted), rules, alerts, incidents, cases, │
                │ config, IaC, TACACS+, audit log                                                       │
                └───────────────────────────────────────────────────────────────────────────────────────┘
                          ▲
                ┌─────────┴─────────┐   FortiGate REST polling (GET), policy sync, SNMP polling, discovery,
                │ worker            │   ICMP probes, service checks, alert evaluation, correlation,
                │ (asyncio loops)   │   notifications, retention, TI feeds, reports, IaC jobs, TACACS+ jobs
                └───────────────────┘
```

| Service | Role | Published ports |
|---|---|---|
| `postgres` | Relational store | none |
| `clickhouse` | Time-series and event store | none |
| `migrate` | Runs Alembic + ClickHouse migrations, then exits; every other service waits for it | none |
| `api` | FastAPI (uvicorn, 2 workers) | none (behind `web`) |
| `web` | nginx: TLS, the React build, `/api` reverse proxy | `WEB_BIND_IP`:443, :80 |
| `worker` | All background loops (sharding supported with `WORKER_SHARD` / `WORKER_SHARDS`) | none |
| `ingress` | rsyslog relay that owns port 514 and spools to disk while `syslog` restarts | `SYSLOG_BIND_IP`:514 udp/tcp |
| `syslog` | Receiver plus parser processes (`SYSLOG_WORKERS`), batch inserts, dead-letter spool | none |
| `traps` | SNMP trap / inform receiver | `TRAP_BIND_IP`:162/udp |
| `tacacs` | tac_plus-ng plus deploy agent. **Opt-in:** `COMPOSE_PROFILES=tacacs` | `TACACS_BIND`:49/tcp |

All application containers run as an unprivileged user (uid 10001) with `no-new-privileges`, resource limits,
health checks and size-capped JSON logs. Bind addresses default to `127.0.0.1`, so nothing is exposed until you set
them. Every component is described in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and
[docs/PROJECT_ARCHITECTURE_AUDIT.md](docs/PROJECT_ARCHITECTURE_AUDIT.md).

---

## Quick start (Docker)

**Requirements:** Docker Engine 24+ with the Compose plugin, 4+ vCPU, 16 GB RAM, SSD storage (more for a large estate).

```bash
cp .env.example .env
./scripts/gen-secrets.sh                                  # random DB passwords, SECRET_KEY, TOKEN_ENCRYPTION_KEY, admin password
./scripts/gen-selfsigned-cert.sh sentinel.example.internal # temporary certificate; replace it with one from your internal CA
docker compose up -d --build
docker compose ps                                         # every service healthy; 'migrate' exits 0
```

Open `https://<server>/` and sign in as `admin` with the password printed by `gen-secrets.sh`. Then:

1. **Settings → Preferences:** set your time zone and change the password. Remove `BOOTSTRAP_ADMIN_PASSWORD` from `.env`.
2. **Settings → Users:** create accounts, assign **Grid** and / or **NMS**, and optionally limit NMS analysts to sites.
3. Choose your product: **Sentinel Grid** for firewall logs and security, **Sentinel NMS** for network monitoring.

**Expose the listeners deliberately.** Set these in `.env`:
- `WEB_BIND_IP`: the web UI (the management interface address).
- `SYSLOG_BIND_IP`: the log interface.
- `TRAP_BIND_IP`: SNMP traps.

They all default to loopback.

**Demo mode.** Set `DEMO_MODE=true` to try the platform without devices. The worker generates synthetic, clearly flagged FortiGate events (`source=demo`, with a banner in the UI). Never use demo mode in production.

---

## Connecting data sources

### FortiGate (Grid and NMS)

**1. Read-only REST API administrator**

```
config system accprofile
    edit "siem-readonly"
        set secfabgrp read
        set ftviewgrp read
        set authgrp read
        set sysgrp read
        set netgrp read
        set loggrp read
        set fwgrp read
        set vpngrp read
        set utmgrp read
    next
end
config system api-user
    edit "siem-api"
        set accprofile "siem-readonly"
        set vdom "root"
        config trusthost
            edit 1
                set ipv4-trusthost <SENTINEL_IP> 255.255.255.255
            next
        end
    next
end
execute api-user generate-key siem-api
```

Register the firewall under **Firewalls → Register firewall**: name, management IP, port, site and token, then **Test connection**. Tokens are encrypted at rest and never returned by the API.

The FortiGate's TLS certificate must verify. Install a certificate from your CA on the FortiGate, or mount the CA in `deploy/certs/fortigate-ca/`. If you run multiple VDOMs, register each VDOM as its own firewall entry.

Bulk registration: tokens come from environment variables named in the file, never from the file itself ([deploy/firewalls.example.json](deploy/firewalls.example.json)).

```bash
export FGT_TOKEN_HQ_FW01='<token>'
docker compose run --rm -e FGT_TOKEN_HQ_FW01 -v "$PWD/deploy/firewalls.example.json:/tmp/fw.json:ro" api python -m app.register /tmp/fw.json --test
```

**2. Syslog forwarding** (the primary path; FortiGate's REST API does not stream logs)

```
config log syslogd setting
    set status enable
    set server "<SENTINEL_IP>"
    set mode reliable          # TCP (RFC 6587); 'udp' also works
    set port 514
    set format default
    set source-ip <FORTIGATE_MGMT_IP>
end
config log syslogd filter
    set severity information
    set forward-traffic enable
    set local-traffic disable
    set anomaly enable
end
```

**What to enable on the FortiGate:**
- **Traffic:** `logtraffic all` on the policies you want logged.
- **DNS:** a DNS-filter profile with `log-all-domain enable`.
- **URLs:** a web-filter profile with `log-all-url enable`.

**How logs are matched to a firewall:** by serial (learned at Test Connection), then hostname, then the configured syslog source IPs. Unregistered senders are dropped and counted. Field coverage per FortiOS version is in [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

### Palo Alto Networks (Grid)

Use a read-only PAN-OS XML API key: only `show` operational commands and configuration `get` are sent. Forward
syslog in the default format to the same listener.

### Switches, routers, firewalls and controllers over SNMP (NMS)

1. **NMS → Switch & Device Monitoring → Administration:**
   - Add the **authorised management networks**; devices can only be added or discovered inside them.
   - Create **SNMP credential profiles**: SNMPv3 recommended (authPriv, SHA-2 / AES). SNMPv2c is refused unless `SWITCH_ALLOW_SNMPV2C=true`.
2. Add devices one by one, import a CSV or run a **discovery** sweep. For a Cisco Catalyst 9800, set role `wlc` so its wireless groups are collected.
3. Check **NMS → SNMP Monitoring → Vendor & Device Overview** for the identified vendor, product line and confidence. Override them per device if needed.
4. **For traps:**
   - Set `TRAP_BIND_IP` and allow UDP 162 from the device subnets.
   - Point each device's trap host at Sentinel, using the **same credential profile** it is polled with.

   Examples: Cisco `snmp-server host <ip> version 3 priv <user>`, Junos `set snmp v3 target-address …`, FortiGate `config system snmp user` → `set notify-hosts`.

Per-device Cisco / Ruckus switch prerequisites are in [docs/SWITCHES.md](docs/SWITCHES.md) (for example, SNMPv3 VLAN contexts for PVST and per-VLAN MAC tables). Wireless controller setup is in [docs/WIRELESS.md](docs/WIRELESS.md).

### ISP / WAN, service checks, TACACS+

- **ISP / WAN:** register circuits and ICMP targets under NMS → ISP / WAN ([docs/WAN.md](docs/WAN.md)).
- **Service checks:** NMS → Service Checks, administrators only. Checks only probe targets an administrator entered.
- **TACACS+:** start with `COMPOSE_PROFILES=tacacs docker compose up -d`, then follow [docs/TACACS.md](docs/TACACS.md).

### Optional enrichment

- **GeoIP / ASN:** put `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` (or the DB-IP Lite equivalents) in `deploy/geoip/`, then restart `syslog` and `worker`.
- **Threat-intel feeds:** allow outbound HTTPS from the host to:
  - `feodotracker.abuse.ch`
  - `www.spamhaus.org`
  - `hole.cert.pl`
  - `raw.githubusercontent.com`

  Feed licences: check each provider's terms.

### Policy analytics and shadow-policy detection

**Policy Analytics** answers three questions: which firewall policies are used, which appear unused, and which may be shadowed. It is read-only: the worker collects every `POLICY_SYNC_INTERVAL_SECONDS` (default 900) per firewall / VDOM, using GET requests only.

| Data | Source | Shown as |
|---|---|---|
| Policy configuration and order | `GET /api/v2/cmdb/firewall/policy` (evaluation sequence) | Configured |
| Address / service / zone objects | `cmdb/firewall/address`, `addrgrp`, `address6`, `addrgrp6`, `firewall.service/custom`, `firewall.service/group`, `system/zone` | Used to expand policies |
| Hit counters, bytes, first / last used | `GET /api/v2/monitor/firewall/policy`, snapshotted into ClickHouse `policy_counters`; usage = deltas between snapshots (resets and policy-ID reuse handled) | **Firewall hits** |
| Log matches | Ingested traffic logs whose `policyid` (+ `poluuid`) match | **SIEM matches** |

Firewall hits and SIEM matches describe the same traffic, so they are never added together. A value a source does not provide is shown as "Not available", never 0.

**Usage states:**
- In use.
- No observed hits.
- Potentially unused: no hits over at least 30 days of adequate coverage.
- Unknown: not enough telemetry to judge.
- Disabled.
- Not assessable.

Every state shows its method, confidence and reasons.

**Shadow analysis** compares enabled policies in sequence order, using exact IPv4 / IPv6 and port interval sets.
- **Full shadow / redundant:** reported only when coverage is proven in every dimension.
- **Overlap (unverified):** FQDN, dynamic, geography, ISDB, user-identity and negated objects downgrade a finding to this, with the assumptions listed.
- **Partial shadow:** an earlier deny blocks part of a later allow.

**The platform never reorders, disables or deletes policies.**

API: `/api/v1/policies` (inventory with server-side pagination), `/summary`, `/shadow`, `/{firewall}/{vdom}/{id}`, `/scopes`, and `POST /sync/{firewall}` (admin, read-only collection). The access profile needs `fwgrp read` and `netgrp read`; both are already in the profile above.

### Firewall hardening plans (CLI generation)

**Hardening** builds FortiOS objects from what was actually observed, then produces a reviewed CLI script. The platform never applies the script itself.

1. **Choose a time range** (and optionally a source subnet). The suggestions list destination ports (allowed / denied counts and the logged service name) and web domains.
2. **Group ports into a service group** (well-known ports map to predefined FortiOS services). **Add domains to a URL filter table** as allow or block.
3. **Add addresses / address groups and policies.**
4. **Check against firewall** (admin): read-only GETs report the objects the script would modify and any referenced objects that are missing.
5. **Generate CLI:** an apply script and a reverse-order rollback script. Back up first, apply during a change window, then move the new policies above broader rules.

Plans are validated server-side, and quotes and control characters are rejected so the CLI cannot be injected. Every create, update, export and check is audited.

---

## Configuration reference

All settings live in `.env`; [.env.example](.env.example) documents each one. The most important:

| Setting | Default | Purpose |
|---|---|---|
| `SECRET_KEY`, `TOKEN_ENCRYPTION_KEY` | generated | Session signing; encryption of API tokens and SNMP secrets. **Keep `TOKEN_ENCRYPTION_KEY` stable**: changing it makes stored credentials unreadable. |
| `WEB_BIND_IP`, `SYSLOG_BIND_IP`, `TRAP_BIND_IP`, `TACACS_BIND` | `127.0.0.1` (TACACS `0.0.0.0`) | Where each listener is published |
| `COOKIE_SECURE`, `SESSION_TTL_MINUTES`, `LOGIN_RATE_LIMIT_PER_MINUTE` | secure | Session hardening |
| `OUTBOUND_ALLOWED_HOSTS` | | Extra destinations allowed for outbound requests (SSRF guard) |
| `SYSLOG_WORKERS`, `SYSLOG_BUFFER_MAX_EVENTS`, `INGEST_INSERT_MAX_ATTEMPTS` | CPUs−1 (max 4), see file | Parser processes, ingestion buffer cap (backpressure), insert retries before dead-lettering |
| `SWITCH_MAX_CONCURRENT_POLLS`, `SWITCH_POLL_TIMEOUT_SECONDS` | 16, 240 | SNMP polling concurrency and per-poll time budget |
| `SWITCH_ALLOW_SNMPV2C` | false | Allow SNMPv2c credential profiles |
| `DB_POOL_SIZE`, `DB_MAX_OVERFLOW`, `CLICKHOUSE_POOL_SIZE` | 4, 4, 4 | Connection pools per process. Keep the PostgreSQL total under `max_connections`; see [DEPLOYMENT_AND_ROLLBACK_GUIDE.md §3](docs/DEPLOYMENT_AND_ROLLBACK_GUIDE.md). |
| `ALERT_INTERVAL_SECONDS`, `RETENTION_INTERVAL_SECONDS`, `POLICY_SYNC_INTERVAL_SECONDS` | see file | Background job cadence |
| `WORKER_SHARD`, `WORKER_SHARDS` | 0, 1 | Split firewall polling across worker containers |
| `INTERNAL_CIDRS`, `GEOIP_DIR` | | Internal address space; GeoIP databases |
| `IAC_DEVICE_WRITES` | false | Enables device writes for the IaC module (also needs enabling in IaC settings) |
| `ANTHROPIC_API_KEY`, `AI_MODEL`, `AI_ALLOW_DATA_SHARING` | unset / false | Optional AI assistant |
| `DEMO_MODE`, `DEMO_BACKFILL_HOURS` | false | Synthetic demo data |

**Retention defaults:**

| Data | Kept for |
|---|---|
| traffic, DNS | 30 days |
| web | 90 days |
| security, system | 365 days |
| switch metrics | 90 days raw / 400 days hourly |
| interface samples | 35 days raw / 400 days hourly |
| SNMP traps | 180 days |
| service-check results | 400 days |

Event retention is editable in Settings → Retention, and every deletion is logged.

---

## Security model

- **Authentication:**
  - Local accounts with Argon2 password hashes, login rate limiting and lockout.
  - Signed session cookies (HttpOnly, Secure, SameSite) plus a CSRF token on every state-changing request.
  - Session versioning ends open sessions on password, role or status changes.
- **Authorization:**
  - Roles: admin / analyst.
  - Product access: Grid / NMS, enforced for every API prefix (a test fails if a route is unclassified).
  - **NMS site scope** per user; out-of-scope devices return 404.
  - IaC roles: editor / approver / deployer / admin, with separation of duties.
  - TACACS+ roles.
- **Secrets:**
  - Firewall tokens and SNMP keys are encrypted at rest.
  - They are never returned by the API or written to logs, and errors never include communities or keys.
- **Network safety:**
  - Outbound requests go through an SSRF guard (`netguard.py`).
  - SNMP devices can only be added inside authorised networks.
  - Traps are accepted only from inventory devices using their own credentials.
- **Input safety:**
  - Strict Pydantic validation.
  - Parameterised ClickHouse and SQL queries.
  - Query-language and CLI generation are injection-checked.
  - CSV exports are protected against formula injection.
  - Uploaded MIB files are parsed as text and never executed.
- **Audit:** every configuration change, OID test, deployment and access denial is written to the audit log; IaC has its own hash-chained audit.

Checklists and reviews: [SECURITY.md](docs/SECURITY.md), [SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md),
[SECURITY_AUDIT_REPORT.md](docs/SECURITY_AUDIT_REPORT.md).

---

## Observability and health

| Endpoint / signal | What it gives |
|---|---|
| `GET /api/health` | Liveness: the API process is up (`{"status":"ok"}`) |
| `GET /api/ready` | Readiness: PostgreSQL and ClickHouse reachable. Returns 503 with `degraded` when not. |
| `GET /api/metrics` | Per-process request counts, latency, errors and DB pool usage, in Prometheus text format. **Administrators only.** |
| `X-Request-ID` | Accepted when valid or generated, returned on every response, and added to every log line |
| Structured logs | JSON lines with an access log keyed by route template (health checks excluded) |
| Container health checks | api, web and the databases are probed directly; worker, syslog and traps write heartbeat files |
| Ingestion counters | `syslog counters` log lines: received, parsed, failed, `dead_lettered`, `insert_failures`, `dropped_buffer_full`, queue depth |
| In-app health | NMS → SNMP Monitoring → Polling Health (success rate, timeouts, backoff, unsupported metrics, traps); per-device Monitoring Health; WAN collector health; Log Sources ingestion health |

**Dead-letter spool.** Events that ClickHouse rejects go to the `deadletter` volume instead of being lost. List and replay them with:

```bash
docker compose exec -T syslog python -m app.ingest.deadletter list
```

```bash
docker compose exec -T syslog python -m app.ingest.deadletter replay
```

---

## Deployment, backup and rollback

`scripts/deploy.sh` syncs the tree to the server, builds images, checks the nginx configuration and runs
`docker compose up -d`. The `ingress` relay keeps receiving syslog during the restart. Run it without arguments for a
dry run (the file list); `--apply` deploys.

```bash
./scripts/deploy.sh
```

```bash
./scripts/deploy.sh --apply
```

**Deploy targets.** `DEPLOY_REMOTE` selects the target host. `SKIP_BACKUP=1` skips the pre-deploy backup.

**Migrations.** They run automatically in the `migrate` service before the API starts. PostgreSQL migrations are additive, and indexes are built `CONCURRENTLY`.

**Backup and restore:**

```bash
./scripts/backup.sh
```

```bash
./scripts/restore.sh <timestamp>
```

Add the named volumes to your backup scope: `pgdata`, `chdata`, `ingress_spool`, `deadletter`, `tacacs_*`.

**Rollback.** Code and migrations roll back independently; the steps are in
[docs/DEPLOYMENT_AND_ROLLBACK_GUIDE.md](docs/DEPLOYMENT_AND_ROLLBACK_GUIDE.md). The pre-modernization tree is kept on the
local branch `checkpoint/pre-modernization-20261102`.

Day-two operations (troubleshooting, scaling, conntrack fix for UDP syslog, known limitations) are covered in
[docs/OPERATIONS.md](docs/OPERATIONS.md).

---

## Local development

The backend runs as a single process with embedded ClickHouse (chdb) and SQLite. Use it for development only.

```bash
python3.12 -m venv .venv && .venv/bin/pip install -r backend/requirements-dev.txt
cd frontend && npm ci && cd ..
cd backend
export CLICKHOUSE_MODE=embedded CLICKHOUSE_EMBEDDED_PATH=./.dev/ch DATABASE_URL=sqlite+aiosqlite:///./.dev/dev.db
export SECRET_KEY=$(openssl rand -hex 32) TOKEN_ENCRYPTION_KEY=$(../.venv/bin/python -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())")
export BOOTSTRAP_ADMIN_PASSWORD='ChangeMe-Dev-123' COOKIE_SECURE=false ENVIRONMENT=development DEMO_MODE=true
mkdir -p .dev && ../.venv/bin/python -m app.devserver      # API :8000, syslog :5514, and every worker loop
```

In another terminal, run `npm --prefix frontend run dev` and open http://localhost:5173. Keep `TOKEN_ENCRYPTION_KEY`
stable across restarts once you register devices.

---

## Tests and CI

```bash
cd backend && ../.venv/bin/python -m pytest -q
```

Backend unit and integration tests run on embedded ClickHouse and SQLite.

```bash
cd frontend && npm run typecheck && npm test && npm run build
```

Frontend: type-check, then Vitest, then the production bundle.

**Live FortiGate test.** It only sends read-only GETs and runs only when credentials are set:

```bash
FGT_TEST_HOST=10.0.0.1 FGT_TEST_TOKEN=... FGT_TEST_CA_BUNDLE=/path/ca.pem ../.venv/bin/python -m pytest -m live -s
```

**What the tests cover.** Parsers and normalisers, the FortiGate client (mocked responses, pagination, retries, rate limiting), ingestion (dedupe, backpressure, dead-letter, TCP framing), alert rules and correlation, RBAC / CSRF / product access / site scope, and migrations. They also cover the SNMP client against a real local agent (v2c, v3 auth / priv, timeouts), counter maths, vendor adapters, traps over UDP (v1 / v2c / v3 inform), MIB parsing, NMS analytics, service checks, maintenance and dependencies, wireless and RF, IaC and TACACS+.

**Test data.** All device data in the tests are **labelled synthetic fixtures** (RFC 1918 / RFC 5737 addresses, fake serials) built from public MIB definitions and log formats. They are never presented as live monitoring.

**CI** ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs on every push and pull request; nothing is deployed from CI:
- **Backend:** ruff, pytest and pip-audit.
- **Frontend:** type-check, Vitest, the production build and `npm audit` on runtime dependencies.
- **Images:** `docker compose config` and image builds.

API latency harness: `backend/tools/bench_api.py` (results in [docs/PERFORMANCE_BENCHMARKS.md](docs/PERFORMANCE_BENCHMARKS.md)).

---

## Project layout

```
backend/app/
  main.py, observability.py, products.py   app factory, request IDs / metrics, product + site access
  api/              FastAPI routers: auth, admin, firewalls, analytics, alerts, soc, hunt, identity, isp, wan,
                    ops (fw health / VPN / BGP), switches, wireless, wireless_rf, nms, snmp, tacacs, iac, policies, hardening
  db/               PostgreSQL models + session pool, ClickHouse client pool + versioned migrations
  ingest/           syslog parser, normaliser, batching pipeline, dead-letter spool
  analytics/        filter builder, query language, ClickHouse aggregations
  alerts/           detection rules, custom rules, engine (dedupe, auto-resolve, maintenance), impossible travel
  enrich/           threat intelligence, GeoIP, asset enrichment
  fortigate/        read-only REST client, capability probing, polling
  policy/           policy collection, object expansion, usage and shadow analysis
  switches/         SNMP engine: client, fingerprints, collectors, vendor adapters, registry, poller, discovery, alerts
  wireless/         Catalyst 9800 collection, storage, RF engine and analytics, alerts
  nms/              analytics, service checks, maintenance windows, NMS alerts
  tacacs/           TACACS+ policy, rendering, jobs, accounting
  iac/              desired-state schema, diff, rules, adapters, executor
  hardening/        hardening plan model and CLI generation
  snmp_profiles.py  MIB parser, custom OIDs, metric switches, OID test
  snmp_traps.py     trap / inform receiver (service "traps")
  syslog_server.py  syslog receiver (service "syslog")
  worker.py         background loops (service "worker")
  devserver.py      single-process development server
  *.py              domain modules: incidents, notify, reports, retention, wan, icmp, bgp, vpnmon, fwhealth, identity,
                    automation, sigma, ai, compliance, drift, paloalto, assets, watchlists, searches, …
backend/migrations/  Alembic (PostgreSQL); ClickHouse migrations live in app/db/ch_schema.py
backend/tests/       pytest suites and labelled fixtures
backend/tools/       benchmark harness, wireless MIB registry generator
frontend/src/
  App.tsx            routes (lazy-loaded page chunks)
  components/        layout, sidebar, UI kit, charts (ECharts core build)
  lib/               API client, products / navigation, context, formatting, theme
  pages/             Grid pages; nms/, snmp/, switches/, wireless/, wan/, tacacs/, iac/ for NMS modules
deploy/              ingress relay, TACACS+ image, ClickHouse config, certificates, GeoIP, sample registry
scripts/             gen-secrets, self-signed cert, deploy, backup, restore, syslog conntrack fix
docs/                product, module, operations, security and engineering documentation
```

---

## Documentation index

| Area | Document |
|---|---|
| Products and access | [PRODUCTS.md](docs/PRODUCTS.md): Grid / NMS split, access model, module map, routing |
| Architecture | [ARCHITECTURE.md](docs/ARCHITECTURE.md): components, data flow, schema, retention |
| FortiOS coverage | [COMPATIBILITY.md](docs/COMPATIBILITY.md): FortiOS version matrix and the source of each event type |
| NMS core | [NMS.md](docs/NMS.md): analytics, service checks, maintenance, dependencies, LibreNMS / Zabbix comparison |
| SNMP framework | [SNMP.md](docs/SNMP.md): engine, fingerprints, adapters, MIB / OID registry, traps, support matrix, API |
| Switches | [SWITCHES.md](docs/SWITCHES.md): metrics, MIBs, onboarding, alerts |
| Wireless and RF | [WIRELESS.md](docs/WIRELESS.md): Catalyst 9800, OID registry, frequency tables, RF analytics |
| ISP / WAN | [WAN.md](docs/WAN.md): circuits, ICMP state machine, outages, incidents |
| TACACS+ | [TACACS.md](docs/TACACS.md): AAA servers, roles, accounting, deployment |
| Infrastructure as Code | [IAC.md](docs/IAC.md) and [docs/iac-examples/](docs/iac-examples) |
| Operations | [OPERATIONS.md](docs/OPERATIONS.md): troubleshooting, backup / restore, scaling, known limitations |
| Deployment | [DEPLOYMENT_AND_ROLLBACK_GUIDE.md](docs/DEPLOYMENT_AND_ROLLBACK_GUIDE.md) |
| Security | [SECURITY.md](docs/SECURITY.md), [SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md), [SECURITY_AUDIT_REPORT.md](docs/SECURITY_AUDIT_REPORT.md) |
| Engineering reports | [PROJECT_ARCHITECTURE_AUDIT.md](docs/PROJECT_ARCHITECTURE_AUDIT.md), [CODE_QUALITY_REPORT.md](docs/CODE_QUALITY_REPORT.md), [FRONTEND_PERFORMANCE_REPORT.md](docs/FRONTEND_PERFORMANCE_REPORT.md), [API_PERFORMANCE_REPORT.md](docs/API_PERFORMANCE_REPORT.md), [DATABASE_PERFORMANCE_REPORT.md](docs/DATABASE_PERFORMANCE_REPORT.md), [PERFORMANCE_BENCHMARKS.md](docs/PERFORMANCE_BENCHMARKS.md), [TECHNICAL_DEBT_REGISTER.md](docs/TECHNICAL_DEBT_REGISTER.md), [IMPLEMENTATION_CHANGELOG.md](docs/IMPLEMENTATION_CHANGELOG.md), [UI_AUDIT.md](docs/UI_AUDIT.md) |

---

## Verification status and known limits

**Automated tests.** On 2026-11-02, backend: 434 passed, 1 skipped (the live FortiGate test). Frontend: type-check clean, 39 tests passed, production build OK. CI runs the same checks.

**Production deployment.** Deployed with Docker Compose to the production server. After deployment, migrations 0027 and ClickHouse 15 were applied, every service reported healthy, and switches and the Catalyst 9800 are being polled.

**Validated against real devices:** FortiGate syslog and REST, Cisco Catalyst switches, Ruckus ICX switches and the Cisco Catalyst 9800 controller.

**Fortinet and Juniper SNMP adapters.** These are implemented from the public MIBs and tested against labelled fixtures only. They show as *implemented* (not *observed*) in NMS → SNMP Monitoring → Support Matrix until a real device of that product line answers.

**Not implemented:**
- Catalyst 9800 RESTCONF.
- Ruckus SmartZone / standalone AP wireless data (needs the SmartZone API).
- Juniper Virtual Chassis, SRX IPsec status and NETCONF.
- SNMPv1 polling (v1 traps are accepted).
- Site scope on the topology, NMS analytics and wireless pages.

The full list of known limitations is in [OPERATIONS.md](docs/OPERATIONS.md) and [TECHNICAL_DEBT_REGISTER.md](docs/TECHNICAL_DEBT_REGISTER.md).

**Not measured:** Lighthouse scores and a production-scale load test have not been run. See [PERFORMANCE_BENCHMARKS.md](docs/PERFORMANCE_BENCHMARKS.md) for what was measured and under which conditions.
