# FortiGate SIEM

Centralized security analytics for multiple FortiGate firewalls: traffic, DNS, URL-filtering, UTM and system events,
with dashboards, top-N analytics, an event explorer, IP investigations and an alerting engine.

**Stack:** Python 3.12 · FastAPI · SQLAlchemy/Alembic · PostgreSQL 16 · ClickHouse 24.8 · React 18 + TypeScript + Vite + Tailwind + ECharts · nginx · Docker Compose.

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, data flow, normalized schema, retention model, phased plan |
| [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) | FortiOS compatibility matrix; which source supplies each event type |
| [docs/SECURITY.md](docs/SECURITY.md) | Security hardening checklist |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Troubleshooting, backup/restore, scaling, **known limitations** |

> **Verification status.** 57 automated tests pass (parsing, normalization, API client with mocked FortiGate responses,
> pagination, retries, rate limiting, dedupe, persistence and aggregation accuracy on embedded ClickHouse, alert rules,
> RBAC/CSRF, retention). The full app was run locally in single-process mode with demo data and syslog over UDP.
> **It has not been tested against a real FortiGate, and the Docker Compose stack was not started on the build machine.**

## How data is collected

* **Syslog (primary)** — traffic, DNS-filter, web-filter, IPS, AV, app-control and event logs arrive on 514/udp or tcp.
  FortiGate's REST API does not stream logs, so syslog is the reliable path.
* **REST API (GET only)** — identity and version, CPU, memory, sessions, interfaces, policy names, and Test Connection.
  An optional per-device *best-effort log pull* reads stored log pages.
* **Demo mode** — synthetic, sanitized FortiGate-format logs from three flagged demo firewalls (`source=demo`, with a banner
  in the UI). Never presented as live telemetry.

## Quick start (Docker, Linux server or VM)

Requirements: Docker Engine 24+ with the Compose plugin, 4+ vCPU, 16 GB RAM, SSD storage.

```bash
cp .env.example .env
./scripts/gen-secrets.sh                      # random DB passwords, SECRET_KEY, TOKEN_ENCRYPTION_KEY, admin password
./scripts/gen-selfsigned-cert.sh siem.example.internal   # temporary cert; replace with your internal CA's
docker compose up -d --build
docker compose ps                              # all services healthy; 'migrate' exits 0
```

Open `https://<server>/` and sign in as `admin` with the password printed by `gen-secrets.sh`, then:

1. **Settings → Preferences:** set your timezone and change the password. Remove `BOOTSTRAP_ADMIN_PASSWORD` from `.env`.
2. **Firewalls → Register firewall:** enter the name, management IP, port, site and API token, then **Test connection**.
3. Configure **syslog** on each FortiGate (below). Ingestion health appears per firewall within seconds.

To try it without firewalls, set `DEMO_MODE=true` in `.env` and run `docker compose up -d`. The worker backfills
`DEMO_BACKFILL_HOURS` of demo history, then streams live demo events. Set it back to `false` for production.

### Bulk registration
```bash
export FGT_TOKEN_HQ_FW01='<token>' FGT_TOKEN_WH_EAST_FW01='<token>'
docker compose run --rm -e FGT_TOKEN_HQ_FW01 -e FGT_TOKEN_WH_EAST_FW01 \
  -v "$PWD/deploy/firewalls.example.json:/tmp/fw.json:ro" api python -m app.register /tmp/fw.json --test
```
Tokens come from the environment variables named in the file, never from the file itself ([deploy/firewalls.example.json](deploy/firewalls.example.json)).

## FortiGate configuration

### 1. Read-only REST API administrator
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
                set ipv4-trusthost <SIEM_IP> 255.255.255.255
            next
        end
    next
end
execute api-user generate-key siem-api
```
Use the generated key as the API token. The SIEM only issues GET requests and validates the FortiGate's TLS
certificate. Install a certificate signed by your CA on the FortiGate, or mount the CA in `deploy/certs/fortigate-ca/`.

### 2. Syslog forwarding
```
config log syslogd setting
    set status enable
    set server "<SIEM_IP>"
    set mode reliable          # TCP (RFC 6587); 'udp' also supported
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
* Traffic: set `logtraffic all` on the policies you want logged (denies require logging on the deny policy or implicit deny).
* DNS queries: apply a DNS-filter profile with `set log-all-domain enable`.
* URLs: web-filter profile with `set log-all-url enable`. FortiGate often logs only hostname plus path; the SIEM shows exactly what was logged.

The receiver matches logs to a registered firewall by serial (`devid`, learned at Test Connection), then hostname,
then the sender IPs listed under *Syslog source IPs*. Unregistered senders are dropped and counted.

## Next-generation SIEM features

| Area | What it does | Where |
|---|---|---|
| **Threat intelligence** | Matches every event at ingest against feeds (abuse.ch Feodo C2 IPs, Spamhaus DROP, CERT Polska domains, IPsum) plus a manual IOC list: destination/source IP, CIDR, DNS query and web hostname including parent domains. Retroactive **Hunt** over stored events. | Threat Intel |
| **Assets & identity** | Learns internal hosts from traffic (FortiGate device identification: hostname, MAC, OS; firewall user). Mark criticality: alerts touching a **critical** asset are raised one severity level. | Assets |
| **Behaviour (UEBA-lite)** | Periodic **beaconing**, outbound **volume vs the host's own 7-day baseline** (per-host hourly rollup), **new destination country**, **new external port** per host, **VPN brute force**, **impossible travel**. | Alerts |
| **MITRE ATT&CK** | Every detection is mapped to a tactic and techniques (linked to attack.mitre.org). | Alerts, Incidents, Settings |
| **Correlation → incidents** | Alerts about one entity (IP, VPN user or firewall) within 24 h form one incident; 2 tactics raise severity one level, 3+ make it critical. | Incidents |
| **Case management** | Assignee, acknowledge/resolve SLA timers (critical 15 min / 4 h, high 1 h / 24 h …), comments, evidence, timeline, closure reason; MTTA/MTTR; closure verdicts feed per-rule **false-positive rates**. | Incidents, Settings → Detection rules |
| **Notifications** | Slack, Microsoft Teams (Workflows), email (SMTP) and HMAC-signed webhooks; routing by event type and severity, quiet hours (critical still sent), de-duplication; persistent outbox with retries. | Notifications |
| **Query language & saved searches** | `src_ip:10.0.0.0/8 AND action:deny AND dst_port:445`, OR/NOT/`-`, parentheses, ranges, comparisons, wildcards, free text; saved, shared and scheduled searches with thresholds. | Event Explorer, Saved Searches |
| **Scheduled reports** | Daily/weekly HTML reports (summary, alerts, incidents/MTTR, threats, TI, VPN, policy hygiene, compliance) emailed via channels; printable to PDF. | Reports |
| **Geo & ASN** | Country map and tables from FortiGate country fields; optional GeoLite2/DB-IP database for ASN and coordinates. | Geography |
| **VPN & users** | SSL/IPsec logins, failures, active sessions, countries per user, impossible travel. | VPN & Users |
| **Compliance evidence** | CERT-In, ISO 27001:2022, PCI DSS 4.0 and NIST CSF 2.0 controls with status computed from live configuration; CSV export. Evidence support, not certification. | Compliance |
| **Configuration drift** | Read-only snapshots of interfaces, admins, global admin settings, SSL-VPN and policies; diffs and risky-change alerts (any/any accept, WAN management, telnet/http, admin without trusted hosts, new admin). | Config Drift |

**Optional GeoIP:** put `GeoLite2-City.mmdb` (or Country) and `GeoLite2-ASN.mmdb` — or DB-IP Lite equivalents — in
`deploy/geoip/` and restart `syslog`/`worker`. MaxMind requires a free account/licence key to download.

**Threat-intel egress:** the worker downloads feeds over HTTPS; allow outbound access from the SIEM host to
`feodotracker.abuse.ch`, `www.spamhaus.org`, `hole.cert.pl` and `raw.githubusercontent.com` (or disable feeds you
cannot reach). Feed licences: check each provider's terms for your use.

## Policy analytics and shadow-policy detection

**Policy Analytics** answers which firewall policies are used, which appear unused, and which may be shadowed. It is
read-only: the worker collects every `POLICY_SYNC_INTERVAL_SECONDS` (default 900) per firewall/VDOM using GET requests.

| Data | Source | Shown as |
|---|---|---|
| Policy configuration and order | `GET /api/v2/cmdb/firewall/policy` (results come back in evaluation sequence) | Configured |
| Address/service/zone objects | `cmdb/firewall/address`, `addrgrp`, `address6`, `addrgrp6`, `firewall.service/custom`, `firewall.service/group`, `system/zone` | Used to expand policies |
| Hit counters, bytes, packets, first/last used | `GET /api/v2/monitor/firewall/policy`, snapshotted into ClickHouse `policy_counters`; usage = deltas between snapshots (resets and policy-ID reuse handled) | **Firewall hits** |
| Log matches | Ingested traffic logs whose `policyid` (+ `poluuid` when logged) match | **SIEM matches** |

Firewall hits and SIEM matches describe the same traffic and are never added together. Values a source does not
provide are shown as "Not available", never 0.

**Usage states:** In use · No observed hits · Potentially unused (no hits over ≥ 30 days of adequate counter or
`logtraffic all` coverage) · Unknown (insufficient telemetry) · Disabled · Not assessable. Every state shows its
method, confidence and reasons. Observation windows: 7, 30, 60 and 90 days.

**Shadow analysis** compares enabled policies in sequence order using exact IPv4/IPv6 and port interval sets, with
groups, exclusions and zones expanded. *Full shadow* and *redundant* are reported only when coverage is proven in every
dimension (interfaces, source, destination, service, schedule). FQDN, dynamic, geography and ISDB objects, user
identity, negation, custom schedules and missing objects downgrade a finding to *overlap (unverified)*, with the
assumptions listed. *Partial shadow* is reported when an earlier deny blocks part of a later allow, or for
near-duplicates; an allow placed above a broader deny (the normal exception pattern) is not reported. Each finding has a
side-by-side comparison and manual verification steps. **The SIEM never reorders, disables or deletes policies.**

API: `/api/v1/policies` (inventory, filters, server-side pagination), `/summary`, `/shadow`, `/{firewall}/{vdom}/{id}`
(detail), `/scopes` (sync health), `POST /sync/{firewall}` (admin, read-only collection).
Required access profile: `fwgrp read` (policies, objects, policy statistics) and `netgrp read` (zones) — included in
the read-only profile above. Multi-VDOM: register each VDOM as its own firewall entry.

## Firewall hardening plans (CLI generation)

**Hardening** builds FortiOS objects from what the SIEM actually observed, then produces a reviewed CLI script.
**The SIEM never applies changes itself**: every request it sends to a FortiGate is a GET.

1. Pick a time range (and optionally a source subnet). The suggestions list destination ports (allowed and denied
   counts, the service name FortiGate logged) and web domains.
2. Tick ports and add them to a **service group**. Well-known ports map to predefined FortiOS services (HTTPS, DNS,
   NTP…); others become custom services such as `TCP-8443`. Tick domains and add them to a **URL filter table** as
   allow or block, with an optional "block everything else" entry and web-filter profile.
3. Add **addresses / address groups** and **policies** (interfaces, source, services, web-filter profile, NAT, logging).
4. **Check against firewall** (admin): read-only GETs report objects the script would *modify* and referenced
   objects/interfaces that are *missing*.
5. **Generate CLI**: copy or download the apply script and the reverse-order rollback script. Back up the
   configuration, apply during a change window, then move new policies above broader rules (they are created at the end).

Plans are validated server-side (ports 1–65535, IPv4 subnets, FortiOS name rules, duplicate names, and quotes or
control characters are rejected so the CLI cannot be injected). Create, update, export and check actions are written
to the audit log. Analysts can view and export plans; admins create, edit and check them.

## Local development (no Docker)

The backend can run as a single process with embedded ClickHouse (chdb) and SQLite. This is for development only.

```bash
python3.12 -m venv .venv && .venv/bin/pip install -r backend/requirements-dev.txt
cd frontend && npm ci && cd ..
cd backend
export CLICKHOUSE_MODE=embedded CLICKHOUSE_EMBEDDED_PATH=./.dev/ch DATABASE_URL=sqlite+aiosqlite:///./.dev/dev.db
export SECRET_KEY=$(openssl rand -hex 32) TOKEN_ENCRYPTION_KEY=$(../.venv/bin/python -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())")
export BOOTSTRAP_ADMIN_PASSWORD='ChangeMe-Dev-123' COOKIE_SECURE=false ENVIRONMENT=development DEMO_MODE=true
mkdir -p .dev && ../.venv/bin/python -m app.devserver      # API :8000, syslog :5514 (udp/tcp)
```
In another terminal run `npm --prefix frontend run dev` and open http://localhost:5173. Note that `TOKEN_ENCRYPTION_KEY` must stay the same across restarts if you register firewalls.

## Tests
```bash
cd backend && ../.venv/bin/python -m pytest -q          # unit + integration on embedded ClickHouse/SQLite
cd frontend && npm run build                             # type-check + production bundle
# Live FortiGate test (read-only GETs) — runs only when credentials are explicitly set:
FGT_TEST_HOST=10.0.0.1 FGT_TEST_TOKEN=... FGT_TEST_CA_BUNDLE=/path/ca.pem ../.venv/bin/python -m pytest -m live -s
```
Fixtures in `backend/tests/fixtures/` are sanitized **TEST DATA** (RFC 1918 and RFC 5737 addresses, fake serials).

## Project layout
```
backend/app/
  api/            FastAPI routers (auth, firewalls, analytics/events, alerts, admin)
  fortigate/      REST client (GET-only), capability probing, polling, log pull
  ingest/         syslog parser, normalizer, batching sink with dedupe
  analytics/      filter builder + ClickHouse aggregations
  alerts/         detection rules + engine
  db/             PostgreSQL models, ClickHouse client + migrations
  syslog_server.py worker.py migrate.py register.py demo.py devserver.py retention.py
backend/migrations/  Alembic
frontend/src/        React app (pages/, components/, lib/)
deploy/              ClickHouse config, certs, sample firewall registry
scripts/             gen-secrets, self-signed cert, backup, restore
```

## Retention defaults
traffic 30 d · DNS 30 d · web 90 d · security 365 d · system 365 d. Change these in Settings → Retention. Every deletion is logged.
