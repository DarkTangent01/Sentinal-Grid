# Sentinel NMS — architecture

## 1. Components

```
Browser (React, xterm.js)
   │  HTTPS / WSS  (session cookie + CSRF header; WebSocket: cookie + Origin + one-time ticket)
   ▼
web (nginx) ── /api/nms/access/*  ──────────────►  access   (Device Access Gateway, uvicorn, 1 process)
   │                                                 │  RBAC (nms.* permissions) → access policy → session manager
   │                                                 │  credential vault (Fernet, TokenCipher) → validate_address
   │                                                 ▼
   │                                              management network → devices (SSH 22, TCP probes 22/443/830)
   └─ /api/*  ──► api (FastAPI, 2 workers): inventory, monitoring, analytics, alerts, reports, config history
                   │
        postgres (inventory, state, audit) · clickhouse (time series, events, flows)
                   ▲
   worker / poller (SNMP polling, discovery, wireless, WAN, alert engine, backups) · traps · flows · syslog
```

| Service | Role | Talks to devices? |
|---|---|---|
| `api` | All REST APIs except device access | No. Only connection tests and the existing integrations: FortiGate REST, PAN-OS, SNMP test. |
| `access` (new) | Terminal WebSocket, connectivity tests, diagnostics, bulk diagnostics, approved configuration changes, the access audit | Yes: SSH and TCP probes to inventory devices only |
| `worker` | Periodic jobs: alerts, backups, discovery, rollups, retention | Yes: SNMP, SSH backup |
| `poller` | Per-device SNMP polling (replicas) | Yes: SNMP |
| `traps`, `flows`, `syslog` / `ingress` | Passive receivers | Receive only |

The browser never connects to a device. Every interactive or command connection starts in `access`.

## 2. Monitoring engine (existing, vendor-independent)

- **Scheduling:**
  - `switches/poller.py` claims due devices with a lease, so replicas never poll the same device;
  - per-group intervals, with exponential backoff for failing devices (`backoff_until`);
  - wireless controllers' large tables run as a separate job with their own lease.
- **Collectors:** `switches/collect.py COLLECTORS` are vendor-neutral and ask the adapter (`switches/adapters.py`)
  for vendor OIDs. Unknown vendors get the standard-MIB baseline (`generic`).
- **Rates:** `switches/rates.py` handles 64-bit counters, wraps, resets, reboots and ifIndex renumbering, refusing
  implausible deltas rather than producing spikes.
- **Storage:**
  - PostgreSQL holds current state (switch, interface, VLAN, MAC, neighbour, wireless rows);
  - ClickHouse holds time series with hourly / daily rollups and TTLs (`db/ch_schema.py`).
- **Alerts:** the shared engine (`alerts/engine.py`) evaluates NMS rules (`switch_`, `wireless_`, `wan_`, `bgp_`,
  `nms_` …). Root-cause suppression uses `Switch.parent_id`, and maintenance windows come from `nms/maintenance.py`.
  NMS faults never become SIEM incidents (`products.alert_product`).

## 3. Device Access Gateway (new)

Code: `backend/app/access/`, served by the `access` service (`python -m app.access`). In development and tests, the
same router is mounted in the main app (`ACCESS_GATEWAY_INPROCESS=true`).

| Module | Responsibility |
|---|---|
| `rbac.py` | Seven NMS roles, 13 `nms.*` permissions, `require(perm)` dependency, site scope |
| `vault.py` | Credential kinds, encryption (TokenCipher), resolution order (device override → most specific group assignment), rotation metadata; never returns secrets |
| `commands.py` | Vendor command library (diagnostic templates), `classify()` → `READ_ONLY`…`DESTRUCTIVE`, terminal `LineGuard` |
| `gateway.py` | Target resolution by device id only, `validate_address` allowlist, fixed protocol ports, session caps, SSH connect with pinned host keys, TCP probes, prompt-driven shell helper |
| `terminal.py` | WebSocket ⇄ SSH PTY bridge: ticket check, resize, idle / maximum timeouts, termination polling, command metadata, optional recording |
| `diagnostics.py` | Run templates on one device; bulk jobs with a semaphore, per-device timeout, progress, cancel |
| `changes.py` | Change requests: validate → classify → backup → preview / dry run → approve → execute → verify → audit → rollback |
| `audit.py` | Append-only, hash-chained access audit (`nms_access_audit`) with verification |

Every SSH connection goes through the same five checks:

1. **Device:** the device must exist in inventory and be inside the user's site scope.
2. **Address:** `validate_address(device.address, authorised networks)` must pass: an IP literal, no loopback or
   reserved address, inside an authorised network.
3. **Port:** the port comes from a fixed map (`ssh` 22, `https` 443, `netconf` 830) and is never taken from the
   request.
4. **Host key:** the stored key must match (trust on first use); a changed key refuses the connection before any
   password is sent.
5. **Session caps:** global, per user and per device.

## 4. Data model additions (PostgreSQL migration 0035, additive)

| Table / column | Purpose |
|---|---|
| `users.nms_roles` (JSON) | NMS roles of an account |
| `device_ssh_credentials.kind`, `.rotated_at`, `.owner` | Credential kind (`ssh`, `https`, `api_token`, `netconf`) and rotation metadata (the table is reused, not duplicated) |
| `nms_credential_assignments` | Group assignment of a credential: kind + site / role / vendor match |
| `nms_access_sessions` | One row per terminal session: user, device, protocol, source IP, start / end, result, termination reason, byte counts, ticket hash |
| `nms_access_commands` | Commands seen in sessions and diagnostics: masked text, risk, allowed / blocked |
| `nms_access_recordings` | Optional masked output transcript (recording mode `full`) |
| `nms_diag_jobs`, `nms_diag_results` | Single and bulk diagnostic runs and per-device / per-command output |
| `nms_change_requests` | Change workflow state, risk, lines, rollback lines, approvals, backups, result |
| `nms_access_audit` | Hash-chained audit of every access event |

## 5. Security model

- **Authentication:**
  - REST: session cookie plus CSRF header (existing `current_user`);
  - WebSocket: the session cookie, an allowed `Origin` (`ACCESS_ALLOWED_ORIGINS`, defaults to the request host),
    then a one-time ticket in the first message. The ticket is single use, bound to user + device + session, and
    expires after 30 s. Its SHA-256 is stored.
- **Authorisation:** `nms.*` permissions are checked on each route and when the WebSocket opens. Site scope applies.
  Changing a user's roles bumps `session_version`, which revokes the user's existing sessions, including open
  terminals at their next check.
- **Command control:**
  - diagnostics accept template ids only;
  - the terminal guard blocks every command above `LOW_RISK` unless the session is bound to an approved change
    request;
  - `DESTRUCTIVE` is always blocked in the terminal.
- **Secrets:** no API returns a secret. Commands typed after a password prompt are neither logged nor classified,
  and logged command text and recordings are masked with the backup masker.
- **Isolation:** `access` runs as a non-root user with a read-only root filesystem, `cap_drop ALL`, and its own
  memory, CPU and PID limits.

## 6. Scale design

- **Polling:** the existing lease and replica model with backoff. Measured figures are in
  [PERFORMANCE_BENCHMARKS.md](PERFORMANCE_BENCHMARKS.md).
- **Access:** session caps (default 50 global, 5 per user, 3 per device), a bulk semaphore (default 10) and per-device
  timeouts. Cancellation is checked between devices and enforced by task cancellation in the gateway process.
