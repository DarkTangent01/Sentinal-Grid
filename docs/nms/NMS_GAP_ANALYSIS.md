# Sentinel NMS — gap analysis

Assessment date: 2026-11-20. Method: every claim below was checked by reading the code path
frontend page → API route → service → database model → device protocol, plus the existing tests. A page or menu item
existing was never taken as evidence that a feature works.

Status keys: `IMPLEMENTED`, `PARTIALLY_IMPLEMENTED`, `UI_ONLY`, `BACKEND_ONLY`, `NOT_IMPLEMENTED`, `BROKEN`,
`NEEDS_VALIDATION` (built and unit-tested, but not proven against real hardware of that kind).

The per-feature table is in [NMS_FEATURE_MATRIX.md](NMS_FEATURE_MATRIX.md). This document covers the findings, root
causes, priorities and acceptance criteria.

## 1. Summary

Sentinel NMS is not a skeleton. The monitoring side is mature for four vendor families (Cisco, Fortinet, Juniper,
Ruckus):

- SNMP v2c / v3 polling with a vendor-independent collector engine and per-vendor adapters;
- 64-bit counters with reset, wrap, reboot and renumbering handling;
- LLDP / CDP topology with impact analysis;
- wireless controller, AP, client and RF analytics with persisted history;
- WAN / ISP / SD-WAN / BGP / VPN monitoring;
- service checks, maintenance windows, anomaly baselines, capacity forecasts;
- flow collection, read-only configuration backup and PDF reports.

There was no device-access layer at all. This is the core feature the transformation brief marks mandatory. Before
this work:

- no SSH terminal (no xterm, no WebSocket endpoint anywhere in the backend);
- no diagnostic command execution beyond the three fixed backup commands;
- no bulk diagnostics;
- no access sessions, access audit or session termination;
- no NMS-specific roles or permissions (only `admin` / `analyst` plus product and site scope);
- no change workflow for switch / router configuration (the IaC module covers FortiGate / FortiManager only);
- credential storage covered SNMP profiles and one SSH backup login type, with no group assignment and no
  rotation tracking.

## 2. Confirmed root causes and architectural gaps

| # | Gap | Root cause (evidence) | Priority |
|---|---|---|---|
| G1 | No browser terminal or device access | The design was "read-only toward devices": `configs/backup.py` allows only `COMMANDS` (3 strings). No WebSocket route exists (`grep -r websocket backend/app` was empty), and the frontend has no terminal library (`frontend/package.json`). | P0 |
| G2 | No NMS permission model | `User.role` is `admin \| analyst` (`db/models.py:21`). NMS access is all-or-nothing per product (`products.py products_of`). Only IaC and TACACS+ have their own role lists. | P0 |
| G3 | No access audit / session record | `AuditLog` records API actions only. There is no session, command or termination record. | P0 |
| G4 | Credential vault partial | SNMP: `SwitchCredential`; SSH: `DeviceSshCredential` (Fernet via `TokenCipher`, never returned). Missing: credential kinds for HTTPS / API token / NETCONF, site / role / vendor group assignment, rotation date, and "who may use" control. | P0 |
| G5 | No controlled change path for switches / routers | No model or code. IaC executor targets FortiGate / FortiManager only (`iac/adapters.py`). | P1 |
| G6 | No bulk diagnostics | No job model. The only multi-device SSH loop is backup `run_due` (bounded semaphore, no cancel or progress). | P1 |
| G7 | Additional vendors monitored only generically | `switches/fingerprints.py VENDORS = (cisco, fortinet, juniper, ruckus, generic)`. Aruba, HPE, Arista, Huawei, MikroTik, Dell and Extreme fall back to standard MIBs (`generic`). This is correct as baseline monitoring, but there is no vendor identification or vendor health OIDs for them. | P2 |
| G8 | SNMPv1 not supported | `switch_credentials.version` is `v3 \| v2c`; there is no v1 code path. v1 has no 64-bit counters. | P3 (by design; documented) |
| G9 | Discovery is SNMP-only | `switches/discovery.py`: one SNMP GET per address in an authorised network. No ICMP or TCP liveness sweep, so devices without SNMP are invisible. ARP-table discovery is not built (no `ipNetToMedia` walk). | P2 |
| G10 | NETCONF / RESTCONF / gNMI | Mentioned only as labels in the SNMP support-matrix API (`api/snmp.py`). No client. | P2 |
| G11 | Ruckus SmartZone / vSZ / Ruckus One, Mist, FortiManager-for-switches, Aruba controllers | No REST clients. SmartZone is fingerprinted only (`fingerprints.py`). Ruckus wireless data comes from SNMP where the controller exposes it. | P2 |
| G12 | HTTPS management access | No path. The browser cannot be given device credentials, and a full reverse proxy of vendor web UIs is a large, risky component. | P2 |
| G13 | Access through the API process | `api` runs 2 uvicorn workers on networks `backend, frontend, egress, aaa` (`docker-compose.yml:131`). Device SSH sessions in the API process would share its memory limit (1 GB) and failure domain. | P0 (design) |

## 3. What already works (verified)

- **Inventory:**
  - `switches` table: vendor / family / model / serial / firmware / OS / site / building / floor / rack / role /
    parent;
  - unique name and address (duplicates refused by the database);
  - CSV export, bulk import (`POST /api/switches/import`), manual add, test before add.
- **Discovery:** SNMP sweep of an authorised network (`switch_networks.allow_discovery`), bounded concurrency and
  subnet cap. Results are candidates and are never auto-onboarded. One run per network at a time
  (`SwitchDiscoveryRun`).
- **Polling engine:**
  - per-device leases (`lease_until`), per-group intervals, backoff for failing devices (`backoff_until`);
  - separate wireless job lease;
  - poller replicas (`POLLER_REPLICAS`);
  - bounded concurrency settings.
- **Interfaces:**
  - HC counters with reset, wrap, reboot and renumbering refusal (`switches/rates.py`);
  - duplex, speed, errors, discards, flaps;
  - LAG (`collect_lacp`), STP, VLANs, PoE, MAC tables (Bridge / Q-BRIDGE).
- **Topology:**
  - LLDP / CDP neighbours, firewall and AP placement, impact BFS;
  - parent suggestions that are never applied automatically (`switches/topology.py`);
  - echarts graph with search, zoom and pan (`pages/switches/Topology.tsx`).
- **Wireless:**
  - controller / AP / radio / WLAN / client tables, persisted client sessions and history;
  - roaming, floor SLA, rogues, RF analytics, client traps (`wireless/*`, `docs/WIRELESS*.md`);
  - exact-window history from stored slots, never reconstructed.
- **WAN:** ICMP latency / loss / jitter, ISP outages, SD-WAN health, circuit availability, BGP peers and flaps, VPN
  tunnels (`isp.py`, `wan*.py`, `bgp*.py`, `vpnmon.py`).
- **Services:** TCP / HTTP / DNS / TLS-expiry checks (`nms/services.py`).
- **Faults:**
  - alert engine with NMS rule prefixes;
  - root-cause suppression under a down parent;
  - maintenance windows, acknowledgement and assignment through the shared alerts API;
  - NMS alerts kept apart from SIEM incidents (`products.alert_product`).
- **Config backup:** fixed read-only commands, trust-on-first-use host key, masking, diff, change alert.
- **Self-monitoring:** per-process loop lag / CPU / memory / poll figures with SLOs (`selfmon.py`).

## 4. Partially implemented or needing validation

- **Vendor coverage claims:** these models are tested against SNMP fixtures (`tests/switch_fixtures.py`,
  `snmp_sim.py`), not lab hardware, and are therefore `NEEDS_VALIDATION`:
  - Catalyst 9000 / 9800;
  - FortiGate / FortiSwitch;
  - EX / QFX / MX / SRX;
  - ICX.

  The production deployment polls real Cisco, Ruckus and FortiGate devices.
- **"Last state change":** `ifLastChange` is collected, but flapping is derived from oper-status transitions between
  polls, not from traps. Sub-poll flaps are missed unless link traps are enabled.
- **WAN SLA reporting:** availability and SLA reports exist for circuits. Per-path jitter SLA targets are not
  configurable.
- **ARP:** the MAC table is collected; ARP (`ipNetToMedia` / `ipNetToPhysical`) is not. IP-to-MAC for wired hosts
  therefore relies on the wireless client table.

## 5. Mandatory capability: device access (what the work must deliver)

| Requirement | Acceptance criteria |
|---|---|
| Dedicated access gateway | A separate service (`access`) owns every device SSH / TCP connection. It connects only to inventory devices whose management address passes `validate_address` (authorised network, IP literal, not loopback / reserved). The port comes from a fixed protocol map. A request for any other host or port is refused, with a test. |
| Browser SSH terminal | xterm.js in the device page and the Device Access page. WebSocket with cookie session, Origin check and a one-time ticket bound to user + device + session. Resize, idle and maximum duration timeouts, explicit disconnect, copy and download. |
| Credential vault | Secrets are Fernet-encrypted, never returned and never logged. Kinds: ssh (password / key), https, api_token, netconf. Assignment per device, or per group (site / role / vendor), with the device override winning. Rotation date and owner recorded. Use requires a permission, management requires another. |
| Command library and risk | Vendor command templates. Each command is classified `READ_ONLY` … `DESTRUCTIVE` by a pure function with tests. Diagnostics run only templates. There is no free-text command parameter in the API. |
| Terminal command guard | Commands typed in the terminal are classified at Enter. Configuration-mode entry and destructive commands are blocked unless the user holds `nms.device.access.configuration`. This is defense in depth; device-side AAA is the authority. |
| Bulk diagnostics | Many devices × templates. Bounded concurrency, per-device timeout, progress, cancel, partial failure, history. |
| Change workflow | Request → validate → classify → backup → preview → approve (a different user, `nms.configuration.approve`) → execute (only when `NMS_CONFIG_CHANGES_ENABLED`) → post-backup and diff → verify → audit → rollback (Junos `rollback 1`; other vendors use requester-supplied rollback lines, also approved). |
| Access audit | Every session (user, device, source IP, protocol, result, start / end, termination reason), command (masked, risk, blocked / allowed) and diagnostic run. Hash-chained, append-only. Optional output recording, off by default. |
| RBAC | Seven NMS roles mapped to the 13 `nms.*` permissions from the brief, enforced on every route and on the WebSocket. Site scope still applies. |

## 6. Security weaknesses found

- **S1:** Device SSH from the API process would put device sessions next to every other API workload. Fixed by
  design (G13): a separate gateway service.
- **S2:** `validate_address` is the single allowlist for SNMP, backup and now access. It is correct, but nothing
  stopped a future caller from passing a user-chosen host. The gateway API takes only a device id; the host and
  port are never request parameters (tested).
- **S3:** No session-level record existed for any interactive SSH activity. Terminal sessions, diagnostics and changes
  now write the hash-chained access audit. Configuration backups keep their own record (snapshots and the backup error
  on the device) and now open their SSH connection through the gateway's single dial function, so every device SSH
  connection passes the same host-key pinning code.

No new weakness was found in the existing SNMP, backup or topology code paths during this review.

## 7. Performance considerations

- The production observation in earlier work (syslog and worker memory pressure, ClickHouse CPU) is ingest-driven.
  Device access adds per-session memory (asyncssh channel plus buffers, about 1–2 MB) in a separate container with
  its own limit. Session caps (`NMS_ACCESS_MAX_SESSIONS`, per-user and per-device caps) bound it. No existing limit
  was raised.
- Bulk diagnostics use a semaphore (`NMS_BULK_CONCURRENCY`, default 10) and a per-device timeout. One slow device
  holds one slot only.

## 8. Out of scope for this iteration (documented, not claimed)

These items are listed with reasons in [NMS_IMPLEMENTATION_ROADMAP.md](NMS_IMPLEMENTATION_ROADMAP.md):

- HTTPS reverse proxy of vendor web UIs;
- NETCONF / RESTCONF RPCs beyond a port check;
- gNMI;
- Ruckus SmartZone / One, Mist, Aruba Central and FortiManager-for-switches REST clients;
- serial console servers;
- Telnet (deliberately not built);
- Ansible;
- vendor adapters for Aruba / HPE / Arista / Huawei / MikroTik / Dell / Extreme beyond generic MIBs;
- ICMP / TCP / ARP discovery.
