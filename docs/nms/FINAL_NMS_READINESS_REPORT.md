# Sentinel NMS: final readiness report (2026-11-20)

## 1. Feature completion

**Update (2026-11-23):** ICMP / TCP / ARP discovery, the L3 / WAN topology layer, NETCONF / RESTCONF read operations,
Telnet (opt-in), serial console (Opengear, Cisco), SmartZone / Ruckus One / Mist / Aruba Central integrations and
Ansible automation are now built; see [NMS_EXTENSIONS.md](NMS_EXTENSIONS.md).

See [NMS_FEATURE_MATRIX.md](NMS_FEATURE_MATRIX.md) for every feature with before / after status and evidence. In
short:

- **Monitoring** (discovery, inventory, SNMP v2c / v3, interfaces with HC counters and reset handling, LLDP / CDP
  topology with impact, Catalyst 9800 wireless with history, WAN / BGP / VPN, services, flows, faults, capacity,
  reports, self-monitoring):
  - already implemented before this work, and verified in the code path;
  - unchanged except where noted.
- **Device access**, the mandatory core: newly implemented (gateway, terminal, vault, command library, diagnostics,
  bulk, change workflow, audit, RBAC, UI).
- **Not implemented** (with reasons and next steps in [NMS_IMPLEMENTATION_ROADMAP.md](NMS_IMPLEMENTATION_ROADMAP.md)):
  - gNMI telemetry;
  - HTTPS proxying;
  - configuration templates with variables;
  - full-configuration restore.

## 2. Confirmed root causes and gaps

From [NMS_GAP_ANALYSIS.md](NMS_GAP_ANALYSIS.md):

| Gap | Root cause |
|---|---|
| G1: no device access | The design was read-only toward devices, with no WebSocket or terminal stack |
| G2: no NMS permission model | Only `admin` / `analyst` plus product and site scope existed |
| G3: no access audit | Nothing recorded sessions or commands |
| G4: partial vault | SSH secrets for backup only, with no kinds, groups or rotation |
| G5: no change path for switches / routers | Not built |
| G13: no isolated service for device sessions | Sessions would have run inside the API process |

## 3. Implemented in this release

| Area | Delivered |
|---|---|
| Gateway (`app/access/gateway.py`) | Device-id-only targets, management-network allowlist, fixed ports, session caps, single SSH dial path with host-key pinning (now also used by configuration backup) |
| Terminal (`terminal.py`, `Terminal.tsx`) | xterm.js over a ticket-authenticated WebSocket. Command guard, timeouts, termination, revocation, recording, multiple sessions, copy / download / reconnect. |
| Vault (`vault.py`) | ssh / https / api_token / netconf credentials, Fernet at rest, group assignment, rotation date. Write-only secrets. |
| Command library (`commands.py`) | Five-level risk classifier; 71 read-only templates on 11 platforms |
| Diagnostics (`diagnostics.py`) | Single and bulk; bounded, cancellable, partial-failure tolerant, exportable |
| Changes (`changes.py`) | Request → four-eyes approval → backup → execute → verify → backup → diff → rollback. Junos `commit confirmed`. Off by default. |
| Audit (`audit.py`) | Hash-chained, concurrency-safe, verifiable, CSV export |
| RBAC (`rbac.py`) | 7 roles, 13 permissions on REST and WebSocket; site scope; revocation on role change |
| UI | NMS → Device Access (Devices, Sessions, Bulk diagnostics, Change requests, Credential vault, Access audit, NMS roles); device page **Access** tab |
| Deployment | `access` service, nginx WebSocket route, Kubernetes upstream, worker housekeeping |

## 4. Files

| | Files |
|---|---|
| **New, backend** | `app/access/` (`__init__`, `__main__`, `asgi`, `audit`, `changes`, `commands`, `diagnostics`, `gateway`, `rbac`, `terminal`, `vault`), `app/api/access.py`, `migrations/versions/0035_nms_device_access.py`, `tests/test_device_access.py`, `tools/nms_bench.py` |
| **New, frontend** | `src/pages/nms/Access.tsx`, `src/pages/nms/Terminal.tsx`, `proxy_access.inc` |
| **New, docs** | `docs/nms/*.md` (19 documents) |
| **Changed, backend** | `app/db/models.py`, `app/config.py`, `app/main.py`, `app/configs/backup.py` (dial path), `app/configs/alerts.py` (housekeeping), `app/api/configs.py` (SSH-kind filter), `tests/test_secret_files.py` |
| **Changed, frontend** | `App.tsx`, `lib/products.ts`, `components/Sidebar.tsx`, `pages/switches/SwitchDetail.tsx`, `vite.config.ts`, `package.json`, `package-lock.json`, `nginx.conf`, `nginx-main.conf`, `upstream.inc`, `Dockerfile` |
| **Changed, deployment** | `docker-compose.yml`, `scripts/deploy-files.rsync`, `k8s/applications/frontend/web.yaml` |
| **Backups** | `backups/pre-nms-access-2026-11-20/` |

## 5. Database migrations

PostgreSQL **0035** is additive:
- 5 columns: `users.nms_roles`, `switches.access_platform`, and `device_ssh_credentials.kind / owner / rotated_at`;
- 8 tables: `nms_credential_assignments`, `nms_access_sessions`, `nms_access_commands`, `nms_access_recordings`,
  `nms_diag_jobs`, `nms_diag_results`, `nms_change_requests`, `nms_access_audit`.

Upgrade / downgrade / upgrade was tested. There is no ClickHouse migration.

## 6. Vendor support status

See [VENDOR_SUPPORT_MATRIX.md](VENDOR_SUPPORT_MATRIX.md).

- **Monitoring:** Cisco, Ruckus ICX, the 9800 WLC and FortiGate are observed in production. Juniper, FortiSwitch,
  Nexus and ISR / ASR are simulated only. Other vendors get the generic standard-MIB profile.
- **Device access:**
  - the Cisco IOS platform is exercised against a simulated device;
  - every other platform is implemented with templates or a change procedure, but has no device-level test;
  - **no access platform is validated on lab hardware.**

## 7. Device access: security validation

See [SECURITY_REVIEW.md](SECURITY_REVIEW.md), which covers 12 threats, each with its control and test, and the
residual risks.

Checked in the browser against the simulated device (lab):
- `show version` ran;
- `conf t` and `reload` were blocked and never reached the device;
- the refused line was abandoned (^C) and the next command worked;
- diagnostics returned output;
- a change request went requested by `eng` → approved by `appr` → executed → verified → saved, with the before / after
  diff (SNMP community masked);
- sessions, vault, audit and roles views rendered.

**Bugs found and fixed during that check:**

| Bug | Fix |
|---|---|
| Unused tickets left sessions pending | Tickets expire, and the UI releases abandoned sessions |
| Concurrent audit writes on SQLite broke the chain | Per-process lock added |
| Pager offset | Corrected |
| Configuration backup bypassed the gateway dial | Now uses it |
| The guard's prompt handling could have let a refused line through on a CLI without Ctrl-U | Input is now held until a fresh prompt |

## 8. Automated tests

| Suite | Result |
|---|---|
| Backend (full) | **693 passed, 1 skipped** (no failures) |
| Of which device access | 52 (`tests/test_device_access.py`) |
| Frontend | typecheck clean, 53 unit tests passed, production build OK |

## 9. Load tests (simulated)

See [PERFORMANCE_BENCHMARKS.md](PERFORMANCE_BENCHMARKS.md).

| Test | Result |
|---|---|
| Polling engine | 100 / 500 / 1,000 / 2,000 devices: about 21 ms engine time per device per cycle; 2,000 devices in 42 s; no failures |
| Bulk diagnostics | 2,000 devices in 44 s; no failures; about 50 devices/s ceiling in one process |
| Terminals | 100 concurrent; about 0.5 MB each; echo p95 38 ms |

**Not demonstrated:** 2,000 real devices at a 60 s interval. That needs measured SNMP latency and probably 6–7 poller
replicas.

## 10. Remaining limitations

- No lab-hardware validation of any access platform or of the change procedures.
- Terminal guard limits: device-defined aliases / macros; history-recalled lines are refused in read-only sessions.
- Shared vault accounts: device-side logs show the vault user. Sentinel's audit shows the person.
- Trust on first use for host keys.
- HTTPS management is a direct link, not a proxy. NETCONF / RESTCONF are read-only operations.
- Kubernetes runs device access in-process in the API pods. A separate Deployment is roadmap R3.
- Bulk throughput is bounded by one gateway process (about 50 devices/s in simulation).
- The not-implemented items in section 1.
- Pre-existing npm audit findings (ECharts, React Router, moderate) are unchanged by this work.

## 11. Production readiness

| Capability | Status |
|---|---|
| Read-only access (terminal, diagnostics, bulk, vault, audit, RBAC) | **Ready to deploy**, with a lab check on one device of each platform before rollout to engineers |
| Configuration changes | Implemented and tested against a simulator. **Keep `NMS_CONFIG_CHANGES_ENABLED=false`** until each platform's procedure, and its rollback, has been run on a lab device. |
| Monitoring | Unchanged and production-proven |
| Deployment | Additive, with no change to existing service limits. Rollback documented. |

## 12. Deployment and rollback

| Topic | Where |
|---|---|
| Deploy | [PRODUCTION_DEPLOYMENT.md](PRODUCTION_DEPLOYMENT.md). Nothing was deployed: deploy on your go-ahead with the usual `scripts/deploy.sh` command. |
| Rollback | [ROLLBACK_PLAN.md](ROLLBACK_PLAN.md): feature switches, service stop, file restore from `backups/pre-nms-access-2026-11-20/`, `alembic downgrade 0034` (export the audit first) |
