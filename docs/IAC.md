# Infrastructure as Code (IaC) module

FortiGate configuration as code inside Sentinel Grid: versioned desired state, drift detection against the live
firewall, reviewed plans, approvals with separation of duties, controlled deployments with backups and
verification, and recovery plans. It is the **only** part of the SIEM that can change a firewall, and it is off by
default.

## Architecture

| Layer | Where | Notes |
|---|---|---|
| Desired-state format | `backend/app/iac/schema.py` | YAML (`apiVersion: iac.sentinelgrid/v1`), strict Pydantic schema, line-numbered errors, `${var}` substitution only |
| Capability registry + canonical forms | `backend/app/iac/resources.py` | FortiOS cmdb ↔ canonical conversion, managed / reference-only / unsupported types, secret redaction |
| Diff / plan / drift classification | `backend/app/iac/diff.py` | create / update / delete / move, field diffs, dependencies, risk, disruption |
| Security validation + rule catalogue | `backend/app/iac/rules.py` | `IAC-SEC-*` and `DRIFT-*` rules (configurable), exceptions; reuses the policy-analytics shadow analyzer |
| Device integration | `backend/app/iac/adapters.py` | `FortiGateAdapter` (REST, read + gated write), `FortiManagerAdapter` boundary |
| Workflow | `backend/app/iac/service.py` | versions, plans (hash-bound), approvals, staleness, locks, backups, drift, hash-chained audit |
| Execution | `backend/app/iac/executor.py` | worker loop: deploy / dry run / drift jobs, timeouts, cancellation, verification |
| API | `backend/app/api/iac.py` | `/api/iac/*`, role-checked in the backend |
| UI | `frontend/src/pages/iac/` | Overview, Devices, Configuration studio, Drift, Plans & approvals, Deployments, Backups & recovery, Audit, Settings |
| Storage | migration `0014_iac.py` | 15 tables, `users.iac_roles` |

### Why the FortiGate REST API and not Terraform / Ansible

The SIEM already holds an encrypted, least-privilege API token per FortiGate, verifies TLS, and guards outbound
destinations. A REST executor reuses all of that, keeps a single owner for each resource, and needs no new runtime on
the server. Terraform would add a second source of truth (its state file, which contains secrets and must be
encrypted, locked and isolated per device) for the same objects; Ansible would add a procedural runner that the plan
/ approval model cannot bind to a hash. Neither is installed or used. The adapter interface (`DeviceAdapter`) is where
a Terraform- or FortiManager-backed executor would plug in later, with one owner per device.

## Installation and dependencies

No new Python or npm dependencies (PyYAML was already present). Apply migrations as usual (the deploy script runs the
`migrate` service). The worker runs the IaC job loop automatically.

### Environment

| Variable | Default | Meaning |
|---|---|---|
| `IAC_DEVICE_WRITES` | `false` | Master switch. When false, only plans, drift checks, validation and dry runs run; deployments are refused. |
| `IAC_JOB_TIMEOUT_SECONDS` | `1800` | Whole-job timeout for a deployment |
| `IAC_MAX_CONCURRENT_JOBS` | `2` | Jobs the worker runs at once (each device is additionally locked) |
| `IAC_MAX_PLAN_DEVICES` | `25` | Devices per plan |

Writes need **both** `IAC_DEVICE_WRITES=true` and *Settings → Allow approved plans to be deployed* (IaC admin).

## Device onboarding

1. Register the FortiGate under **Firewalls** (host, HTTPS port, VDOM, API token — stored Fernet-encrypted).
2. For read-only use (drift, plans, dry runs) the token's admin profile needs read access to firewall objects /
   policies, router, system and log settings. For deployments, give **write** access only to the object types you
   manage (address, service, policy, router static, selected system / log settings) and restrict trusted hosts to the
   SIEM. Never use a super_admin token.
3. **Infrastructure as Code → Devices → Add device to project** (IaC admin). One project owns each device.
4. **Detect capabilities**: reads `system central-management` (FortiManager detection) and every managed table.
   Devices managed by FortiManager are marked `fortimanager` and their deployments are blocked: a direct change would
   be overwritten by the next FortiManager install. A FortiManager deployment adapter is not implemented yet.

## Configuration format

See `docs/iac-examples/branch-baseline.yaml` (fictional addresses). Variables resolve in the order project →
`sites.<site>` → `devices.<firewall name>` → per-device variables set in the UI. Supported resources:

| Key | FortiOS table | Notes |
|---|---|---|
| `addresses` | firewall address | `ipmask` (CIDR), `iprange`, `fqdn`, `interface-subnet` (subnet + `interface`), `mac` (`macaddr` list) |
| `address_groups` | firewall addrgrp | members |
| `services` / `service_groups` | firewall.service custom / group | TCP/UDP/SCTP (and 7.4 `TCP/UDP/UDP-Lite/SCTP`) port ranges, IP protocol, ICMP / ICMP6 |
| `policies` | firewall policy | interfaces, addresses, services, action, schedule, NAT, logging, status; destination by Internet Service (`internet_service: enable` + `internet_service_name` / `_group` / `_custom`, with `dstaddr` / `service` left empty); **order is managed** (move) |
| `static_routes` | router static | id = seq-num; exactly one of `device`, `sdwan_zone: [zone]` or `blackhole: enable` |
| `system_global` | system global | only `admintimeout`, `admin-https-redirect`, `strong-crypto`, `admin-lockout-threshold`, `admin-lockout-duration`, `admin-telnet`, `admin-sport`, `admin-ssh-port` |
| `syslog` | log.syslogd setting | `status`, `server`, `port`, `mode`, `facility`, `format` |

Reference only (validated, never written): interfaces, zones, schedules. Not supported (reported, never silently
dropped): IPsec VPN, SD-WAN, administrator accounts, IPv6 objects/policies, VIPs, UTM profiles. Unknown keys are schema
errors. Fields not listed are not compared or written; on update the adapter sends the managed fields only.

`manage.prune: [type, ...]` deletes undeclared objects of those types. Without it, IaC only deletes objects it deployed
earlier that were later removed from the file.

`manage.ignore: ["policy:59", "address:EMS-TAG", ...]` lists device objects IaC leaves alone: never changed or deleted
(even with prune) and never reported as drift. An object cannot be both declared and ignored.

**Import from device** validates every object against the schema and only emits what the format can represent exactly.
Everything else is skipped, never imported in a partial form: dynamic / SDN / geography / wildcard addresses,
explicit-proxy services, policies matching on source Internet Service, custom ISDB groups or IPv6 addresses, and routes
to a named address or Internet Service. Skipped objects are listed in the file's header comment, in the import dialog
and in `manage.ignore`, so plans and drift checks leave them out.

## Plan and approval workflow

States: `validation_failed`, `ready_for_review`, `pending_approval`, `approved`, `rejected`, `queued`, `running`,
`succeeded`, `failed`, `rolled_back`, `cancelled`, `stale`.

1. **Commit** a version (immutable, SHA-256). Validation runs without a device.
2. **Plan**: reads every target (GET), renders per device, diffs, classifies risk, runs security rules with the live
   objects (definitive reference checks), and stores the plan with a hash over version, targets, observed device
   state, rule set and every change. Device read errors make the plan `validation_failed`; nothing is guessed.
3. **Submit** (editor) → **Approve / reject** (approver). The approval stores the plan hash; destructive or
   disruptive plans need an explicit acknowledgement. With separation of duties (default for production) the plan
   creator and the version author cannot approve.
4. **Deploy** (deployer): only `approved` plans whose approval hash matches, with writes enabled. Production requires a
   typed confirmation in the UI.
5. Plans become **stale** (and cannot be approved or deployed) when older than the configured age, when rules or
   exceptions change, when the target set changes, or when a device's live configuration no longer matches what was
   planned (checked again by the worker immediately before writing).

## Deployment execution

Jobs run in the worker, never in an HTTP request. For a deployment the worker: takes a lock per device (database
primary key, shared by all replicas) → pre-flights every device (reachable, not FortiManager-managed, live state
unchanged since planning) before the first write → per device: captures a backup, applies the changes in dependency
order (objects → groups → routes → policies → moves; deletes in reverse), checks for cancellation between changes,
re-reads and verifies the result, runs a health check (reachability, CPU, memory) → records per-change results.

* **Fail-fast** (default): later devices are skipped after a failure. Multi-device deployments are **not** atomic.
* **Failures are reported as they are**: partial results, the device's re-read state, the backup id. Nothing is rolled
  back automatically.
* **Cancellation**: a queued job is cancelled immediately; a running job stops before its next change. A request
  already sent to a device cannot be recalled.
* **Dry run**: same pre-flight, then the exact requests each change would send. No backup, no lock, no writes.
* Only allow-listed cmdb paths are writable; object keys are URL-encoded; no command, path, executable or endpoint
  comes from user input.

## Drift detection

Compares the approved desired state with the live device (scheduled every *N* minutes, default 60, or on demand):
missing, modified or moved resources, undeclared policies / routes added after the last deployment (ones that existed
then are recorded as a baseline), action / match / NAT / logging changes, route and admin-access changes. Findings are
classified by the `DRIFT-*` rules (severity configurable) and raise the **iac_drift** alert. Drift never triggers an
overwrite: remediate by planning the approved version again (which goes through approval) or by updating the desired
state.

## Backup and recovery

Before changing a device the worker stores (a) the normalised managed-resource snapshot (no secrets) with its SHA-256
and (b) when the token's profile allows `monitor/system/config/backup`, the full configuration file, Fernet-encrypted
with `TOKEN_ENCRYPTION_KEY`, with its SHA-256. *Verify* re-computes both checksums. A **recovery plan** restores the
resources the job touched to the backup (objects the job created are deleted, modified ones restored) and then follows
the normal approval / deployment workflow. A full-configuration restore (`system/config/restore`, which reboots the
device) is intentionally not implemented.

## RBAC

| Role | Can |
|---|---|
| viewer (everyone signed in) | read everything in IaC |
| editor | edit drafts, commit versions, import, plan, submit, dry run, run drift checks |
| approver | approve / reject plans |
| deployer | deploy approved plans, cancel jobs, verify backups, create recovery plans |
| admin | settings (write switch, separation of duties), rules, exceptions, roles, add/remove devices, production environment changes |

SIEM administrators hold all IaC roles; separation of duties still applies to them. Roles are stored in
`users.iac_roles` and changed under *Settings → IaC roles* (changing them revokes the user's sessions). All checks are in
the backend; the UI only mirrors them.

## Security considerations

* Writes: off by default, two switches, approval bound to the plan hash, re-checked against the live device right
  before writing, per-device locks, job timeouts, rate limits on plan / deploy / device-read endpoints.
* TLS verification and the outbound SSRF guard of the FortiGate client apply to every IaC request.
* Secrets: desired state has no secret fields; observed state never contains them; logs, errors and stored request
  bodies pass through `redact()`; full backups are encrypted; exports contain no tokens.
* Audit: every operation is written to `iac_audit`, a hash chain (*Audit → Verify hash chain* detects modification).
  The chain proves tampering, not prevention: someone with database write access could rewrite it entirely.
* Uploaded configurations are YAML text (≤ 1 MB) parsed with `safe_load`; there is no file upload or path parameter.

## Troubleshooting

| Symptom | Cause |
|---|---|
| Plan `validation_failed` with "cannot read device" | Unreachable host, TLS certificate not trusted (install the CA), token / trusted-host mismatch |
| "the API token's profile cannot read this table" | Give the profile read access to that table |
| Deploy refused: "IAC_DEVICE_WRITES is not enabled" / "disabled in the IaC settings" | Enable both switches |
| Job failed "live configuration changed since planning" | Someone changed the device after planning — re-plan and review |
| Job failed "another deployment holds a lock" | Another job is (or crashed while) deploying to the device; locks expire after the job timeout + 5 min |
| Capabilities say FortiManager | Deploy through FortiManager; direct deployment is blocked |

## Tests

```
cd backend && ../.venv/bin/python -m pytest -q tests/test_iac.py   # IaC (mocked FortiGate, no network)
cd backend && ../.venv/bin/python -m pytest -q                     # whole backend
cd frontend && npx vitest run                                      # frontend unit tests
```

`tests/iac_fake.py` is an in-memory FortiGate REST API (httpx MockTransport) used by every IaC test; no test contacts a
real device.

## Known limitations

* Resource coverage is the table above; FortiManager deployment, IPv6, VIPs, VPN, SD-WAN and UTM profiles are not
  managed.
* No remote Git repository integration yet: versions live in PostgreSQL and the project export produces the `iac/…`
  repository layout. A Git adapter can be added behind the version store.
* Shadow / redundancy findings are static analysis (see Policy Analytics) — confirm with policy lookup and hit counts.
* Real-device deployment has not been tested from this codebase; it has only been exercised against the mocked API.
  Try it first against a lab FortiGate with a restricted token.
