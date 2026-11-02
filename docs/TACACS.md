# TACACS+ AAA module

Centralised authentication, authorization and accounting for **administrators of network devices** (FortiGate, Cisco
IOS / IOS-XE, Ruckus ICX FastIron), managed from Sentinel Grid. It does **not** replace how users sign in to the SIEM:
SIEM sign-in and RBAC are unchanged. The module never changes network devices: it generates device templates for
engineers to review and apply, and it changes only the TACACS+ server's configuration, through an approved job.

> **Verification status.** Everything below is implemented and covered by automated tests against simulated
> components (a test TACACS+ server speaking the real protocol framing, a simulated deploy agent, synthetic log lines
> in the configured format). The tac_plus-ng server itself has **not** been built or run in this environment: running
> the upstream build was not permitted during development. The generated configuration follows the tac_plus-ng
> documentation of the pinned commit, and the deploy agent refuses any version that `tac_plus-ng -P` does not parse.
> Run the lab checklist below before pointing production devices at it.

## Architecture

| Component | Where | Responsibility |
|---|---|---|
| TACACS+ server | `deploy/tacacs/` (image `fortisiem-tacacs`) | tac_plus-ng (event-driven-servers, Marc Huber), built from pinned commit `dc3ce306f0a9753c2ae8cb4cc761d8c8a33b7b6b` with PCRE2 and the MAVIS LDAP module |
| Deploy agent | `deploy/tacacs/agent.py` | stdlib-only supervisor inside the tacacs container: runs tac_plus-ng, validates candidates with `tac_plus-ng -P`, backs up, activates atomically, reloads (SIGHUP), health-checks TCP/49, rolls back automatically, writes `status.json` |
| Configuration adapter | `backend/app/tacacs/render.py` | structured model → native tac_plus-ng configuration (full, with secrets, and redacted) |
| Policy engine | `backend/app/tacacs/policy.py` | evaluation order shared by the renderer and the simulator; precedence, time windows, conflicts, effective-access explanation |
| Vendor adapters | `backend/app/tacacs/vendors.py`, `templates.py` | capability matrix, command categories, privilege semantics, device templates |
| Log parser / ingestion | `backend/app/tacacs/parse.py`, `jobs.py` | log formats, message-id classification, redaction, cursors, de-duplication, health, deployment jobs |
| Testing center | `backend/app/tacacs/client.py` | TCP/49, test-user authentication and accounting round trip (tacacs_plus client), LDAP / AD bind |
| Detections | `backend/app/tacacs/alerts.py` | 17 rules in the existing alert engine |
| API | `backend/app/api/tacacs.py` | `/api/tacacs/*` with backend RBAC |
| UI | `frontend/src/pages/tacacs/` | sidebar → **TACACS+ AAA** (14 tabs) |
| Storage | Alembic `0017_tacacs_aaa.py`, ClickHouse migration 10 | see *Data* |

Data flow: devices → TCP/49 → tac_plus-ng → log files on the shared volume `tacacs_logs` → SIEM worker (read-only
mount) → ClickHouse `tacacs_events` → explorer, sessions, detections. Configuration: SIEM UI → versions (PostgreSQL,
full text Fernet-encrypted) → approved deployment job → worker writes a candidate and a request into the shared volume
`tacacs_config` → agent validates and activates → result file → job status.

### Why tac_plus-ng, and not a custom server

A maintained, standards-compatible server (RFC 8907 TACACS+) with LDAP / AD (MAVIS), PAM, command authorization,
configurable accounting formats and multiple keys per device (rotation without an outage). The SIEM implements no
server-side protocol code. The only protocol code in this repository is the **client** used for tests (the pinned
`tacacs_plus` library) and a minimal test-only server in `backend/tests/tacacs_sim.py`.

## Installation

Dependencies (pinned): backend `tacacs_plus==2.6`, `six==1.16.0`, `passlib==1.7.4`, `ldap3==2.9.1`; image
`debian:12.7-slim` with tac_plus-ng from the commit above. The image build clones the upstream repository: the build
host needs HTTPS access to github.com.

```
# .env on the SIEM host
COMPOSE_PROFILES=tacacs            # build and start the tacacs service (otherwise it is neither built nor started)
TACACS_BIND=10.0.0.5               # optional: publish TCP/49 on one host address only (default 0.0.0.0)

docker compose build tacacs && docker compose up -d   # deploy.sh does this when COMPOSE_PROFILES is set
docker compose run --rm migrate                       # applies Alembic 0017 and ClickHouse migration 10 (deploy.sh does this)
```

On first start the agent installs a deny-all bootstrap configuration (no devices defined: every connection is
rejected) until the first approved version is deployed. The bootstrap uses the same log formats as rendered versions
(so its connection log is ingested correctly) and is refreshed on container start while it is still the active
configuration; a SIEM-deployed version is never replaced.

Then register the server under **Servers** as kind *managed*, management address `tacacs` (the compose service
name, checked from the worker and api containers), client address = the host IP devices use, port 49. The agent checks
its own listener through `/proc/net` rather than connecting, and connection-log lines from the SIEM's own containers
(the TCP/49 health checks) are stored as `conn_probe` / `health_check`, never as unknown devices.

Log variables and msgids follow tac_plus-ng at the pinned commit (`parse_log_format` in `tac_plus-ng/utils.c`, the
hint table in `authen.c`); `test_log_formats_use_known_variables_and_match_bootstrap` fails if a format uses a
variable the server would refuse (an unknown variable stops the whole configuration from loading).

Environment variables (backend): `TACACS_CONFIG_DIR` (`/tacacs/config`), `TACACS_LOG_DIR` (`/tacacs/logs`),
`TACACS_DEPLOY_TIMEOUT_SECONDS` (90), `TACACS_TEST_TIMEOUT_SECONDS` (8).

### Ports and firewall rules

| From | To | Port | Purpose |
|---|---|---|---|
| network devices (management interfaces) | SIEM host | TCP/49 | TACACS+ (restrict to the device management subnets in the host firewall) |
| tacacs container | LDAP / AD servers | TCP/636 (LDAPS) or TCP/389 + StartTLS | MAVIS directory lookups |
| SIEM worker | tacacs container | TCP/49 (Docker network) | health checks and tests |

TACACS+ obfuscates packet bodies with the shared key (MD5-based); this is **not** transport encryption and must not be
treated as equivalent to TLS. Keep TCP/49 on management networks only.

## Getting started

1. **Settings** (policy_admin): add the authorised client networks (device management subnets), and the tester
   address: the SIEM worker's source IP as the TACACS+ server sees it (`docker inspect` the worker on the compose
   network). A tester key is generated; it is used only by the SIEM.
2. **Servers** (operator): add the managed server (management address `tacacs`, client-facing address = the host IP
   devices use), and any external TACACS+ servers (monitor and test only).
3. **Users & identity sources** (policy_admin): add `local` (for break-glass accounts) and your AD / LDAP source:
   `ldaps://dc1.example.net:636`, base `dc=example,dc=net`, a read-only bind account, memberOf regex
   `^CN=tac_([^,]+),.*` (AD group `tac_netops` becomes TACACS+ group `netops`). Run the bind test.
4. **Authorization & commands**: add the built-in roles, map groups to roles (scope by site / device group / vendor /
   device, time window, expiry; privileged roles need a justification), add command rules, check *Conflicts* and use
   the simulator for permitted, denied and unmatched commands.
5. **Device clients** (operator): register each device (IP; ranges need a justification). The 32-character shared
   secret is shown once. Open **Template** for the vendor configuration.
6. **Configuration studio** (policy_admin): review the redacted diff, commit a version, *Validate on server*, then
   *Request deployment*. A different user with the approver role approves (separation of duties). The worker hands
   it to the agent, which validates, backs up, activates and health-checks.
7. **Testing center** (operator): TCP/49, test-user authentication (correlated with the server's own log line),
   accounting round trip (appears in the explorer), primary / secondary reachability.
8. Apply the device template in a change window, from a session that stays open until a new TACACS+ login works.

## RBAC

| TACACS+ role | Can |
|---|---|
| (any signed-in user) | overview counts, servers, clients, roles, simulator, health (no command history) |
| auditor | accounting explorer, raw (redacted) records, session audit, CSV export, audit history |
| operator | servers, clients (secrets, rotation, templates), tests |
| policy_admin | identity sources, users, roles, mappings, command rules, authentication policies, settings, configuration preview / versions, deployment requests |
| approver | approve / reject deployments (never their own) |

SIEM administrators hold every TACACS+ role (separation of duties still applies) and are the only ones who assign them
(*Settings → Role assignment*; changing roles revokes the user's sessions). Refused attempts are audited and raise
the *unauthorised policy change* detection.

## Authentication

Identity sources: **local** (users in tac_plus-ng, passwords stored only as SHA-512-crypt hashes), **AD / LDAP**
(MAVIS `mavis_tacplus-ng_ldap.pl`; the directory is queried at login and not copied into the SIEM), **PAM** (on the
TACACS+ host). Result classes come from tac_plus-ng message ids:

| Class | Message ids |
|---|---|
| success | AUTHC-PASS |
| failure (wrong / missing credentials) | AUTHC-FAIL, -DENY, -DENY-RETRY, -NOPASS, -WEAKPASSWORD |
| backend unavailable | AUTHC-FAIL-BACKEND (never counted as a wrong password) |
| policy denial | AUTHC-FAIL-ACL (ruleset / disabled / no mapping) |
| protocol error | AUTHC-FAIL-BUG, undecodable requests (often a key mismatch) |
| authorization denial | AUTHZ-FAIL |
| accounting failure | ACCT-UNKNOWN, missing accounting |

Authentication policies (per device group): allow local and / or directory accounts, allow emergency accounts,
failure alert threshold. **No lockout** is configured: thresholds raise alerts only, so a failure burst cannot lock
administrators out of the network. Default deny is fixed: a user with no matching role mapping is denied.

## Authorization and command authorization

Evaluation order (first match wins; identical in the simulator and the rendered ruleset):

1. disabled or expired users, then authentication-policy denials
2. the tester device (deny-all profile)
3. role mappings by priority (lower first), then specificity (device > device group > site > vendor > all), then id

Inside the role's vendor profile: explicit command rules by priority (deny before permit at equal priority, so an
exception must have a *lower* number than the rule it overrides), then the role's permitted categories, then the
role's default action. Exceptions need an owner, a justification and an expiry; expired rules and mappings are not
rendered.

| Vendor | Exec authorization returns | Command authorization |
|---|---|---|
| Cisco IOS / IOS-XE | `set priv-lvl = N` (1 user EXEC … 15 full) | per command, at the levels configured with `aaa authorization commands <lvl>` |
| Ruckus ICX FastIron | `add foundry-privlvl = N` — **0 super-user, 4 port-config, 5 read-only** (inverse of Cisco) | per command (`aaa authorization commands 0`) |
| FortiGate FortiOS | `add admin_prof = "<profile>"` (service fortigate) | **not supported**: profile only; the UI says *not enforced* |

Command categories (read-only, interface, VLAN, routing, firewall policy, VPN, system, AAA / users, save / restore,
reload / reset, configuration mode) are vendor-specific regular expressions (`vendors.py`), not universal syntax.
Custom patterns accept the subset that Python and the server's PCRE2 agree on (no lookaround, back-references or
inline flags) and are case-sensitive, like the server.

## Accounting and session auditing

The rendered configuration defines the log formats (tab-separated, RFC 5424 timestamps, message id first, AV pairs
with `|`). Ingestion keeps a cursor per file (inode + offset), detects rotation and truncation, leaves an incomplete
last line for the next pass, de-duplicates by line fingerprint (in memory and with ReplacingMergeTree), counts parse
errors and keeps the last one, and flags missing files. Events are normalised (`tacacs_events`: time, server, log,
message id, event type, result, user, device, client id / vendor / site, port, rem_addr, service, privilege,
profile, rule, command, command category, task id, session id, elapsed time, redacted raw line).

Sessions are reconstructed from exec accounting start / stop (task id), with the commands recorded on the same
device / user / port while the session was open. A session record is only as complete as the device's accounting
configuration: without `aaa accounting commands …` there are sessions but no commands, and FortiGate accounting depends
on the FortiOS release.

**Redaction** happens before storage, indexing, display, export or alerting: password / secret / key / community /
psksecret / passphrase arguments (with Cisco type digits and FortiOS `ENC` values), plus your own rules (Settings).

## Configuration studio and deployment

Versions are immutable (number, message, SHA-256, redacted text, Fernet-encrypted full text, validation result).
Deployment: request (policy_admin) → approval by someone else (approver), bound to the version, the server and the
server's active configuration hash (a stale or replayed approval is refused and the request is cancelled) → worker
writes `candidates/<job>.cfg` and `requests/<job>.json` → agent checks the hash, parses with `tac_plus-ng -P`, copies
the active file to `backups/`, renames the candidate into place, sends SIGHUP, waits for the process and TCP/49, and
restores the backup automatically if the new configuration is unhealthy → `results/<job>.json`. The worker times out
after 90 s and withdraws the request, so a late agent cannot apply it. No path, command or file name comes from the
browser.

### Recovery

* Roll back: request deployment of the previous version (it is a normal approved change).
* If the SIEM cannot reach the agent: on the host, `docker compose exec tacacs ls /tacacs/config/backups`, copy the
  desired backup over `/tacacs/config/active/tac_plus-ng.cfg`, then `docker compose restart tacacs`.
* If TACACS+ is down, devices fall back to their local emergency accounts (templates configure `… local` fallback and
  Cisco `if-authenticated`).

## High availability

Clients have a primary and a secondary server. Only one **managed** server per SIEM host (it shares the agent volume);
secondaries are external servers you keep in step with your own process (or a second SIEM instance with its own
managed server). Health checks run every 30 s (TCP/49 plus the agent's status), with damping (down after two
failures), history and 24-hour availability. Device failover differs by vendor (Cisco tries servers in group order,
FortiGate uses `secondary-server` on timeout, FastIron tries hosts in configured order); test it in a lab. Never remove
a device's only working administrative method during a failover test or a configuration change.

## Emergency access

* Keep a device-local emergency account on every device (the templates start with it) and store its password offline.
* Optional TACACS+ break-glass accounts: local users flagged *emergency*; every successful use raises a **critical**
  alert. Authentication policies can exclude them per device group.
* Apply TACACS+ changes from a session that stays open until a new login has been verified.

## Detections

tacacs_auth_failures, tacacs_authz_denials, tacacs_success_after_failures, tacacs_privileged_off_hours,
tacacs_unexpected_client, tacacs_unknown_device, tacacs_disabled_user, tacacs_server_down*, tacacs_accounting_gap*,
tacacs_protocol_errors, tacacs_backend_failures, tacacs_config_change, tacacs_privileged_role_assigned,
tacacs_unauthorized_policy_change, tacacs_emergency_use, tacacs_multi_device_activity, tacacs_missing_accounting*
(* resolve themselves and send `alert.resolved`). Each alert carries the rule, user, device, timestamps, the logic,
evidence, investigation steps and related events. Thresholds and windows are rule parameters (Detections); one open
alert per user / device / condition (no alert per repeated event); alerts correlate into incidents by user, together
with the SIEM's VPN / identity alerts for the same person.

## Security hardening

* Secrets: device keys, the tester key and LDAP bind passwords are Fernet-encrypted with `TOKEN_ENCRYPTION_KEY`, shown
  once (device keys) or never (bind passwords), redacted in previews, versions, logs and agent output. The live
  configuration file is readable only by the tacacs user and the `tacshare` group (worker).
* The tacacs container drops all capabilities except those needed to prepare the volumes; tac_plus-ng binds TCP/49
  through a file capability and runs as an unprivileged user.
* Client addresses are validated (inside authorised networks, no overlaps, no loopback / link-local / reserved, wide
  ranges need a recorded justification, nothing wider than /16). Server and LDAP hosts pass the outbound guard; LDAP
  TLS is always verified; clear-text LDAP is refused.
* Inputs: identifiers are restricted to `[A-Za-z0-9_.-]`, strings are escaped, regexes validated; subprocesses in the
  agent use argument lists and timeouts.
* Rate limits: tests (10/min, authentication tests 5/min), health checks (20/min), deployment requests (10/min).
* Every change is in the SIEM audit log (*Audit & changes*), including refused attempts.

## Lab checklist (before production)

1. Build the image (`COMPOSE_PROFILES=tacacs docker compose build tacacs`) and start it in a lab.
2. Commit and deploy a version; confirm the job succeeds (the agent's `tac_plus-ng -P` accepted it).
3. Testing center: TCP, authentication of a local and a directory user, accounting round trip.
4. Point a lab Cisco, Ruckus and FortiGate at it with the templates; verify login, exec privilege, a permitted and a
   denied command, accounting in the explorer, and failover to the secondary.
5. Only then add production devices, a few at a time, each with its local emergency account tested first.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Test: TCP refused / name does not resolve | tacacs service not running (COMPOSE_PROFILES), or wrong management address (use `tacacs`) |
| Test: authentication *policy denial* | the user has no role mapping for the tester device / was disabled — or for real devices, no mapping for that device |
| Test: *backend unavailable* | LDAP / AD not reachable from the tacacs container, certificate not trusted, bind account wrong (run the bind test) |
| *protocol error* events / alert | shared-secret mismatch between device and server (rotation half-finished?) |
| Deployment *invalid* | `tac_plus-ng -P` rejected the version: the parser output is shown on the job |
| Deployment *failed: no answer* | agent not running or the volume is not shared with the worker |
| Ingestion problems on the overview | log file missing (no events yet or wrong volume), or unparsed lines (format changed by hand) |
| Sessions without commands | the device does not send command accounting (FortiGate, or no `aaa accounting commands`) |

## Testing

```
cd backend && ../.venv/bin/python -m pytest -q tests/test_tacacs.py   # TACACS+ (simulated server / agent, no real AAA)
cd backend && ../.venv/bin/python -m pytest -q                       # whole backend (regression)
cd frontend && npx tsc --noEmit && npx vitest run
```

Covered: rendering (full vs redacted, escaping, ordering, rotation keys), validation and conflicts, exec and command
authorization per vendor (permitted, denied, unmatched, exceptions, time windows, expiry, policies), parsing of every
log class, redaction, ingestion (cursor, incomplete lines, rotation, duplicates, parse errors, missing files),
sessions, deploy workflow (approval, separation of duties, replay, stale base, invalid, agent timeout), the agent
(hash check, parse failure, activation, backup, automatic rollback, unknown actions), health damping and recovery,
client tests over TCP against the simulated server (PASS, FAIL, wrong key, accounting), outbound guard, LDAP refusals,
detections with thresholds and de-duplication, server-down auto-resolve, templates, API RBAC / validation /
secret handling, frontend navigation. **All results are against simulated components.**

## Example (fictional addresses, placeholder secrets)

```
id = tac_plus-ng {
	device wh1-acc-sw01 {
		address = 10.20.0.11/32
		key = "<per-device secret>"
		tag = cisco
	}
	profile r_network_engineer_cisco {
		enable 15 = login
		script {
			if (service == shell) {
				if (cmd == "") { set priv-lvl = 15 permit }
				if (cmd =~ /(?:^(reload|erase|format|delete|write erase|factory-reset)\b)/) deny # rule:1
				if (cmd =~ /(?:^(show|ping|traceroute|terminal|dir|more|who|exit|end|disable|enable$)\b)/) permit # category:read_only
				deny # role default
			}
			deny
		}
	}
	ruleset {
		rule m1_cisco { script { if (member == "netops" && device.tag == cisco) { profile = r_network_engineer_cisco permit } } }
	}
}
```

## Known limitations

* tac_plus-ng was not built or run during development (see the verification note); validate in a lab first. Upstream
  describes it as work in progress.
* One managed server per SIEM host; secondary servers are external (monitored and tested, not configured).
* Remote (external) servers' logs are not ingested; ingestion reads the managed server's files only.
* Command authorization cannot be enforced on FortiGates; FortiGate accounting is release-dependent.
* Time windows are evaluated in the server's time zone (UTC in the container) — the simulator uses UTC too.
* Device shared secrets cannot be verified from the SIEM side; a device's first successful authentication (Last
  authentication) or protocol errors show whether its key matches.
* No account lockout by design; no automatic device configuration (templates only).
* passlib 1.7.4 emits a deprecation warning on Python 3.12 (it uses its own SHA-512-crypt implementation, not the
  removed stdlib module).
