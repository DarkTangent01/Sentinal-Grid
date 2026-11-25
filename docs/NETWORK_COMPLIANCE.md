# Network Compliance (Sentinel NMS)

**Where:**
- **Page:** NMS → Network Governance → **Network Compliance** (`/network-compliance`).
- **API:** `/api/nms/compliance/*`.
- **Code:** `backend/app/netcompliance/`.

**What it does:** read-only checks of switches, routers, wireless controllers and FortiGates, mapped to four
frameworks:
- CIS Controls v8;
- PCI DSS v4.0;
- NIST SP 800-53 Rev. 5;
- ISO/IEC 27001:2022 Annex A.

Each check is evaluated once per device, and its result counts for every control it supports. The results are
evidence for an audit. They are not a certification.

## What it reads (and what it never does)

| Evidence | Source | Devices |
|---|---|---|
| Running configuration, secrets masked | read-only SSH backup (NMS → Config Changes) | Cisco IOS / IOS-XE (incl. 9800 WLC), Juniper (display set), Ruckus ICX |
| Interfaces, administrators, global settings, SSL-VPN, policies | FortiGate configuration snapshot (drift collection) | FortiGate |
| BGP neighbour protection | BGP configuration audit | FortiGate |
| SNMP version and privacy of the polling credential; last successful poll | SNMP polling | all |
| TACACS+ authentications and accounting from the device | TACACS+ module | all registered TACACS+ clients |
| Logs arriving | syslog: per FortiGate; per network device only when a log source lists exactly that one address | all |
| Firmware version vs other devices of the same model | inventory | all |

**What it never does:**
- An evaluation reads stored data only. **No device is contacted and nothing is changed.**
- The suggested CLI shown for a failed check is text to review and apply by hand.
- Configuration lines quoted as evidence are already masked by the backup. Like the configuration itself, they are
  shown to administrators only; other NMS users see the status and the evidence summary.

## Results

| Status | Meaning | In the score |
|---|---|---|
| Met | the evidence shows the requirement is met | yes |
| Not met | the evidence shows it is not | yes |
| No evidence | the data needed is missing; the evidence text says what to collect (for example "assign a read-only SSH credential") | **never**: shown as coverage instead |
| Excepted | not met or no evidence, with an active exception | no |
| not applicable | vendor, type or role outside the check (for example DHCP snooping on a core switch) | not stored |

**Score:** met ÷ (met + not met).

**Evidence coverage:** results with evidence ÷ all applicable results. A high score with low coverage means "what
we could see is fine", nothing more.

**Control status (Controls tab):**
- **Met:** every result is met.
- **Partially met:** some results are met, some are not.
- **Not met:** no result is met.
- **No evidence:** nothing could be evaluated.

Controls that need process evidence (reviews, approvals, training, risk assessment) are not listed. No device check
can show them.

## Checks (catalog version 1.0)

**Switches, routers and WLCs** (the five marked † also run on FortiGates):

| ID | Check | Severity | Evidence |
|---|---|---|---|
| NC-01 † | Central AAA (TACACS+ / RADIUS) for administrative login | high | config; TACACS+ authentications |
| NC-02 | Administrative command accounting | medium | config; TACACS+ accounting |
| NC-03 | Telnet disabled for management | high | config |
| NC-04 | SSH version 2 only | medium | config |
| NC-05 | Plain HTTP management disabled | medium | config |
| NC-06 | Management access restricted to authorised sources | medium | config |
| NC-07 | Idle session timeout ≤ 15 minutes | medium | config |
| NC-08 | Login banner | low | config |
| NC-09 | No SNMPv1 / v2c communities | high | config; polling credential |
| NC-10 | SNMPv3 authPriv | medium | polling credential (+ config) |
| NC-11 † | Logs sent to a central log server | medium | config; syslog arrival |
| NC-12 | Log timestamps with date and time | low | config (Cisco) |
| NC-13 | NTP configured | medium | config |
| NC-14 | NTP authentication | low | config |
| NC-15 | Credentials stored as hashed secrets | high | config (Cisco) |
| NC-16 | Legacy services disabled | medium | config (Cisco, Juniper) |
| NC-17 | BPDU guard on edge ports | low | config (switches) |
| NC-18 | DHCP snooping | low | config (access switches) |
| NC-19 † | Configuration backed up / change-tracked | medium | backup or snapshot age |
| NC-20 † | Firmware matches the fleet standard for the model | low | inventory |
| NC-21 † | Device monitored | low | polling |

**FortiGate:**

| ID | Check | Severity |
|---|---|---|
| FG-01 | No HTTP / Telnet administrative access on interfaces | high |
| FG-02 | No administrative access on WAN interfaces | high |
| FG-03 | Administrators limited to trusted hosts | high |
| FG-04 | Administrator idle timeout ≤ 15 minutes | medium |
| FG-05 | Lockout after ≤ 10 failed logins | medium |
| FG-06 | Strong cryptography | medium |
| FG-07 | Telnet administration and maintainer account disabled | medium |
| FG-08 | MFA for administrators | high |
| FG-09 | SSL-VPN brute-force protection (when SSL-VPN is enabled) | medium |
| FG-10 | BGP sessions protected (when BGP is configured) | medium |
| FG-11 | No any → any / ALL accept policy; accept policies log traffic | high |

Each check's framework controls, rationale and per-vendor CLI are in the check drawer and in
`/api/nms/compliance/catalog`.

**Behaviours worth knowing:**
- Cisco VTY lines without `transport input` fail NC-03: the default accepts Telnet on many IOS releases.
- Ruckus Telnet and HTTP management fail unless explicitly disabled: the default depends on the FastIron release.
- A FortiGate also present in the SNMP inventory is assessed for configuration under the FortiGate scope only.
- Access points are assessed through their controller.

## When it runs
- **Worker loop `network_compliance`:** checks hourly whether an evaluation is due. It runs:
  - once a day;
  - sooner when a new configuration backup or FortiGate snapshot arrived since the last run.
- **Evaluate now** (administrators): runs immediately from the API. This is safe because it only reads the database.
- **Retention:** runs are kept 400 days, which gives the trend chart and audit history.

## Exceptions (accepted risk)

**Who and how:** administrators add an exception from a device finding (one device) or from a check (every device of
a kind). Each exception needs:
- a reason (at least 10 characters);
- an expiry (30, 90, 180 or 365 days).

**Effect:**
- Results stay as evaluated; the stored runs are unchanged.
- Pages, CSV and reports show the result as **excepted** while the exception is active, and it leaves the score.
- When the exception expires, the result counts again.

Adding and removing exceptions is written to the audit log.

## Reporting
- **CSV:** one row per device × check, with the framework controls in their own columns (per framework, or all).
  Cells are protected against spreadsheet formula injection.
- **Scheduled reports:** section **Network compliance (NMS)**, in HTML and PDF. It shows the score and coverage per
  framework and the most failed checks.

## Data model

Migration `0033`, additive only:

| Table | Holds |
|---|---|
| `net_compliance_runs` | one row per evaluation, with totals and a per-framework summary for the trend |
| `net_compliance_results` | per device per run: a JSON list of `{check, status, evidence, lines}` |
| `net_compliance_exceptions` | the active and expired exceptions |

## Limits
- **Configuration checks need the SSH backup.** Without a backup credential those checks show **No evidence**. The
  telemetry checks still run: AAA via TACACS+, SNMP version, logging, backup, firmware, monitoring.
- **FortiGate coverage:** checks use the tables the drift collection reads. Remote-admin (TACACS+ / RADIUS)
  settings, NTP and SNMP on FortiGates are not in the snapshot. NC-01 for a FortiGate therefore relies on TACACS+
  authentications; without them it is No evidence.
- **Firmware:** compared with the fleet, not with vendor advisories. There is no CVE feed for network OS versions
  in this stack.
- **Syslog per network device:** proven only when a log source lists that one address. Syslog lines do not carry
  the sender's address per event.
- **Vendors:** Juniper and Ruckus have fewer configuration checks than Cisco. Unsupported vendors (for example Aruba,
  Arista) show No evidence for configuration checks.
