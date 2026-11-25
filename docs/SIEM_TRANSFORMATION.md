# Sentinel Grid: SIEM transformation (2026-11-16)

This builds on the existing platform and does not replace it.

**Kept unchanged:**
- **Pipeline:** FastAPI + PostgreSQL + ClickHouse, the rsyslog ingress, parser workers, the alert engine and the YAML
  rule format.
- **Investigation tools:** the incident model, the query language, hunting, automation playbooks and the IaC
  approval pipeline.

**New:** everything below is additive. No table was dropped or rewritten, and existing events, alerts and incidents
keep working unchanged.

## 1. Assessment of the existing architecture

The previous gap analysis (`docs/SIEM_GAP_ANALYSIS.md`, 2026-11-02) still describes the foundations. This pass
re-inspected the pipeline, detection, correlation, threat intelligence, identity, incident, automation and AI code.

| Area | Found | Limitation that mattered |
|---|---|---|
| Ingestion | rsyslog ingress (disk queue) → parser workers → batched ClickHouse inserts with retry and a dead-letter spool; backpressure on TCP; per-firewall stats | lines from unknown or spoofed senders, parse failures and duplicates were **only counted in a process log line**: nobody could see who sent what, or why it was not stored. No HTTP / API ingestion. No timestamp validation (a device clock in 2035 put events in a partition nobody queries) |
| Formats | FortiGate, PAN-OS, Windows (NXLog / Winlogbeat / Snare), CEF, Cisco / Ruckus syslog | no Zeek, LEEF, generic JSON / ECS, Linux auth, Juniper or Aruba; RFC 5424 / 3164 headers discarded for unrecognised lines |
| Normalization | one FortiGate-shaped column set used by every query | no common-schema view (ECS / OCSF) for export or search |
| Detection | ~100 Python rules + YAML rules (threshold, distinct count, sum, allowlists, tests) | no **sequence** logic (A then B by the same entity), so brute-force-then-success, scan-then-access and similar needed separate alerts; no confidence or risk per rule |
| Correlation | incidents group alerts by entity within 24 h | works; sequences were the missing piece |
| ATT&CK | tactic and technique per rule | no catalogue, no coverage or gap view, no effectiveness measure |
| Threat intel | IP / CIDR / domain lists from HTTPS feeds, ingest-time matching | no STIX / TAXII / MISP / OTX, no URL / hash / email / ASN, no confidence, expiry or false-positive handling |
| Zeek | **not integrated** | a sensor's view of east-west traffic was missing entirely |
| UEBA | identity baselines (VPN / admin logins), volume baselines | no explainable per-entity risk that learns from analyst verdicts |
| AI | question → query (compiled, read-only), incident summary | no per-alert explanation with citations, no hunt suggestions |
| Incidents | statuses open / in progress / resolved / closed, SLA, tasks, evidence, timeline | no response lifecycle stages, priority, tags or escalation |
| SOAR | SIEM-side playbooks (assign, notify, enrich, suggest block CLI) | no approval workflow, verification or rollback for containment |
| Dashboards | many real-data pages | no executive / SOC operations view (MTTD, MTTR, SLA, workload, posture) |
| Bug found | `get_ch()` | the ClickHouse client could be created twice under concurrent first requests (embedded mode closed the first session; server mode leaked a pool): **fixed** with a lock and a test |

**Decisions on what is not introduced:**
- **No broker (Kafka / Redpanda):** the measured single-host headroom and the rsyslog disk queue cover buffering and
  replay. The criteria for adding one are in `SIEM_IMPLEMENTATION_ROADMAP.md`.
- **No second database:** everything new fits PostgreSQL (state, verdicts, workflow) and ClickHouse (events,
  accounting).
- **No automatic changes to firewalls or directories:** see section 8.

## 2. Ingestion

**New formats** (`backend/app/ingest/formats.py`), each with its own parser version stored on the event:

| Log-source type | What is parsed |
|---|---|
| `zeek` | Zeek JSON logs: conn, dns, http, ssl, x509, notice, files, dhcp, ssh, weird. The connection uid is kept (`log_id`, plus a stable numeric `session_id`) so every log of one connection can be pulled together. Category `zeek` is kept apart from firewall traffic so volumes are not counted twice. |
| `json` | Generic JSON: ECS names, flat names, AWS CloudTrail fields; authentication outcome, traffic action, URL, DNS |
| `leef` | LEEF 1.0 and 2.0 (custom delimiters) |
| `linux` | sshd (failed / accepted / invalid user), sudo (allowed / denied), su, PAM failures, useradd / userdel / group changes |
| `netdev` | Juniper Junos structured tags (commit, login, BGP / OSPF, link) and Aruba (authentication, rogue AP, configuration), in addition to Cisco and Ruckus |
| `syslog` | auto-detects Cisco, CEF, LEEF, Linux auth, Juniper and Aruba; otherwise stores the line with the RFC 5424 / 3164 header (host, program, msgid, severity) |

**HTTP ingestion:**
- **Endpoint:** `POST /api/ingest/{source_id}` with a per-source bearer token. Only its SHA-256 is stored; it is shown
  once and can be revoked.
- **Body:** newline-separated records or a JSON array; at most 2,000 records and 1 MB; 120 requests per minute per
  source.
- **Acknowledged:** a 200 is returned only after ClickHouse accepted the batch. Any other status means "retry the same
  batch". A retry is idempotent: ids come from source + record, and ids already stored in the last day are skipped.

**Accounting: nothing is dropped silently.** Every line that does not become an event is written to ClickHouse
`ingest_rejects` (30-day TTL) with the reason, the sender, the source and one sample line, secrets redacted. Reasons:

| Reason | Meaning |
|---|---|
| `duplicate` | the same event was received again; it is not stored twice |
| `unknown_device` | the sender is not registered |
| `source_mismatch` | the message names a firewall, but the sender is not one of its addresses |
| `parse_error` | the line could not be parsed |
| `bad_timestamp` | the device clock is more than a day in the future or before 2000: the event is stored with the receive time and marked `+bad-ts` |
| `buffer_full` | UDP arrived faster than the store accepted |

**Ingestion health** (`GET /api/log-sources/health`, Log Sources page): for each firewall and log source:
- status: ok, degraded, silent or never;
- events in the last hour and 24 hours;
- ingestion lag p50 / p95;
- duplicates, parse errors, bad timestamps and drops;
- unregistered senders and sample lines.

**Parser test** (administrators): paste a line and see the normalized event and its ECS / OCSF view. Nothing is stored.

**Parser test framework:** `backend/tests/fixtures/parser_samples.yml` holds 25 representative lines and the fields
each must produce. `tests/test_parsers.py` runs them and also checks properties of every parser:
- the raw line is preserved;
- every column is present;
- the same line always gives the same id;
- any unrecognised line falls back to plain syslog and is never lost.

**Measured parser throughput** (one core, in-process, sample mix):

| Parser | Lines / s |
|---|---|
| JSON | 36,000 |
| LEEF | 65,000 |
| Linux | 54,000 |
| netdev | 41,000 |
| syslog | 40,000 |
| Zeek | 46,000 |

Parsing is not the bottleneck; storage writes are (see `PERFORMANCE_BENCHMARKS.md`).

## 3. Normalization: common schema view

Storage keeps the platform's own columns: every query, rollup and rule is written against them, and renaming them would
break everything. `backend/app/ingest/schema_map.py` adds a view on top:
- **ECS mapping:** each column's Elastic Common Schema (ECS) field.
- **OCSF class:** the class per event (Network, DNS, HTTP, Authentication, Account Change, Detection Finding …).
- **`event.outcome`** derived from the action.
- **`to_ecs()`:** the normalized view used by the parser test.
- **ECS search aliases:** ECS names work in the query language. `source.ip:10.0.0.5` compiles to exactly the same SQL
  as `src_ip:10.0.0.5`.

## 4. Detection and correlation

- **Sequence detection:** a YAML rule can add `followed_by` (selection, `within`, optionally another category). The rule
  alerts only when a group that met the condition also has a later matching event from the same entity within the
  window. It runs as one ClickHouse query (`sequenceMatch`), with every value still a bound parameter.
- **New rule fields:**
  - `confidence` (low, medium, high), separate from severity;
  - `risk_score`, derived from severity and confidence when not set;
  - `author` and `modified`.
- **18 new rules, each with positive and negative tests.** The full pack is now 27 rules and 69 test cases, all
  passing.

| Rules | What they detect |
|---|---|
| COR-1001 | brute force then success |
| COR-1002 | password spraying then success |
| COR-1003 | external scan then an allowed, answered connection |
| COR-1004 | IPS detection then allowed traffic from the same source |
| COR-1005 | new account gains privileges within the hour |
| COR-1006 | large upload to a threat-intel destination |
| ZEEK-4001…4006 | internal port scan, SSH brute force then success, Zeek notices (capture loss excluded), long DNS names, SSH / RDP on non-standard ports to the internet, Windows executables over plain HTTP |
| AUTH-5001, AUTH-5002 | Linux SSH brute force, repeated denied sudo |

- **Correlation:** sequence rules fold what used to be several alerts into one finding. The existing correlation then
  groups findings about one entity into one incident. On the lab data, eight detections across Zeek, Linux and a JSON
  portal became 5 incidents.
- **Unchanged:** Sigma import / export, rule tests before activation, dry runs over history and run statistics already
  existed and still apply.

## 5. MITRE ATT&CK

`backend/app/mitre.py`; page: Threat Detection → ATT&CK Coverage.

**Catalogue:**
- **Built-in:** a curated subset of ATT&CK Enterprise v16, 66 techniques. These are the techniques network, identity
  and device telemetry can show; endpoint-only techniques are left out, so coverage is not diluted by what nothing here
  could ever see.
- **Controlled update:** `python -m app.mitre import enterprise-attack.json` converts the official STIX bundle, and
  `ATTACK_CATALOG_FILE` points to the reviewed result. Nothing is downloaded automatically.

**The page shows:**
- coverage per tactic;
- per technique: rules (enabled / total), alerts in the period, and **precision** (true positives ÷ judged alerts);
- gaps and disabled-rule techniques;
- enabled rules with no technique;
- a drill-down to each technique's rules and alerts.

Incidents already carried tactics and techniques; alert briefs now name and link each technique.

## 6. Threat intelligence

**Connectors** (`backend/app/enrich/connectors.py`):

| Kind | Source |
|---|---|
| `stix` | STIX 2.1 bundle |
| `taxii` | TAXII 2.1 collection (paged) |
| `misp` | MISP `restSearch`, `to_ids` attributes |
| `otx` | AlienVault OTX subscribed pulses |

**Connector safety:**
- API keys are stored encrypted (TokenCipher, included in key rotation). They are sent only to the feed's own host and
  never returned by the API or logged.
- Requests use the same outbound guard as everything else: https only, no private destinations unless allowlisted.
- Paging never follows a link to another host.
- VirusTotal / AbuseIPDB are lookup services rather than feeds; nothing sends your indicators or events to a third
  party.

**Indicators:**
- **Types:** ip, cidr, domain, url, sha256 / sha1 / md5, email, asn.
- **Attributes:** confidence (as the source states it, else the feed default), threat classification, first and last
  seen, expiry, source attribution (one row per feed).
- **Hygiene:** normalization, and refusal of private / reserved / broad networks; dedupe within a fetch.
- **Analyst false-positive verdict:** stops matching within 5 minutes and survives feed refreshes.

**Matching at ingest:** IP / CIDR / domain as before, plus URL (scheme-less, with and without query), email (user
field) and ASN. Hashes are stored for search; events carry no hash column, so they are not matched at ingest.

Page: Threat Intel → Indicators (search, verdicts, statistics) and Feeds (connector form).

## 7. Zeek network security analytics

`backend/app/zeek.py`; page: Security Analytics → Network Security (Zeek). Everything is an observation with its
numbers, never a verdict.

| Tab | What it shows |
|---|---|
| Overview | volumes, connection states, services by protocol detection, notices, protocol anomalies, logs over time |
| Scanning | sources whose connections mostly failed across many ports or hosts |
| Beaconing | internal → internet pairs at regular intervals, with interval, timing / size variation and a 0-100 score (timing 60, size 25, persistence 15) |
| DNS | domains resolved by one host only, NXDOMAIN bursts, long query names, top names |
| TLS | failed certificate validation, self-signed or expired certificates, TLS to IPs without a server name |
| Unusual ports | protocols identified by content on non-standard ports |

**Connection view:** a uid opens every Zeek log of that connection, next to the FortiGate / Palo Alto log entries for
the same addresses and port within ±5 minutes: the sensor's view beside the firewall's verdict.

## 8. Entity risk (UEBA)

`backend/app/risk.py`; page: Threat Detection → Entity Risk. Each host and user gets an explainable 0-100 score:

| Factor | How it counts |
|---|---|
| Points per alert | severity × rule confidence × recency |
| Repeats | from the third alert of one rule on, each counts a quarter |
| Analyst verdicts | two or more false positives / benign for a rule and entity lower that rule to 20% for it; a confirmed true positive raises it to 125% |
| Asset criticality | weights hosts (critical × 1.5 … low × 0.75) |

The page lists every factor with its points. Unusual behaviour alone never raises a score without a detection behind it.

## 9. AI SOC assistant

AI support is optional: it needs an API key and, for anything that sends data, `AI_ALLOW_DATA_SHARING=true`.

- **Investigation brief** (`backend/app/investigate_brief.py`, no AI needed): built for every alert and shown in the
  alert drawer. It covers:
  - what happened and why it was detected (rule description, metric, threshold, confidence, known false positives);
  - assets with inventory context, and users;
  - evidence: the matching events with **event ids and timestamps**;
  - threat-intel matches, impact by tactic, ATT&CK techniques, related alerts in 24 h, entity risk, and next steps.
- **Explain with AI:** writes a narrative from that brief only. Every activity statement must cite
  `[event <id> @ <time>]` or the alert id, and the model is told an alert is a lead, not a verdict.
- **Hunt suggestions** (`POST /api/ai/hunts`): sends only detection names, technique ids and coverage gaps, never
  events, addresses or users. Every suggested query is compiled by the same allow-listing compiler as hand-written
  ones; a query that does not compile is dropped and reported, never run.
- **Unchanged:** natural-language search still compiles to the read-only pipeline language (no generated SQL), as
  before.

## 10. Incident management

**New fields:**
- **Response lifecycle stage:** new → triage → investigation → containment → eradication → recovery → closed. The
  coarse status that every existing query reads is derived from the stage, and older status-only changes keep the stage
  consistent.
- **Priority:** P1–P4, following severity unless set.
- **Tags.**
- **Escalation:** who escalated, to whom and why; an escalated case becomes at least P2.

**Closing** requires a closure reason. Every stage, priority and escalation change is written to the incident's
history and the audit log.

**API:**
- `GET /api/incidents/{id}/timeline` merges detections, status / stage changes, comments, evidence and finished tasks.
- The incident list filters by stage and escalation.

**Metrics:** SLA and workload figures are on the SOC operations page.

## 11. Response actions (SOAR with approvals)

`backend/app/response.py`; page: Security Operations → Response Actions; also available from alerts and incidents.

**Read-only actions run immediately:**
- `enrich_ip`: threat intel, GeoIP, asset and 7-day event counts;
- `collect_evidence`: 24 h of events attached to the incident;
- `notify`: through the notification rules.

**Containment** (`block_ip`, `disable_account`, `isolate_host`) **is never executed by Sentinel.**

1. **Dry-run plan:**
   - the exact commands per target (FortiGate address + SENTINEL-BLOCK group, PAN-OS, AD PowerShell / LDAP, switch
     port);
   - their **rollback**;
   - prerequisites, warnings, and how Sentinel will verify the effect.
2. **Approval** by a second person: an administrator or an approver / responder, **never the requester**.
3. **An operator applies** the commands and records it.
4. **Sentinel verifies from the logs:**
   - a block: denies seen and no accepted session after the change;
   - an account: refused and no successful logins after the change;
   - **inconclusive** (no traffic yet) is never reported as success.
5. **Rollback** is recorded the same way. Temporary blocks carry their expiry.

**Safeguards:**
- **Idempotency:** one open action per (action, target).
- **Validation:**
  - blocks larger than /24 (IPv4) or /64 (IPv6) are refused;
  - internal or reserved addresses are refused for blocking;
  - account names are restricted to a safe character set.
- **Logging:** every step goes to the action's log and the audit log.

Sentinel holds no credentials that can change firewalls or directories, and no model output is ever executed. Applying
a firewall change through the platform's own IaC pipeline (with its own approvals, verification and rollback) remains
the way to automate that.

## 12. Dashboards

| Page | Content |
|---|---|
| SOC Overview → Executive | security posture (100 minus explained deductions), events, open critical alerts, open incidents, high-risk entities, threat-intel matches, MTTD, MTTR, alerts per day by severity, incidents opened / resolved |
| SOC Overview → Operations | alert volume, false-positive rate, MTTD / MTTA / MTTR (median and p90), open incidents by stage and priority, closure reasons, analyst workload, noisiest rules, SLA breaches |
| Network Security (Zeek) | section 7 |
| Entity Risk, ATT&CK Coverage, Response Actions | sections 5, 8, 11 |
| Log Sources | ingestion health, unregistered senders, sample lines, HTTP tokens, parser test |

Every figure comes from stored data. A figure that cannot be measured shows "—", never zero.

## 13. Data model changes

**PostgreSQL migration `0034`** (additive; downgrade drops only what it added):

| Table | Change |
|---|---|
| `log_sources` | HTTP token hash, hint, created |
| `ti_feeds` | auth header, encrypted key, default confidence, expiry days |
| `ti_indicators` | confidence, threat, first / last seen, expires, false positive, fp_by |
| `incidents` | stage, priority, tags, escalation fields |
| `response_actions` | new table |

**ClickHouse migration 21:** `ingest_rejects` (30-day TTL).

**Retention:** Zeek events get a 30-day retention policy by default (category `zeek`), adjustable like the others.

**Migration check:** upgrade, downgrade to 0033 and upgrade again tested on a fresh database. Existing rows need no
backfill.

## 14. API additions

| Prefix | Endpoints |
|---|---|
| `/api/ingest/{id}` | HTTP ingestion (token) |
| `/api/log-sources` | `/health`, `/parse-test`, `/{id}/token` (create, revoke) |
| `/api/ti` | `/indicators` (search, verdict), `/stats`; feeds accept `stix`, `taxii`, `misp`, `otx` with `auth_value`, `default_confidence`, `expire_days` |
| `/api/mitre` | `/coverage`, `/techniques/{id}` |
| `/api/network-security` | `/overview`, `/scanners`, `/beacons`, `/dns`, `/tls`, `/ports`, `/connection/{uid}` |
| `/api/risk` | `/entities`, `/{ip\|user}/{entity}` |
| `/api/soc` | `/metrics`, `/executive` |
| `/api/alerts/{id}/brief` | investigation brief |
| `/api/ai` | `/alerts/{id}/explain`, `/hunts` |
| `/api/incidents` | `/{id}/escalate`, `/{id}/timeline`; PATCH accepts `stage`, `priority`, `tags`; the list filters by `stage`, `escalated` |
| `/api/response/actions` | list, create, `/{id}/decision`, `/applied`, `/verify`, `/rollback`, `/cancel` |

All are behind the Grid product boundary except `/api/ingest`, which is authenticated by a source token, not a user
session.

## 15. Tests and results

**Totals:**
- **Backend:** 641 passed, 1 skipped (was 568 before this work and the network compliance module).
- **Frontend:** typecheck clean; 53 tests pass, including the UI consistency guards.

| New test file | Covers |
|---|---|
| `test_parsers.py` | 25 parser samples, fallback, uid linkage, Zeek never "severe" by itself, syslog headers |
| `test_ingest_api.py` | HTTP ingest (ack, idempotent retry, limits, tokens, RBAC), reject accounting per sender and reason, health, parser test, ECS view and search aliases |
| `test_ti_connectors.py` | normalization and refusals, STIX / MISP / OTX parsing, TAXII paging with the key, verdicts surviving refresh, expiry, foreign-link refusal, key never returned |
| `test_soc.py` | Zeek scans, beacons (a regular pair found, irregular ones not), DNS, TLS, ports, connection view; risk factors and verdict feedback; ATT&CK coverage and precision, STIX import; SOC metrics; response four-eyes, idempotency, log verification (inconclusive / verified / not verified), rollback, input validation; AI hunt validation; brief; incident lifecycle |
| rule pack | 69 positive and negative cases through the production SQL |
| `test_storage_analytics.py` | one ClickHouse client under concurrent first use |

**Browser check** (lab, synthetic data clearly named `lab-*`, documentation / private addresses):
- the 16 new and changed pages: no errors, overflow or unlabeled controls;
- the beacon detector found exactly the planted beacon;
- the detections and incidents listed in section 4.

## 16. Deployment and rollback

**Deploy:** the normal `./scripts/deploy.sh --apply`. It applies PostgreSQL migration 0034 and ClickHouse migration 21
and restarts the services.

**Nothing to configure for the new features to stay quiet.** To use them:
- **Zeek:** register the sensor as a log source of kind `zeek` and send its JSON logs (`LogAscii::use_json=T`) by
  syslog or HTTP.
- **Linux / JSON / LEEF sources:** register them with their kind.
- **TI connectors:** add a feed of kind `stix`, `taxii`, `misp` or `otx` with its key.
- **Response approvals:** give approvers the `approver` IaC role (or make them administrators).
- **AI explanations:** set `ANTHROPIC_API_KEY` and `AI_ALLOW_DATA_SHARING=true`.

**Rollback:** redeploy the previous code. The new tables and columns are unused by it and can stay; to remove them,
`alembic downgrade 0033` (drops only what 0034 added). `ingest_rejects` expires on its own (30-day TTL).

## 17. Limits and what is not done

- **Syslog over TLS:** not in this pass. The ingress still takes UDP / TCP; HTTPS ingestion is the encrypted path.
  `rsyslog gtls` remains roadmap R2.
- **Windows Event Forwarding:** not added. Windows events still arrive through NXLog / Winlogbeat / Snare.
- **SNMP traps:** not shown in the Event Explorer (unchanged).
- **Zeek per-connection correlation with firewall logs:** matches addresses and port within ±5 minutes. NAT can hide
  the match; the firewall's NAT columns are shown to help.
- **Risk scoring:** built on detections, not raw statistical baselines per user. Identity baselines (unusual login
  time, place, device) already exist as detections and feed it.
- **File hashes in TI:** stored and searchable, not matched at ingest (no hash column in events).
- **Multi-tenancy:** unchanged. NMS has site scoping; Grid data is organisation-wide.
- **Not exercised against real data:** Zeek on a real sensor, real MISP / TAXII servers and the AI calls, because none
  is configured in the lab. They are covered by tests with mocked transports.
