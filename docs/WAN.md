# ISP / WAN observability

**ISP / WAN** in the sidebar (`/isp`) has eight tabs:

| Tab | What it shows |
|---|---|
| WAN overview | Current circuit state, ISP incidents, time to resolve, sites affected, missing root causes, downtime by ISP and site, incidents by location, ISP incidents per day (stacked, one colour per ISP), collector health |
| Live ISP monitoring | Every ICMP target: state, availability, outages, downtime, longest outage, RTT now / avg / P95, jitter, loss, last check, interval; search, filters, sorting, paging, auto refresh; per-target history drawer |
| Circuit inventory | ISP circuits (discovered SD-WAN members plus hand-added ICMP-only circuits) and the targets attached to each |
| ISP incidents | The ISP incident queue: workflow, owner, severity, confirmed root cause, notes, timeline, outages, investigation |
| Analytics & reports | Incident totals, MTTD / MTTR / time to resolve, downtime by ISP / site / circuit, availability trend, monthly trend, root-cause breakdown, CSV export |
| Event history | Every target state change |
| Monitoring configuration | Correlation strategy, recovery behaviour, severities, root-cause categories, maintenance windows |
| SD-WAN health checks | The existing FortiGate SD-WAN analytics (unchanged) |

Every number on every tab comes from one place: the **outage records** (`wan_outages`). The live table and the
incident dashboard therefore cannot disagree.

## Data model

- **Circuit**: an `isp_links` row. SD-WAN members are discovered from firewall logs. Circuits monitored only by ICMP
  have no firewall (`firewall_id` NULL).
  - Fields: name, circuit ID, ISP, site, location, firewall / interface, gateway, bandwidth, primary / backup role,
    SLA target, owner, support contact, monitoring start, enabled, notes.
  - Several circuits per ISP and site are allowed.
- **Target**: an `icmp_targets` row. A target belongs to at most one circuit through `isp_link_id`, and a circuit can
  have several targets (gateway, WAN IP, upstream hosts). A public IP is never treated as the identity of a circuit.
- **Outage**: a `wan_outages` row, one per confirmed outage or degradation episode of a target (`source = icmp`) or
  of an SD-WAN link (`source = sdwan`, mirrored every 5 minutes from full SD-WAN link outages).
  - A partial unique index allows only one open outage per target and kind. Opening an outage is idempotent, so a
    worker restart, a duplicate job or a second worker cannot duplicate it.
- **ISP incident**: an `incidents` row with `category = 'wan'`. It uses the same case workflow tables as security
  incidents and adds site, ISP, circuit, correlation key, probable cause and root cause.
  - The security incident list, its stats and reports filter on `category = 'security'`.
  - Security alert correlation never attaches to ISP incidents.

## State machine (per target)

| State | Entered when |
|---|---|
| unknown | the target was just added or resumed: no baseline yet |
| up | reachable, and loss, RTT and jitter are under the target's thresholds |
| degraded | `degrade_after` (default 3) consecutive *poor* checks: reachable, but loss ≥ `loss_warn_pct`, RTT ≥ `rtt_warn_ms` or jitter ≥ `jitter_warn_ms` (optional) |
| down | `down_after` consecutive failed checks |
| paused | monitoring was paused by an admin; not probed |

How a check works:

- **A check** is `probes` echo requests, each with `timeout_ms`. It succeeds if any reply arrives. A failed check is
  repeated up to `retries` times before it counts as failed. Each check has a deadline of
  probes × (timeout + 0.2 s) + 2 s.
- **Transitions:**
  - unknown → up or degraded on the first good check.
  - down → up or degraded only after `up_after` consecutive good checks.
  - up → degraded after `degrade_after` consecutive poor checks; degraded → up after `clear_after` (default 2)
    consecutive healthy checks. A single slow check never flips the state.
  - A failed check interrupts a healthy streak but not a poor one.
  - A degradation episode is recorded from its first poor check to the first healthy check of the clearing streak.
- **Local errors:** a resolver or socket failure on the SIEM itself is recorded with `error_class = local`. It does not
  move either streak and does not count as packet loss.
- **Scheduling:**
  - The worker claims due targets with a short lease, so overlapping cycles or a second worker never probe one target
    twice.
  - Probes run concurrently (64 at a time by default).
  - Each result is applied in its own transaction to a freshly locked row, and is dropped if that row already holds a
    newer observation.
- **Timestamps:** every check stores its observation time (`ts`), its ingestion time (`ingested_at`) and how late it
  ran (`sched_delay_ms`).
- **Collector heartbeat:** the loop writes a heartbeat (`wan_collector`).
  - If the heartbeat is older than `stale_after_seconds`, every page shows a "stale" banner. Targets keep their last
    known state and are never re-labelled up or down without new evidence.
  - The `wan_collector_stale` alert fires.

## Outage timing convention

| Field | Meaning |
|---|---|
| `last_ok_at` | last healthy check before the failure (the physical failure happened after this) |
| `started_at` | **first failed check** of the streak that crossed the threshold |
| `detected_at` | when the failure threshold was met |
| `recovered_at` | **first good check** of the streak that crossed the recovery threshold |
| `recovery_detected_at` | when the recovery threshold was met |

- Duration = `recovered_at − started_at`.
- Time to detect = `detected_at − started_at`.
- Time to recover = the duration.

Example: with the defaults (3 probes every 30 s, down after 3 failures, up after 2 successes), an outage is confirmed
about 60 s after its first failed check. Its duration runs from the first failed check to the first good one.

- **Pausing:** pausing a target closes any open outage at the pause time. The end of that outage is unknown; it is not
  recorded as a recovery.
- **Maintenance:** an outage that starts inside a matching maintenance window is recorded with `maintenance_id`. It
  opens no incident, sends no notification, and is excluded from outage counts and availability.
- **Targets already down at upgrade:** a target that was already down when outage tracking was installed gets a
  reconciled outage, starting at its last state change.

## Metric definitions

| Metric | Definition |
|---|---|
| RTT now | average of the replies of the latest check |
| RTT avg / min / max | over every successful reply in the window. Failed probes have no RTT. |
| P50 / P95 / P99 | nearest rank: the value at position ⌊n·p⌋ (0-based) of the sorted reply RTTs (ClickHouse `quantileExact`). P99 is shown only with ≥ 100 samples. |
| Jitter | mean absolute difference between consecutive reply RTTs **within one check**, averaged over all such pairs in the window. Consecutive checks are never compared, so gaps cannot create jitter. This is **not** RFC 3550 interarrival jitter. |
| Packet loss | (echo requests sent − replies) ÷ echo requests sent × 100, over the window's checks. Local probe errors are excluded and counted separately. |
| Observed time | the window from the later of its start and the target's first observation, minus paused time, minus maintenance windows, minus **unobserved gaps** (no check for more than `gap_factor` × interval, default 3×) |
| Coverage | observed time ÷ (window − paused − maintenance). Shown next to availability; `*` marks coverage under 90 %. |
| Availability | (observed time − downtime) ÷ observed time. Unobserved time is neither healthy nor down. |
| Downtime | confirmed outage intervals inside observed time. An open outage runs to the window end. |
| Outages | counted in the window in which they **started**. Downtime and longest outage include the overlapping part of earlier outages. |
| Circuit downtime | times when **every** target of the circuit was down, plus full SD-WAN link outages. One unreachable public target does not make a circuit down. |

Checks keep every reply RTT (`icmp_results.rtts`), so the percentiles and jitter are computed from real samples.
Rows written before this upgrade fall back to their per-check average.

## Incidents and correlation

When a target crosses its failure threshold:

1. An outage record is opened. Maintenance windows suppress the following steps.
2. The outage joins an open ISP incident with the same correlation key, but only while that incident still has an
   outage in progress, or one that recovered less than `merge_gap_seconds` ago (default 0). Otherwise a new incident
   is opened.
3. Correlation keys depend on the strategy:
   - `target`: one incident per target.
   - `circuit` (default): targets of one circuit share an incident.
   - `site`: every circuit at a site shares an incident.

Separate outages are never merged just because they happened close together.

When every outage of an incident has recovered, `recovery_action` decides what happens:

| Setting | Effect |
|---|---|
| `resolve` (default) | an Open incident becomes Resolved at the recovery time. Its root cause stays empty, so it counts as missing. |
| `monitoring` | the incident moves to Monitoring |
| `none` | the incident is left as is |

An incident someone is investigating always moves to Monitoring, never straight to Resolved. A new outage on a
Monitoring incident reopens it.

- **Workflow statuses:** Open → Investigating → Monitoring → Resolved → Closed.
- **Fields:** owner, severity, acknowledgement, resolution notes, linked incidents, comments and timeline.
- **Closing rules:** closing needs a root-cause category and no outage in progress.

**Root cause** works in three layers:

- The system records the **detected symptom** (the summary) and an evidence-based **probable cause** from
  `investigate()`.
- Only a person sets the **confirmed root-cause category**. The categories are configurable.
- ICMP failure alone is never presented as an ISP root cause.

**Investigation** (`/api/wan/investigate`, shown in the target drawer and on every incident) classifies a situation as
one of:

- monitoring-system problem (stale collector)
- site-wide outage (every target across different circuits at the site)
- firewall or local problem (every circuit behind one firewall)
- ISP-wide problem (that ISP's targets down at two or more sites)
- single-circuit failure (every target of the circuit, or SD-WAN agreement)
- single-target failure (other targets on the circuit still answer)

Every evidence line is listed with the verdict.

**Counting rules** for analytics:

- An incident is counted once, in the window and calendar day (in the viewer's time zone) in which its first outage
  started.
- "Missing root cause" = incidents in the window with no confirmed category.
- Time to resolve = `resolved_at − first_seen`.

## Alerts and notifications

**Direct notifications**, sent through the existing outbox and channels:

- `wan.outage`: an outage is confirmed.
- `wan.recovered`: the outage recovered. The message includes the outage duration.

Add these event types to a notification rule. Quiet hours and de-duplication apply as usual.

**Alert rules** go through the standard engine, with its thresholds, cooldown, de-duplication and auto-resolve with
`alert.resolved`. They skip paused targets and targets in maintenance.

| Rule | Condition |
|---|---|
| `wan_latency_sustained` | most checks in the window at or over the RTT threshold |
| `wan_loss_sustained` | loss over the window ≥ the loss threshold (local errors excluded) |
| `wan_jitter_sustained` | within-check jitter ≥ the target's threshold (default 30 ms) |
| `wan_flapping` | at least N down transitions in the window |
| `wan_long_outage` | an outage open longer than N minutes |
| `wan_site_incidents` | at least N ISP incidents at one site within the window |
| `wan_missing_root_cause` | resolved incidents without a root cause after a grace period |
| `wan_collector_stale` | no collector heartbeat |
| `wan_low_coverage` | a target observed for less than N % of the window |
| `wan_availability_low` | circuit availability below its SLA target |

The existing `icmp_down` and `isp_outage` rules are unchanged. WAN rule alerts never open security incidents.

## APIs

All `/api/wan/*` endpoints:

- **Auth:** reads need a signed-in user. Circuits, targets, pause / resume / test, maintenance and settings need the
  admin role. ISP incident workflow is open to analysts.
- **Audit:** every change is audited.

| Endpoint | Purpose |
|---|---|
| `GET /meta` | statuses, root causes, sites, ISPs, firewalls |
| `GET /overview` | cards, ISP + site summary, by location, daily chart |
| `GET /summary?group=isp_site\|isp\|site\|circuit\|firewall` | grouped table with search, filters, sort and paging |
| `GET /targets` | live table (filters, sort, paging, totals, collector) |
| `GET /targets/{id}/history` | time series (gaps as nulls), state timeline, outages, SD-WAN outages, maintenance, events |
| `GET /targets/{id}/observations` | raw checks for a chart point or outage |
| `POST /targets/{id}/pause\|resume\|test` | pause, resume, or a one-off test that changes nothing |
| `GET/POST/PUT/DELETE /circuits` | circuit inventory |
| `GET /outages`, `GET /outages.csv` | outage records and export |
| `GET /incidents`, `GET/PATCH /incidents/{id}`, `POST /incidents/{id}/acknowledge\|comments` | ISP incidents |
| `GET /analytics` | incident analytics (up to 365 days; per-circuit availability up to 31 days) |
| `GET /investigate` | correlation verdict with evidence |
| `GET /events`, `GET /collector` | state changes, collector health |
| `GET/POST/DELETE /maintenance`, `GET/PUT /settings` | configuration |

Target create, edit and delete stay on `/api/isp/icmp/targets` (new optional fields: `retries`, `jitter_warn_ms`).
Disabling a target there pauses it through the state machine.

## Migrations

- Alembic `0018_wan_observability`: additive. `isp_links.firewall_id` becomes nullable.
- Alembic `0019_wan_degraded_damping`: additive (`degrade_after`, `clear_after` and streak counters on `icmp_targets`;
  existing targets get 3 / 2).
- ClickHouse migration 11: adds `rtts`, `error_class`, `error`, `attempts`, `sched_delay_ms` and `ingested_at` to
  `icmp_results`.

Both run with the normal `migrate` step (`deploy.sh` does this).

## Known limitations

- Availability needs observations, so per-circuit availability is computed for ranges up to 31 days. Incident
  analytics cover up to 365 days.
- **Degraded state:** damped by `degrade_after` / `clear_after` per target. Degradation episodes open incidents only
  if `degraded_incidents` is enabled; use the sustained latency, loss and jitter rules for alerting.
- **SD-WAN outages:** mirrored every 5 minutes from logs, so they appear with up to 5 minutes' delay. An SD-WAN outage
  that started more than 48 hours before the first sync is not back-filled.
- **Probe vantage point:** probes measure reachability from the SIEM's own network. A SIEM uplink problem shows as many
  simultaneous outages. The investigation panel flags it only when the collector itself reports errors or a stale
  heartbeat.
- **Tests:** automated tests use mocked probes. Behaviour against real ISP circuits is verified on deployment.
