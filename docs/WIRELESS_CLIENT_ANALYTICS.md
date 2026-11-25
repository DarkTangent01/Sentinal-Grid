# Wireless client history and daily SSID / AP analytics

Sentinel NMS → Wireless Analysis → **WLAN / SSID**: daily client connection analysis, access point client analytics,
roaming analysis. Client drawer (Wireless Clients): **Connection history**.

## 1. What the controller provides, and what that means for the numbers

Investigated in the existing Cisco 9800 / AireOS integration (`app/wireless/collect.py`, `app/snmp_traps.py`):

| Source | Available | Used for |
|---|---|---|
| Client table (`cldcClient*`, `bsnMobileStation*`), read by the client poll | yes, every 300 s by default (`wireless_client` group) | observed clients, concurrency, AP / SSID / band / VLAN / IP |
| `cldcClientUpTime`: seconds since the client associated | yes | the session's real start, and reconnects between two polls |
| Association / disassociation / roam **events** from the controller | **no**: no streaming telemetry, and the trap receiver does not handle client traps. Enabling them would change the controller's configuration, which this product never does | — |
| Authentication-failure records | **no** (not in the polled MIBs) | not reported; the UI does not show a count |
| Disconnect reason | the last reason code the controller reported for the client | session `disconnect_reason` |

So:
- **Unique clients:** distinct MACs the controller listed in the period. Exact for the clients that were listed in at
  least one poll. A client connected for less than one poll interval can be missed.
- **Sessions:** one per association.
  - **Start:** the controller's association time (`now − cldcClientUpTime`, `start_source = controller`), or the first
    poll that listed the client when the controller does not report the timer (`observed`).
  - **Ends:** when a complete client table no longer lists the client (`ended_at` = the last poll that listed it, so
    the real disconnect lies before the next poll), when the controller reports a newer association (a reconnect
    between polls), or when the client moves to another SSID.
  - **Roams:** a roam stays the same session.
  - **Never invented:** a sampled observation is never counted as a session.
- **Peak / average / minimum concurrent:**
  - **Basis:** clients listed per 5-minute bucket.
  - **Average:** taken over the buckets in which a client table was actually read. A collection gap is reported as a
    gap (`coverage`, `polled_buckets`), never as zero.
- **Roams and band changes:** detected between two polls; their time is the poll time.

## 2. Architecture

```
poller (wireless job, every client poll)
  store.persist ──► wireless_clients (PG, current state)            existing
              ├──► wireless_client_samples (CH, per-poll snapshot)  existing, 14 days
              ├──► history.track ──► wireless_client_sessions (PG)  new: one row per association
              │                 └──► wireless_client_events (CH)    new: connect / disconnect / roam / band_change / ssid_change
worker (core, every 5 min): history.run_aggregation
              ├──► wireless_client_slots (CH, 30-min rollup)        new: unique-client sets + clients per 5-min bucket
              └──► expire sessions not listed for a day
api /api/wireless/analytics/* ──► reads slots + events (CH), sessions (PG); never raw snapshots per request
```

- **Rollup grain:**
  - 30-minute slots: day boundaries are exact in every whole- and half-hour timezone (IST included).
  - Quarter-hour zones are rounded to 30 minutes, and the API says so.
- **`clients`:** an `AggregateFunction(uniqExact)` state, so unique counts merge exactly across slots, days, weeks,
  APs, SSIDs and bands.
- **`conc`:** a `sumMap` of {5-minute bucket: clients}. Each client is counted once per bucket, on the AP / SSID /
  band where it was last seen, so any filter's concurrency is exact.
- **Rebuilds:**
  - The aggregation job rebuilds the newest slots each run (`ReplacingMergeTree(version)`), so repeating it is
    idempotent.
  - Its first run backfills every snapshot still kept (14 days).

## 3. Database changes

| Store | Change | Migration |
|---|---|---|
| PostgreSQL | table `wireless_client_sessions` (indexes: mac; wlc + mac + start; start; wlc + end) | `0029_wireless_client_sessions` (additive) |
| PostgreSQL | `wireless_clients.session_id` (nullable) | `0029` |
| ClickHouse | `wireless_client_events`: ReplacingMergeTree, `ORDER BY (wlc_id, kind, ts, mac)`, monthly partitions, TTL 400 days | 18 |
| ClickHouse | `wireless_client_slots`: ReplacingMergeTree(version), `ORDER BY (slot, wlc_id, ssid, ap_id, band)`, TTL 400 days | 18 |

- **Retention:**
  - snapshots 14 days (unchanged);
  - events and slots 400 days;
  - sessions 400 days after they end (`WIRELESS_SESSION_RETENTION_DAYS`).
- **Deduplication:**
  - a repeated poll changes nothing (tested);
  - a repeated event insert collapses in the ReplacingMergeTree.

## 4. API (`/api/wireless/analytics`, NMS product, any signed-in role)

Common filters:
- `start_date`, `end_date`: calendar days in the user's display timezone, inclusive, at most 400 days;
- `controller_id`, `site`, `ssid`, `ap_id` / `ap_name`, `frequency_band` (`2.4`, `5`, `6`).

| Endpoint | Returns |
|---|---|
| `GET /filters` | controllers, sites, SSIDs, APs, bands, the user's timezone |
| `GET /ssid/daily` | per period (`period=day\|week\|month`) and SSID: unique clients, sessions, peak, average, plus coverage. Takes `sort`, `order`, `page`, `page_size` and `format=csv` |
| `GET /ap/daily` | per period, AP (and SSID with `by_ssid=true`): unique clients, AP sessions (associations on the AP + roams onto it), peak, average. Same table options and CSV |
| `GET /hourly` | per hour, for the top SSIDs / APs (`group`): unique, average / peak / minimum concurrent; the 24-hour profile and peak hour |
| `GET /rankings` | top APs by unique clients, peak, average load, disconnections, roams; SSIDs by unique, peak, average, sessions |
| `GET /ap/distribution` | unique clients per AP, overall and per band |
| `GET /roaming` | roams per day, top AP → AP transitions, roams by hour, most-roaming clients |
| `GET /clients/{mac}/history` | the client's sessions (paged) and association changes |

Behaviour:
- **Query shape:** aggregation runs in ClickHouse (`uniqExactMerge`, `sumMapMerge`, window `count()` for paging), and
  sorting is a whitelist.
- **Caching:** responses are cached for 60 s per filter set.

## 5. Frontend

- **WLAN / SSID tab** (`pages/wireless/ClientAnalytics.tsx`): one filter bar drives every section.
  - **Filters:** Daily / Weekly / Monthly view, date range, site, controller, SSID, AP, band.
  - **Sections:**
    - daily clients per SSID (metric selector; click to drill into an SSID);
    - SSID breakdown table (sortable, paged, CSV);
    - hourly clients and 24-hour pattern;
    - clients per AP;
    - AP breakdown (sortable, paged, CSV);
    - AP ranking;
    - band distribution;
    - roaming analysis.
- **Client drawer:** connection history: sessions with start / end, duration, SSID, band, AP path, roams and end reason.
- **Data handling:** react-query with a 60-s stale time and previous data kept while refetching. Chart options are
  memoised.
- **Gaps:** shown as gaps; days without readings are flagged.

## 6. Tests

| Suite | Covers |
|---|---|
| `backend/tests/test_wireless_history.py` (embedded ClickHouse, the real persistence path) | Scenarios 1–10: several clients on one SSID; reconnects; roaming (not a new client or session); one AP with two SSIDs; two controllers on two sites (site filter); disconnect without an event; controller restart; collection gaps (coverage, average over readings only); duplicate polls; band changes; SSID changes. Also: IST vs UTC day attribution; weekly / monthly counting a client once; hourly profile; rollup idempotence; expiry; API filters, CSV, access control and validation |
| `frontend/src/pages/wireless/analyticsModel.test.ts` | timezone days, parameters, pivots that keep gaps as gaps, period labels |

Results: backend full suite 536 passed; frontend type check clean, 45 tests passed, production build OK.

A local UI check was also run: the real API on SQLite + embedded ClickHouse with 7 days of synthetic polls, all
sections rendered and the 24-hour pattern was in IST.

## 7. Performance

- **Per poll:**
  - session rows are written only on change (association, end, roam, band, SSID);
  - continuing clients cost nothing extra;
  - sessions are loaded only for clients that changed.
- **Rollup:** the aggregation job reads only the newest slots (about 90 minutes of snapshots) every 5 minutes.
  `aggregate()` takes one statement per day of backfill.
- **Pages:** read 30-minute rollups, not snapshots. A 30-day AP × SSID table for 1,000 APs merges about 1,000 × SSIDs ×
  bands × 1,440 rollup rows inside ClickHouse.

## 8. Deployment

```bash
./scripts/deploy.sh --apply      # migrate runs PostgreSQL 0029 and ClickHouse 18; both additive
```

- **First worker start:** the rollup backfills the snapshots still kept (up to 14 days). Sessions start with the first
  client poll after the deploy, using the controller's association time for clients already connected.
- **Settings:**
  - `WIRELESS_SESSION_RETENTION_DAYS` (400);
  - `WIRELESS_ANALYTICS_INTERVAL_SECONDS` (300).
- **Rollback:** redeploy the previous commit. The new tables are unused by older code.

## 9. Remaining limitations

- **History start:** sessions, events and roams begin at deployment. Before that only 14 days of snapshots exist,
  which give unique and concurrent clients, not sessions.
- **Resolution:** follows the client poll interval (300 s for the `wireless_client` group). Shorter visits can be
  missed, and disconnect times are bounded by the next poll. A shorter interval per controller (`group_intervals`)
  improves this at a CPU cost in the poller.
- **No authentication failures, and no exact disassociation times:** they would need controller-side telemetry
  (streaming telemetry or client traps), a configuration change on the controller.
- **Reconnect detection needs `cldcClientUpTime`:** for AireOS clients reported only through `bsnMobileStation*`, a
  reconnect inside one poll interval is not visible.
