# Wireless monitoring reference

Summary of what is implemented. The detailed MIB registry, rules and analytics are in docs/WIRELESS.md and
docs/WIRELESS_CLIENT_ANALYTICS.md.

## Controllers

| Controller | Source | Status |
|---|---|---|
| Cisco Catalyst 9800 (IOS-XE 17.x) | SNMP: AIRESPACE / CISCO-LWAPP MIBs as implemented by IOS-XE; client traps | Implemented; polled in production |
| Ruckus SmartZone / vSZ / Ruckus One | REST API integrations ([NMS_EXTENSIONS.md](NMS_EXTENSIONS.md) §6) | Implemented; simulated only |
| Juniper Mist | REST API integration | Implemented; simulated only |
| Aruba Central | REST API integration | Implemented; simulated only |
| Aruba controllers (on-premises, without Central) | — | Not implemented |

## What is collected (Catalyst 9800)

- **Controller:** CPU, memory, uptime, HA / redundancy state, AP count, client count, WLAN count. Licensing is not
  collected.
- **AP:**
  - name, IP, model, serial, location (site / building / floor from the controller or an administrator override);
  - controller, status, uptime, firmware;
  - uplink switch port (from the controller's CDP data) and PoE.
- **Radio:**
  - band, channel, channel width, transmit power;
  - noise floor, channel utilisation, interference, retries;
  - clients;
  - RRM neighbours.
- **Client:**
  - MAC, IP, SSID, AP, VLAN, band;
  - RSSI, SNR;
  - authentication state, session duration;
  - roaming (AP changes), connection failures;
  - user name (shown to administrators only).
- **Rogues:** the controller's rogue table, with classification. Rogues broadcasting our SSIDs, classified malicious,
  or seen on the wire raise `wireless_rogue_detected`.

## History (persisted, never reconstructed from current state)

- **Client sessions:** `wireless_client_sessions` (PostgreSQL), opened and closed as clients appear and disappear
  between polls. Precision is the poll interval, or exact when client traps arrive (`precision = controller_trap`).
- **Rollups:** ClickHouse `wireless_client_slots` (30-minute slots) and history events, with 400-day retention:
  - unique clients;
  - 5-minute concurrency;
  - per SSID / AP / site / building / floor.
- **Exact ranges:** the analytics API takes explicit `start` / `end` instants, and the UI builds them from the user's
  time zone (docs/WIRELESS_CLIENT_ANALYTICS.md).
- **Analytics:**
  - clients per SSID / AP / building / floor / site;
  - daily breakdown and hourly trend;
  - peak concurrent clients;
  - channel-utilisation and interference trends;
  - roaming and authentication failures;
  - the client-experience score and the per-floor SLA;
  - seasonal anomaly baselines (`wireless_ssid_clients_anomaly`, `wireless_ap_zero_clients`).

## Device access for wireless

- **Command library:** the Catalyst 9800 platform has `show wireless summary`, `show ap summary`,
  `show wireless client summary`, `show wlan summary` and `show redundancy`.
- **Bulk diagnostics:** "controller health on all WLCs" is a bulk job with the `wireless` and `health` categories.
- **Changes:** WLC configuration changes are not offered (no change procedure for `cisco_wlc9800`).

## Limits

- **Validation:** against MIB-shaped fixtures, plus production polling of the 9800. Per-release behaviour must be
  checked on the Monitoring Health views.
- **Timing:** roaming and disconnection timing has poll granularity (60–120 s) unless client traps are enabled.
- **Not built:** floor maps, gNMI telemetry, on-premises Aruba controllers without Central.
