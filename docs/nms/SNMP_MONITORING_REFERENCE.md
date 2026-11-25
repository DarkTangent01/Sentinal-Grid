# SNMP monitoring reference

Summary of the polling engine as implemented. The full detail is in docs/SNMP.md and docs/SWITCHES.md, and this
document does not repeat them.

## Versions and security

| Version | Status |
|---|---|
| SNMPv3 | Default. USM auth MD5 / SHA / SHA-224 / 256 / 384 / 512, priv DES / 3DES / AES-128 / 192 / 256 (default SHA + AES-128). Secrets are Fernet-encrypted (`switch_credentials`). |
| SNMPv2c | Refused unless `SWITCH_ALLOW_SNMPV2C=true`, because the community travels in clear text |
| SNMPv1 | Not polled: no 64-bit counters. v1 traps are accepted by the trap receiver. |

- **Allowlist:** every poll target must be an IP literal inside an authorised management network (`switch_networks`).
  That is the same `validate_address` the access gateway uses.

## Engine

- **Scheduling:**
  - leases per device (`lease_until`), so poller replicas never poll the same device;
  - per-group intervals;
  - backoff for failing devices (`backoff_until`, exponential with a cap);
  - wireless controllers' large tables run as a separate job with their own lease;
  - concurrency is bounded by `SWITCH_MAX_CONCURRENT_POLLS` (16 per process);
  - poll start times drift naturally (each poll is stamped when it starts), so cycles do not stay in lockstep.
- **Timeouts:**
  - per request: the device's `timeout_ms` and `retries`;
  - per group;
  - per whole poll: `SWITCH_POLL_TIMEOUT_SECONDS` and the WLC variant.
- **Isolation:** one slow device holds one slot.
- **Self-monitoring:** event-loop lag, polls in flight, loop durations, freshness SLOs and `nms_self_slo_breach`
  (docs/NMS_CAPABILITIES.md §7).

## Interface counters (`switches/rates.py`)

- **Rates:** `ifHCInOctets` / `ifHCOutOctets` (64-bit) when the device has them, otherwise 32-bit with wrap correction.
  Rates are always delta / elapsed between two valid samples.
- **When a delta is refused:**
  - a reboot (`sysUpTime` went backwards) or a change in `ifCounterDiscontinuityTime`;
  - ifIndex renumbering;
  - a 64-bit decrease (a reset);
  - a 32-bit decrease beyond a plausible wrap;
  - a rate above 1.5 × speed.

  A refused delta records no rate for that interval; it never produces a false spike.
- **Data gaps:** flagged (`GAP`), so threshold alerts ignore them.
- **Collected per interface:**
  - admin / oper status, speed and `ifHighSpeed`, duplex (EtherLike-MIB);
  - in / out octets and packets;
  - errors, discards, CRC / FCS;
  - `ifLastChange`;
  - flaps (oper transitions between polls).
- **Derived:**
  - utilisation in % of speed;
  - top-N by bandwidth and by errors;
  - availability;
  - hourly / daily rollups (ClickHouse `switch_if_hourly` …) for history and capacity trends;
  - 95th percentile and linear forecast (`nms/analytics.py`).
- **Interface types:** physical, LAG (ifType 161, `collect_lacp` with member state), VLAN interfaces, loopbacks and
  tunnels (virtual types), trunk / access from Q-BRIDGE and vendor VLAN tables.

## Device health

- CPU, memory, temperature, fans, PSUs;
- stack members, PoE budget and per-port PoE;
- STP, routing (BGP4 / OSPF peers), storage;
- vendor alarms (HA sync, IPsec down, SD-WAN dead, Junos red / yellow alarms).

Coverage is reported per metric and per device: supported, unsupported or not configured.

## Traps

The `traps` service:
- SNMPv3 traps authenticated by `engine_id`; v2c is optional;
- link up / down, config-change (`ciscoConfigManEvent`, which triggers a configuration backup), BGP, OSPF, WLC client
  and AP traps;
- normalised into ClickHouse `snmp_traps` with their raw varbinds.

## Tested

Fixtures in `tests/switch_fixtures.py`, `tests/wireless_fixtures.py` and `tests/snmp_sim.py`:
- an in-memory agent;
- a real UDP agent with SNMPv3 auth and priv.

Test files: `test_switches.py`, `test_snmp.py`, `test_wireless*.py`.

**Scale:** see [PERFORMANCE_BENCHMARKS.md](PERFORMANCE_BENCHMARKS.md) for the polling engine measured with in-memory
agents at 100 to 2,000 devices.
