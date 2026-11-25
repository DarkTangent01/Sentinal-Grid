# Performance benchmarks: Sentinel NMS

**Every number here is from simulated devices** on a development laptop (Apple Silicon, single Python process, SQLite
and embedded ClickHouse instead of PostgreSQL and the ClickHouse server). No real or lab network hardware was used.
The figures show the software's own cost and how it scales; they are not a production capacity guarantee.

Script: `backend/tools/nms_bench.py`, run from `backend/`. It is not deployed. It uses the test fixtures
(`tests/snmp_sim.py`, `tests/switch_fixtures.py`) and a local asyncssh device simulator.

## 1. Polling engine (in-memory SNMP agents, no network)

- **Profile:** each device is a Cisco C9300 fixture: 52 interfaces, VLANs, MAC table, STP, PoE, LLDP / CDP, stack and
  environment.
- **Run:** `poller.run_due` with `SWITCH_MAX_CONCURRENT_POLLS=16`, two cycles (the second computes rates).

| Devices | Cycle 1 (first poll) | Cycle 2 (with rates) | Engine time per device | Failed | Peak RSS |
|---|---|---|---|---|---|
| 100 | 3.4 s | 2.2 s | 22.0 ms | 0 | 266 MB |
| 500 | 14.8 s | 10.5 s | 21.0 ms | 0 | 279 MB |
| 1,000 | 28.4 s | 21.3 s | 21.3 ms | 0 | 363 MB |
| 2,000 | 56.3 s | 42.4 s | 21.2 ms | 0 | 466 MB |

- **Scaling:** the engine's own processing scales linearly at about 21 ms per device per cycle.
- **Real networks:** SNMP round-trips dominate. A device answering a full poll in about 3 s on a LAN, with 16 slots,
  gives about 375 s for 2,000 devices per poller process. Meeting a 60 s interval at that size therefore needs about 6–7
  poller replicas (`POLLER_REPLICAS`), or longer group intervals for the heavy tables.
- **Not demonstrated:** 2,000 real devices at 60 s. That has not been shown and is not claimed.
- **Memory:** peak RSS grows with the fixture data held for the run (all clients in memory at once). The production
  poller streams devices through its slots.

## 2. Bulk diagnostics through the gateway (asyncssh device simulator)

Each device: SSH login (ed25519 host key, password auth), then two exec commands (`show version`,
`show processes cpu sorted`), each with 50 ms simulated device latency. The device simulator runs in the same process
as the gateway, so it consumes part of the measured CPU.

| Devices | Concurrency | Wall time | Devices / s | p50 | p95 | p99 | Failed | Peak RSS |
|---|---|---|---|---|---|---|---|---|
| 100 | 10 | 1.9 s | 53.8 | 127 ms | 203 ms | 216 ms | 0 | 180 MB |
| 500 | 10 | 9.0 s | 55.5 | 127 ms | 174 ms | 207 ms | 0 | 184 MB |
| 500 | 50 | 9.5 s | 52.8 | 141 ms | 491 ms | 999 ms | 0 | 197 MB |
| 1,000 | 50 | 20.4 s | 49.1 | 142 ms | 344 ms | 1,537 ms | 0 | 204 MB |
| 2,000 | 50 | 44.0 s | 45.5 | 143 ms | 298 ms | 743 ms | 0 | 207 MB |

- **Ceiling:** throughput levels off at about 50 devices/s whatever the concurrency. The limit is CPU in one process:
  SSH key exchange and authentication on both sides, plus per-device database writes. Raising concurrency beyond 10
  only adds tail latency.
- **Real devices:** with real devices, latency and login time dominate, and higher concurrency helps.
- **Memory:** stays flat, at about 200 MB for 2,000 devices.

## 3. Concurrent terminal sessions

N sessions opened at once through the full WebSocket handler (ticket check, SSH connect, PTY), then one command each.

| Sessions | Connected | All connected after | Command echo p50 / p95 | Memory per session |
|---|---|---|---|---|
| 10 | 10 | 0.3 s | 5 / 5 ms | 0.3 MB |
| 25 | 25 | 0.8 s | 10 / 10 ms | 0.6 MB |
| 50 | 50 | 1.4 s | 20 / 20 ms | 0.5 MB |
| 100 | 100 | 2.7 s | 38 / 38 ms | 0.5 MB |

- **Default cap:** 50 sessions, which needs about 25–30 MB of session memory. The `access` service limit of 512 MB
  leaves wide headroom.
- **Connect time:** the time to connect all sessions grows linearly because SSH handshakes are CPU-bound in one
  process.

## 4. Command classification

| Operation | Throughput |
|---|---|
| `classify()` | about 500,000 commands / s |
| `LineGuard.feed()` | about 234,000 lines / s |

Neither is a bottleneck.

## 5. Existing measurements (unchanged)

API and database benchmarks for 300 switches × 48 interfaces are in docs/PERFORMANCE_BENCHMARKS.md. Ingest and poller
remediation work is in docs/performance/.

## 6. Not measured

- Real or lab devices at any scale.
- High-volume trap / event processing for NMS: the trap receiver's own tests cover correctness, not throughput.
- Large wireless client populations: covered by earlier work in docs/WIRELESS_CLIENT_ANALYTICS.md §7, not re-run.
- Historical reporting at 2,000 devices.
