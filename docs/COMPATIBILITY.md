# FortiOS compatibility and data-source matrix

> **Verification status:** this build was tested with sanitized fixture logs and mocked API responses only.
> No live FortiGate was available, so **no live integration is claimed**. Run `pytest -m live` (see README)
> and the in-app **Test Connection** against your devices.

## FortiOS versions

| FortiOS | REST monitor endpoints | Syslog `key=value` parsing | Status in app |
|---|---|---|---|
| 7.6.x | expected (same `/api/v2` layout) | yes | `documented` |
| 7.4.x | yes | yes (fixtures modelled on 7.4) | `documented` |
| 7.2.x | yes | yes | `documented` |
| 7.0.x | yes | yes | `documented` |
| 6.4.x | mostly; `eventtime` may be seconds or absent | yes (falls back to `date`+`time`+`tz`) | `best-effort` |
| ≤ 6.2 | not targeted | probably | `untested` |

Detected version and per-endpoint capability (`supported`, `forbidden`, `not_found`) are stored per device and shown on the Firewalls page.

## Event types and where they come from

| Event type | Primary source | Alternative | Notes |
|---|---|---|---|
| Forward traffic (allow/deny/close) | Syslog `type=traffic subtype=forward` | API `log/{dev}/traffic/forward` (best effort) | Needs `logtraffic all` (or `utm`) on policies; denies need implicit-deny logging enabled. |
| Local-in/out traffic | Syslog `subtype=local` | API `traffic/local` | Optional. |
| DNS queries | Syslog `type=utm subtype=dns` | API `log/{dev}/dns` | Needs a DNS-filter profile with `log-all-domain enable`. Not present in traffic logs. |
| Web / URL filtering | Syslog `type=utm subtype=webfilter` | API `log/{dev}/webfilter` | `url` is often path-only; `log-all-url enable` logs allowed URLs too. |
| IPS | Syslog `subtype=ips` | API `log/{dev}/ips` | Severity taken from `severity`. |
| Antivirus | Syslog `subtype=virus` | API `log/{dev}/virus` | |
| Application control | Syslog `subtype=app-ctrl` | API `log/{dev}/app-ctrl` | `app` also appears on traffic logs when application control is enabled. |
| Admin login, config changes | Syslog `type=event subtype=system` | API `log/{dev}/event/system` | Config-change rule uses logids 0100044544–0100044547 (configurable). |
| VPN / IPsec | Syslog `type=event subtype=vpn` | API `event/vpn` | Stored as category `system`. |
| System health (CPU, memory, sessions) | REST `monitor/system/resource/usage` | — | Polled; stored in `device_metrics`. |
| Interfaces and link state | REST `monitor/system/interface` | — | Polled snapshot. |
| Identity and version | REST `monitor/system/status` | — | Test Connection and every poll. |
| Policy names | Syslog `policyname` | REST `cmdb/firewall/policy` (read-only) | |
| Policy configuration + order | REST `cmdb/firewall/policy` | — | Collected every 15 min; changes (modified, reordered, deleted, ID reused) tracked. |
| Policy hit counters | REST `monitor/firewall/policy` (`hit_count`, `bytes`, `packets`, `first_used`, `last_used`) | Traffic-log matches | Field availability varies by version/profile; parsed defensively, missing fields = "Not available". Counters reset on reboot or clear; deltas handle this. |
| Current sessions | REST `monitor/firewall/session` | — | Probed only; **never** stored as history. |
| FortiAnalyzer | Forward FortiAnalyzer logs to this syslog receiver, or set the API log device to `fortianalyzer` | — | No native FortiAnalyzer JSON-RPC connector in this release. |

Every event records its `source` (`syslog`, `api_log` or `demo`). Each firewall shows its last successful API poll and, separately, the last ingested log per source.
