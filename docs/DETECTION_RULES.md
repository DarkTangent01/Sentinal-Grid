# YAML detection rules

The declarative detection engine (`backend/app/detection/`) runs next to the built-in Python rules and the custom
pipeline-query rules. All three share the same alert pipeline: suppression, grouping, auto-resolve, incident
correlation, automation, notifications and per-rule false-positive statistics.

| Where | What |
|---|---|
| `backend/rules/**/*.yml` | Built-in pack: read-only, shipped with the code, seeded as `alert_rules` rows `yml_<id>` |
| `alert_rules.params.yaml` | Custom rules written by administrators (Detections → Rule pack → New YAML rule), with a version history |
| `app/detection/schema.py` | Rule model, field allow-list, operators |
| `app/detection/compiler.py` | Rule → one parameterised ClickHouse query |
| `app/detection/runner.py` | Execution in the alert engine, historical dry run, embedded tests |
| `app/api/yaml_rules.py` | `/api/detections/yaml` |

## Format

```yaml
id: NET-1002                      # LETTERS-digits, unique; key becomes yml_net_1002
name: External port scan against internal hosts
description: What it detects and why it matters.
version: 1                        # must increase on every change of a custom rule
status: enabled                   # enabled | disabled | experimental (seeded disabled)
severity: high                    # informational | low | medium | high | critical
category: network_reconnaissance  # free text, for grouping
log_source:
  category: traffic               # traffic | dns | web | security | system (required: also the partition filter)
  event_type: netdev              # optional exact event_type
  product: fortigate              # documentation only
detection:
  selection:                      # AND of fields; a list of maps = OR of maps
    src_ip: {internal: false}
    dst_ip: {internal: true}
  filter:                         # optional exclusion, same syntax (NOT …)
    action: [deny, block]
  outside_hours:                  # optional: only events outside business hours
    {start: "08:00", end: "20:00", days: [mon, tue, wed, thu, fri], timezone: Asia/Kolkata}
  condition:
    group_by: [src_ip]            # 1-4 fields; one alert per group
    distinct_count: {field: dst_port, threshold: 50}   # or count: 5, or sum: {field: sent_bytes, threshold: 1e9}
    timeframe: 5m                 # 1s … 7d
allowlist:                        # optional: IP fields take CIDRs, other fields exact values
  src_ip: [198.51.100.10/32]
explanation: "{src_ip} probed {metric} ports in {timeframe} (threshold {threshold}): {samples}"
data_sources: [FortiGate traffic logs]
falsepositives: [Authorised scanners]
investigation: [Check the source's reputation]
mitre: {tactic: TA0043, techniques: [T1595]}
tags: [recon]
tests:
  - name: 60 ports probed
    events: [{src_ip: 203.0.113.9, dst_ip: 10.1.1.10, dst_port: {seq: [1, 60]}, action: deny}]
    expect_alerts: 1
    expect_groups: [{src_ip: 203.0.113.9}]
  - name: below threshold
    events: [{src_ip: 203.0.113.9, dst_ip: 10.1.1.10, dst_port: {seq: [1, 30]}}]
    expect_alerts: 0
```

### Values and operators

| Spelling | Meaning |
|---|---|
| `field: value` | equals |
| `field: [a, b]` | one of |
| `field: {op: value}` | operator form; several operators on one field are ANDed |

| Operator | Meaning | Fields |
|---|---|---|
| `eq`, `ne` | equals / differs | any |
| `in`, `not_in` | in / not in a list | any |
| `contains`, `startswith`, `endswith` | case-insensitive text match | text |
| `regex` | RE2 regular expression (300 characters max) | text |
| `gt`, `gte`, `lt`, `lte` | numeric comparison | numeric |
| `cidr`, `not_cidr` | inside / outside any of the listed CIDRs | IP fields |
| `internal` | `true`: inside `INTERNAL_CIDRS`; `false`: a valid IP outside them | IP fields |
| `exists` | non-empty / non-null | any |

**Allowed fields** (the `events` columns):
- **Identity and classification:** category, event_type, event_subtype, log_id, firewall_id, firewall_name, site, devid, vdom, source, severity
- **Addresses and ports:** src_ip, src_port, dst_ip, dst_port, proto, proto_name, src_intf, dst_intf, nat_src_ip, nat_dst_ip
- **Policy and application:** policy_id, policy_name, action, app, app_cat, service
- **Web:** hostname, url, http_method, url_category
- **Volume:** sent_bytes, rcvd_bytes, sent_pkts, rcvd_pkts, duration
- **DNS:** dns_qname, dns_qtype, dns_rcode, dns_qname_len, dns_entropy
- **Content and context:** threat, user, msg, src_country, dst_country, src_mac, src_name, ti_match, ti_category

**Explanation placeholders:** the `group_by` fields, plus `metric`, `threshold`, `events`, `timeframe` and `samples`.

### Safety

A rule can't run arbitrary SQL:
- Field names must be in the allow-list (checked at load and again at compile time).
- Operators come from a fixed table.
- Every value, including regexes, CIDRs and time zones, is a bound query parameter.
- YAML is read with `safe_load`.
- Rules are capped at 64 KB.

`tests/test_detection_yaml.py` covers rejected fields, operators and hostile values.

## Execution

- **Schedule.** The alert engine evaluates each enabled rule every `interval_minutes`. The default is the time frame, between 1 and 60 minutes, and it can be tuned on the rule.
- **Window.** Each run looks back over the time frame, or the interval if that is longer, so consecutive runs leave no gap.
- **Grouping.** Each group that reaches the threshold becomes one alert with group key `<id>:<group values>`. Later runs update the same alert.
- **Alert content.** The alert carries the samples, data sources, false positives, investigation steps, rule version, MITRE mapping, and an Event Explorer filter for the group.
- **Run statistics.** Last run, duration, matches and the last error are stored on the rule row (`params._stats`) and shown in the Rule pack table.
- **Tuning.** Enable / disable, severity and threshold use `PUT /api/alert-rules/{key}`, the same as built-in rules. Tuning survives upgrades of the pack. The rule's `version` and file hash are refreshed from the shipped file on every start.

## Testing

**Embedded tests.** They run the exact production query against the test events, passed inline to ClickHouse through `format(JSONEachRow, …)`. Nothing is written.
- **Event shorthand:**
  - `repeat: N`
  - `{seq: [1, 60]}` for numbers
  - `{ipseq: ["10.1.5.", 1, 30]}` for addresses
  - `at: "-30s"` places an event relative to the evaluation time
  - `now:` sets that time for one test case
- **Coverage:** every shipped rule's tests run in CI (`test_every_pack_rule_passes_its_embedded_tests`).
- **Custom rules:** saving a custom rule requires all of its tests to pass.

**Dry run (historical replay).** `POST /api/detections/yaml/{key}/dry-run?hours=24` (up to 168) buckets the history into fixed windows of the rule's time frame and lists the groups that would have alerted. It is read-only and creates no alerts. Because the live engine uses a sliding window, it can alert slightly more often than a dry run shows.

## API (`/api/detections/yaml`, Sentinel Grid)

| Method | Path | Who |
|---|---|---|
| GET | `` (list), `/{key}` (YAML, metadata, history, run statistics) | Grid users |
| POST | `/validate` (errors or the compiled SQL with parameters), `/test` (unsaved YAML), `/{key}/test`, `/{key}/dry-run?hours=` | Grid users (read-only) |
| POST | `` (create / update a custom rule), `/{key}/rollback/{version}` | administrators, audited |
| DELETE | `/{key}` (custom rules only; built-in rules are disabled instead) | administrators, audited |

## The shipped pack

| Id | Detection | Data source |
|---|---|---|
| NET-1002 | External port scan against internal hosts | FortiGate traffic |
| NET-2001 | Rogue DHCP server (DHCP snooping drop) | Cisco / Ruckus syslog |
| NET-2002 | OSPF adjacency lost | Cisco / Ruckus syslog |
| NET-2003 | BGP session lost (router syslog) | Cisco / Ruckus syslog |
| NET-2004 | HSRP / VRRP gateway failover | Cisco / Ruckus syslog |
| NET-2005 | STP guard blocked a port (BPDU / root / loop) | Cisco / Ruckus syslog |
| NET-2006 | Unauthorized device (port security) | Cisco / Ruckus syslog |
| NET-2007 | Network device configuration changed | Cisco / Ruckus syslog |
| NET-2008 | Repeated login failures on network devices | Cisco / Ruckus syslog |
| NET-2009 | Rogue access point | Catalyst 9800 syslog |
| NET-3001 | Unexpected protocol allowed to the internet (**experimental**: seeded disabled; one alert per host) | FortiGate traffic |
| NET-3002 | Large outbound transfer outside business hours (Asia/Kolkata by default) | FortiGate traffic |
| NET-3003 | Abnormal east-west fan-out on administrative ports | FortiGate traffic |

**Experimental rules.** NET-3001 ships disabled. In demo traffic it matched 87 host / port pairs in one evaluation, and how often it fires depends on each site's policies. Dry-run it over 24 h or 7 days against your own traffic, allowlist the approved destinations, then enable it.

**Enabling the network-device rules (NET-2xxx).** Point the switches, routers and controller at the syslog listener. Then add a **Log source** of kind **Network device** with their source addresses (Log Sources page). Cisco messages are also recognised on a *Plain syslog* source.

**Validation status.** The parser and rules are tested against labelled synthetic messages written in each vendor's documented format. The Catalyst 9800 rogue messages differ between releases, so NET-2009 matches any controller message that mentions a rogue AP. Check the messages against a real device after enabling.
