# Technical debt: SIEM scope, 2026-11-02

The general register (code quality, performance, tooling) is [TECHNICAL_DEBT_REGISTER.md](TECHNICAL_DEBT_REGISTER.md).
This page lists only the debt that limits the SIEM capabilities.

| ID | Area | Debt | Consequence | Plan |
|---|---|---|---|---|
| SD-1 | Detection | Most built-in rules were hand-written Python functions in a 1000-line `alerts/engine.py`, each building its own SQL | New detections need code changes; no shared test harness or performance data per rule | **Started:** declarative YAML rules (`app/detection/`) for new detections. Port existing rules only when they need changes; don't rewrite working rules |
| SD-2 | Schema | The event model is FortiGate-shaped (`event_type`, `devid`, `log_id`, `vdom`) and non-FortiGate sources are mapped onto it | Fields such as process, file hash, URL path or Kerberos ticket have nowhere to go; ECS / OCSF consumers need translation | Keep storage; add an ECS / OCSF alias map for search and export (gap B, P2); add columns additively when a new source needs them |
| SD-3 | Ingestion | Generic sources are matched by sender IP only and parsed by kind; there are no administrator-defined parsers | Every new log format needs a code change | Parser definitions (regex / KV / JSON paths) stored per source (P2) |
| SD-4 | Incidents | The status set (`open / in_progress / resolved / closed`) is narrower than SOC workflows (*investigating, contained, false positive*); there is no priority or tags | Analysts encode state in comments | Additive migration with mapping of old values (roadmap R4) |
| SD-5 | Response | Playbook actions can't change devices. The safe device path (IaC with approvals) isn't reachable from playbooks | Blocking an IP is manual | Wire `block_ip` → IaC address-object plan (approval-gated) (roadmap R7) |
| SD-6 | Scale-out | In-process rate limits and per-process ClickHouse / PostgreSQL pools; one worker process owns all schedulers (sharding only for firewall polling) | Horizontal scaling needs care | Documented limits; no broker until throughput requires it (see roadmap "Broker decision") |
| SD-7 | Flows | No flow collector, so east-west visibility depends on FortiGate traffic logs, which only cover what crosses a firewall | Switch-local lateral movement is invisible | Flow collector (roadmap R5) |
