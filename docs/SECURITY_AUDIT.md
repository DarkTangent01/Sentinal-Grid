# Security audit: SIEM scope, 2026-11-02

This audit adds a SIEM-capability lens to the earlier reviews, which still apply and are not repeated here:
- [SECURITY_REVIEW.md](SECURITY_REVIEW.md): modernization pass
- [SECURITY_AUDIT_REPORT.md](SECURITY_AUDIT_REPORT.md): application audit
- [SECURITY.md](SECURITY.md): hardening checklist

Each finding gives the location, the issue, its impact, and the fix or plan.

## Controls verified in code

| Control | Evidence |
|---|---|
| Password storage | Argon2 (`app/security.py`) |
| Session / CSRF | signed HttpOnly cookie + CSRF header on state-changing calls (`app/api/deps.py`, `src/lib/api.ts`) |
| Brute force | login limiter (`app/api/auth.py:38`), lockout (`locked_until`) |
| API rate limit | per-user limiter (`app/api/deps.py:69`); stricter limiters on SNMP / IaC / TACACS+ actions |
| Authorization | admin / analyst, product access on every prefix (route-classification test), NMS site scope, IaC and TACACS+ roles |
| API docs | `/api/docs` and `openapi.json` disabled when `ENVIRONMENT=production` (`app/main.py:45`) |
| Injection | parameterised ClickHouse / SQLAlchemy queries; query-language compiler emits parameters (`analytics/ql.py`, `pipeline.py`); CLI generation validated |
| XSS | React escaping. The only `dangerouslySetInnerHTML` (`pages/iac/Studio.tsx:49`) renders `highlight()`, which escapes input before adding markup |
| Secrets | firewall tokens and SNMP keys encrypted (`TOKEN_ENCRYPTION_KEY`), never returned or logged |
| SSRF | outbound guard (`app/netguard.py`), `OUTBOUND_ALLOWED_HOSTS` |
| Untrusted syslog | unknown senders dropped (`SYSLOG_ALLOW_UNKNOWN_DEVICES=false`); device-supplied identity fields not trusted (`SYSLOG_TRUST_DEVICE_FIELDS=false`) |
| Containers | non-root uid 10001, `no-new-privileges`, resource limits, loopback-bound listeners by default |

## Findings

| ID | Severity | Location | Issue | Impact | Fix / status |
|---|---|---|---|---|---|
| SA-1 | Medium | `deploy/ingress/rsyslog.conf:20-26` | Syslog is accepted over UDP / TCP without TLS; the sender is identified only by source IP | A host on the log network can spoof a registered source's IP (UDP) or read logs in transit, injecting false events or hiding real ones | Roadmap R2: rsyslog `gtls` listener on 6514 with a CA-signed certificate (optional client certificates). Until then, keep `SYSLOG_BIND_IP` on a dedicated management interface and filter port 514 to known senders at the host firewall |
| SA-2 | Low | `app/security.py` limiter used by `auth.py:38`, `deps.py:69` | Rate-limit counters are in-process memory | With 2 uvicorn workers, the effective limit is double the setting, and counters reset on restart | Accepted for a single-host deployment; move counters to PostgreSQL (or Redis if it is introduced) before scaling out (roadmap R9) |
| SA-3 | Medium | `app/products.py:site_allowed`, Grid APIs | NMS site scope does not apply to Grid events, alerts or incidents | An analyst limited to one site in NMS who also has Grid access can read every site's security events | Documented; site scope for Grid (filter on `events.site`, `alerts.sites`) is roadmap R8. Until then, give site-scoped analysts NMS access only |
| SA-4 | Medium (design) | new YAML detection engine | Rule files are compiled to ClickHouse SQL; an unsafe compiler would allow SQL injection through rule content | Rule authors could read or alter data | **Fixed by design in this pass:** field names are checked against an allow-list of event columns, operators against a fixed set, and every value is passed as a bound parameter; tests cover rejected fields, operators and injection strings (`tests/test_detection_yaml.py`) |
| SA-5 | Low | `app/ingest/generic.py:plain` | Plain syslog lines are stored verbatim (up to 1000 chars of `msg`, full `raw`) | Devices that log passwords in command lines (for example `username x password y` in a Cisco config-change message) put secrets into the SIEM | **Fixed in this pass** for the network-device parser: `password`, `secret`, `key`, `community` arguments in config-change and command messages are masked before storage (`app/ingest/netdev.py:redact`). Other generic sources: roadmap R3 |
| SA-6 | Info | — | Single-tenant data model | Not a vulnerability for one organisation; multi-tenancy would need `tenant_id` on events, alerts and incidents | Roadmap P3 |

## Regression tests added in this pass

- `tests/test_detection_yaml.py`
  - `test_compiler_rejects_unknown_fields_and_operators`
  - `test_compiler_binds_values_as_parameters`
- `tests/test_netdev_parser.py`
  - `test_config_change_secrets_are_redacted`
