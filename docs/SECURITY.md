# Security hardening checklist

## Implemented in the application
- [x] Argon2id password hashing; minimum 12 characters; account lockout (5 failures → 15 min); login rate limit (app and nginx).
- [x] Session JWT in an `HttpOnly`, `Secure`, `SameSite=Strict` cookie; CSRF double-submit (`X-CSRF-Token` must match a claim inside the signed token, constant-time compare) on all state-changing requests.
- [x] Server-side session revocation: logout, password change, and admin changes to a user (role, active flag, password reset) bump `users.session_version`, which invalidates every outstanding JWT of that user. Login runs a dummy Argon2 check for unknown usernames so response time does not reveal valid accounts.
- [x] RBAC: `analyst` is read-only (it can triage alert status and notes); `admin` manages firewalls, rules, retention, users and suppressions.
- [x] FortiGate API tokens encrypted with Fernet (AES-128-CBC + HMAC) using `TOKEN_ENCRYPTION_KEY` from the environment; never returned by the API; redacted from logs; sent only as an `Authorization` header (never in a URL).
- [x] FortiGate TLS certificates always verified (system CA store or per-device or global CA bundle). The UI and API offer no "disable verification" switch.
- [x] The client implements only HTTP GET: the SIEM cannot change firewall configuration. Hardening plans are exported as CLI text for manual, reviewed application; plan names and values are validated so they cannot inject extra CLI commands.
- [x] Parameterized ClickHouse queries; sort columns and dimensions allow-listed; Pydantic validation of all inputs (IP/CIDR, ports, enums, lengths).
- [x] Audit log for logins, user, firewall and rule changes, Test Connection, suppressions, retention changes and CSV exports.
- [x] Security headers (CSP, HSTS, X-Frame-Options DENY, nosniff, no-referrer) on the SPA (`frontend/security_headers.inc`, included in every nginx location) and on API responses; OpenAPI schema and docs disabled in production.
- [x] CSV exports (events, compliance) neutralise spreadsheet formula injection (`= + - @`, tab, CR, also after leading spaces).
- [x] Outbound SSRF guard (`app/netguard.py`) for the FortiGate API, webhooks, SMTP and threat-intel feeds, including every redirect hop: loopback, link-local/cloud metadata, reserved ranges and this stack's container names are refused; private networks stay allowed. `OUTBOUND_ALLOWED_HOSTS` lists exceptions.
- [x] Changing a firewall's host or port requires re-entering its API token, so a stored token cannot be redirected to another address.
- [x] Syslog attribution: a line naming a firewall (`devid`/`devname`) is accepted only from that firewall's host, `syslog_source_ips`, or the addresses its host name resolves to (`SYSLOG_TRUST_DEVICE_FIELDS=false`). TCP syslog has an idle timeout and a session cap.
- [x] Event queries reject custom time ranges wider than `MAX_QUERY_RANGE_DAYS` (default 92).
- [x] Notification secrets (webhook URLs, SMTP passwords, HMAC keys) are Fernet-encrypted and never returned by the API; webhooks can be HMAC-signed.
- [x] The query language compiles to parameterized SQL with an allow-listed field set (no user text reaches SQL).
- [x] Threat-intel feeds: HTTPS only, size-capped, parsed as text; private/reserved address space is never treated as an IOC.
- [x] Report HTML is served with `Content-Security-Policy: default-src 'none'` (no scripts).
- [x] Containers run as non-root (UID 10001) with all Linux capabilities dropped and `no-new-privileges`; databases are not published to the host; web and syslog ports bind to 127.0.0.1 unless `WEB_BIND_IP`/`SYSLOG_BIND_IP` name an interface.

## Deployment checklist
- [ ] Deploy on a management or security network segment. Set `WEB_BIND_IP`/`SYSLOG_BIND_IP` to that interface's address (they default to 127.0.0.1), and restrict 443/tcp to SOC networks and 514 to FortiGate source addresses with the host firewall.
- [ ] For each firewall whose syslog arrives from an address other than its management `host` (NAT, a log relay or FortiAnalyzer forwarding), list that address in `syslog_source_ips`. Otherwise its logs are counted as `source_mismatch` and dropped.
- [ ] Replace the self-signed certificate with one from your internal CA.
- [ ] Run `scripts/gen-secrets.sh`; keep `.env` mode 600; store `TOKEN_ENCRYPTION_KEY` in a vault, separate from backups.
- [ ] Remove `BOOTSTRAP_ADMIN_PASSWORD` from `.env` after the first login, then change the admin password.
- [ ] On every FortiGate, create a dedicated **REST API admin** with a read-only access profile and **trusted hosts** limited to the SIEM IP (see README). Never use a super_admin token.
- [ ] Never expose the FortiGate management interface (HTTPS/SSH) to the internet; allow it only from management networks.
- [ ] Prefer `mode reliable` (TCP) syslog. Syslog is cleartext: keep it on a trusted network, or wrap it with TLS (FortiGate `enc-algorithm` plus an stunnel/rsyslog TLS front end).
- [ ] Rotate API tokens periodically (Firewalls → Edit → API token) and after staff changes.
- [ ] Ship container logs to central logging and alert on `syslog counters` showing `unknown_device`, `source_mismatch` or `parse_errors` growth.
- [ ] Egress-filter the backend containers to FortiGate management networks, the TI feed hosts and the notification endpoints. The SSRF guard checks DNS before connecting but cannot fully prevent DNS rebinding.
- [ ] Schedule `scripts/backup.sh` and test `scripts/restore.sh` regularly.

See `docs/SECURITY_AUDIT_REPORT.md` for the latest audit, its findings and the open items.
