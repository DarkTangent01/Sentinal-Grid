# Security review: Sentinel NMS device access

Scope: the code added in this release (`app/access`, `app/api/access.py`, the terminal UI, deployment changes), and how
it touches existing code (SSH backup, sessions, products, site scope). Method: source review, threat-by-threat, each
with the test that proves the control.

## Threats and controls

| # | Threat | Control | Evidence |
|---|---|---|---|
| T1 | Gateway used as an SSRF / pivot / port scanner | The host comes only from inventory and passes `validate_address` (IP literal, no loopback / reserved, inside an authorised network). The port comes from a fixed map. There are no host / port parameters. | `test_targets_are_inventory_devices_only` (outside-network device refused, extra request fields ignored, the dial goes only to the device address on port 22) |
| T2 | Unauthorised device access | 13 permissions on every route. Site scope on every device lookup. The WebSocket re-checks cookie, account state, `session_version`, product and permission. A watchdog re-checks every 2 s. | `test_permissions_enforced_on_routes`, `test_terminal_requires_permission_and_idle_timeout`, `test_role_change_revokes_sessions` |
| T3 | Cross-site WebSocket hijacking | Origin must equal the request host (or `ACCESS_ALLOWED_ORIGINS`), plus a one-time ticket (32 random bytes, SHA-256 stored, 30 s, bound to user and session) sent in the first message, not the URL | `test_terminal_session_end_to_end` (wrong origin, wrong ticket, ticket reuse) |
| T4 | Credential disclosure | Fernet at rest. No API returns secrets. Audit details are redacted. Output and command logs are masked. Decryption happens only in the gateway or worker. | `test_vault_never_returns_or_stores_plaintext` |
| T5 | Arbitrary or destructive commands | Diagnostics accept template ids only (checked `≤ LOW_RISK` at import and before sending). The terminal guard blocks above `LOW_RISK`, and always blocks `DESTRUCTIVE`. A refused line can never be submitted later (input is held until a fresh prompt). Change requests refuse destructive lines. | `test_command_risk_classification`, `test_line_guard`, `test_templates_are_read_only_and_platforms_resolve`, terminal e2e |
| T6 | Unapproved configuration change | Four-eyes approval (the requester can never approve). A global off switch (default off). The approved window is enforced. Changes never start from alerts or schedules. Backup before; verify after. | `test_change_workflow` |
| T7 | Audit tampering or repudiation | Append-only, hash-chained `nms_access_audit`. Writes are serialised (per-process lock plus a PostgreSQL advisory lock). Verification via `/audit/verify`. The real user is recorded even with a shared vault account. | `test_audit_chain_detects_tampering`, `test_audit_chain_survives_concurrent_writers` |
| T8 | MITM on device SSH | Host keys are pinned (trust on first use). A changed key refuses before authentication. The same code path serves backup, terminal, diagnostics and changes (`gateway._dial`). | `test_config_backup.py` (host key change), diagnostics test (key pinned) |
| T9 | Resource exhaustion | Session caps (global, per user, per device). Unused tickets expire and give their slot back. Bulk caps (devices, jobs per user, concurrency). Per-command and per-device timeouts. Idle and maximum session timeouts. Input frames capped at 8 kB and WebSocket messages at 1 MB. The service has its own container limits. | `test_session_limits`, bulk test, idle-timeout test |
| T10 | Secrets in recordings | Recording is `commands` by default. `full` is opt-in, masked, capped and retained 90 days. Download needs audit.view and is itself audited. | `test_recording_retention` |
| T11 | Privilege persistence after a role change | A role change bumps `session_version`, which ends REST sessions and open terminals | `test_role_change_revokes_sessions` |
| T12 | Container escape / lateral movement | `access` runs as uid 10001 with a read-only root FS, `cap_drop ALL` and `no-new-privileges`. Its networks are backend, frontend and egress (no `aaa`). Its secrets are the session key and the vault key only. | `test_secret_files.py::test_each_service_mounts_only_the_secrets_it_needs` |
| T13 | Telnet exposes credentials | Off unless `ACCESS_TELNET_ENABLED` and the per-device switch are both set; the UI warns before connecting; sessions and audit are marked `cleartext` | `test_telnet_disabled_by_default_then_guarded` |
| T14 | Console servers as a pivot | Console server address must be in an authorised network; port reached only through a mapping to an inventory device, under that device's RBAC and site scope; host key pinned; same guard and audit | `test_console_session_through_opengear` |
| T15 | NETCONF / RESTCONF writes | Fixed read operations only (checked at import); no edit-config or arbitrary path; secrets masked in replies; HTTPS certificate pinned and checked before credentials are sent | `test_netconf_read_operations`, `test_restconf_read_operations` |
| T16 | Wireless integrations as SSRF | Cloud hosts restricted to the vendors' domains (no IP literals, port 443); SmartZone only to an authorised management address; no redirects followed | `test_integration_url_allowlist`, `test_integration_api_admin_only` |
| T17 | Ansible as arbitrary code execution | Static policy allowlist (no shell / command / file / template / lookups / local or delegated tasks / roles); only the approved SHA-256 runs; second-person approval of versions and of change runs; private 0700 work directory removed after each run; minimal environment; host key checking with Sentinel's pinned keys; separate container with backend + egress networks and the vault key only | `test_playbook_policy_refuses` (11 cases), `test_playbook_library_and_runs`, `test_runner_executes_with_a_private_inventory` |

## Residual risks (accepted or for follow-up)

- **R1: The terminal guard is not a sandbox.** Device-defined aliases, macros or completion can turn an allowed-looking
  line into something else. Mitigation: least-privilege vault accounts and device-side command authorisation (TACACS+).
  Documented in the terminal guide.
- **R2: Shared vault accounts.** Device-side logs show the vault account, not the engineer. The Sentinel audit maps
  each session to the real user. Per-user device credentials are not implemented.
- **R3: Trust on first use.** The first connection to a device accepts its key. Verify fingerprints out of band for
  high-value devices before the first session or backup.
- **R4: Web management.** The audited link opens the device UI directly, so the browser needs network reachability.
  There is no gateway control over that HTTPS session.
- **R5: In-process mode on Kubernetes.** Device sessions share the API pods' resources until a separate Deployment
  exists.
- **R6: Recording mode `full`.** Captures device output (configurations, neighbour data). Masking covers known secret
  patterns, not every possible sensitive value.

- **R7: Ansible policy is static.** A collection module's own behaviour is trusted (for example what `ios_config` sends
  with its options); the policy restricts which modules and arguments can appear, and change runs are approved and
  backed up. Keep the runner's collections pinned.
- **R8: RESTCONF first contact.** The first request to a device accepts its certificate (trust on first use), like SSH.
- **R9: Integration data.** Vendor API responses are trusted as data (masked, bounded in size and pages), never as
  instructions.

## Not changed

Authentication, password policy, CSRF, rate limiting and product boundaries are the existing mechanisms. No existing
permission was widened: accounts without an NMS role keep exactly `nms.device.view`, which is what they had before.
