# Sentinel NMS API reference

All routes need a session cookie. Writes also need the `X-CSRF-Token` header. Every route enforces the NMS product
boundary (`products.py`), and device routes enforce the user's site scope.

## Device access (`/api/nms/access`, served by the access gateway)

| Method & path | Permission | Purpose |
|---|---|---|
| `GET /me` | access.view | Roles, permissions, feature switches, limits |
| `GET /library` | access.view | Platforms (with test status) and diagnostic templates with their risk |
| `POST /classify` `{command}` | access.view | What the gateway would decide for a command (contacts nothing) |
| `GET /devices?q&site&vendor&limit&offset` | access.view | Inventory with access status |
| `GET /devices/{id}` | access.view | Access tab: protocols, credential (name only), SNMP state, actions allowed for the caller, templates, sessions, history |
| `POST /devices/{id}/test` | access.diagnostics | TCP 22 / 443 / 830 reachability and latency, plus the SNMP state |
| `POST /devices/{id}/sessions` `{mode, change_id, cols, rows}` | access.ssh | Opens a pending session; returns `{session_id, ticket, ws_path}` (the ticket is single use, 30 s) |
| `WS /ws` | access.ssh (cookie) + Origin + ticket | Terminal; messages in [SSH_TERMINAL_GUIDE.md](SSH_TERMINAL_GUIDE.md) |
| `POST /devices/{id}/web` | access.https | Audited; returns the device's HTTPS URL |
| `PUT /devices/{id}/platform` `{platform}` | device.manage | Command-library platform override |
| `PUT /devices/{id}/credential` `{ssh_credential_id}` | access.credential.manage | Device credential override |
| `GET /sessions?state&switch_id&username` | access.view | Own sessions; all within scope for audit.view / session.terminate |
| `GET /sessions/{id}` | access.view (own) / audit.view | Session with its command log |
| `GET /sessions/{id}/recording` | audit.view | Masked transcript (audited) |
| `POST /sessions/{id}/terminate` | own, or access.session.terminate | Ends a session |
| `POST /devices/{id}/diagnostics` `{templates, categories}` | access.diagnostics | Runs templates on one device; returns the outputs |
| `POST /bulk` `{device_ids, templates, categories, concurrency, timeout_seconds}` | access.diagnostics + automation.execute | Bulk job (202, `job_id`) |
| `GET /jobs?kind` · `GET /jobs/{id}?full` · `GET /jobs/{id}/results/{switch_id}` | access.diagnostics | Progress and results (owner, or audit.view) |
| `POST /jobs/{id}/cancel` · `GET /jobs/{id}/export` | access.diagnostics | Cancel; text export |
| `GET /vault` · `POST /vault` · `PUT /vault/{id}` · `DELETE /vault/{id}` | access.credential.manage | Credentials (secrets write-only) |
| `POST /vault/{id}/assignments` · `DELETE /vault/assignments/{id}` | access.credential.manage | Group assignment |
| `GET /roles` · `PUT /roles/{user_id}` `{roles}` | administrator | NMS roles (a change revokes the user's sessions) |
| `GET /changes?status&switch_id` · `GET /changes/{id}` | access.view | Change requests |
| `POST /devices/{id}/changes` | access.configuration | New change request |
| `POST /changes/{id}/approve` · `/reject` | configuration.approve (not the requester) | Decision |
| `POST /changes/{id}/execute` | access.configuration (+ `NMS_CONFIG_CHANGES_ENABLED`) | Run an approved change |
| `POST /changes/{id}/rollback` | configuration.approve (+ enabled) | Roll back |
| `POST /changes/{id}/cancel` | requester or approver | Cancel |
| `GET /audit?action&username&switch_id&success&start&end` · `GET /audit/verify` · `GET /audit/export.csv` | access.audit.view | Access audit, chain verification, CSV |
| `GET /health` | none | Container health check |

Permission names in the table omit the `nms.device.` prefix. The full names are in `app/access/rbac.py PERMISSIONS`.

## Extensions ([NMS_EXTENSIONS.md](NMS_EXTENSIONS.md))

| Method & path | Permission | Purpose |
|---|---|---|
| `POST /api/switches/admin/discovery` `{network_id, methods, credential_id?}` | administrator | Discovery with `snmp`, `icmp`, `tcp`, `arp` |
| `GET /api/switches/topology/l3?site=` | NMS | OSPF / BGP / IPsec / ISP edges with source and match |
| `GET /api/nms/access/protocol-ops` | access.view | NETCONF / RESTCONF operation catalogue |
| `POST /api/nms/access/devices/{id}/netconf` · `/restconf` `{operation}` | access.diagnostics | Fixed read-only operation |
| `POST /api/nms/access/devices/{id}/https-cert/accept` | access.credential.manage | Reset the pinned HTTPS certificate |
| `PUT /api/nms/access/devices/{id}/telnet` `{enabled}` | administrator | Per-device Telnet opt-in |
| `POST /api/nms/access/devices/{id}/sessions` `{protocol: ssh / telnet / console, console_port_id?}` | access.ssh | Terminal over SSH, Telnet or a console port |
| `GET · POST /api/nms/access/console-servers` · `PUT · DELETE /{id}` · `POST /{id}/ports` · `DELETE /console-ports/{id}` · `POST /{id}/accept-host-key` | view / device.manage / credential.manage | Console servers and port mapping |
| `GET · POST /api/wireless/integrations` · `PUT · DELETE /{id}` · `POST /{id}/sync` | NMS (read) / administrator | Wireless controller and cloud integrations |
| `GET · POST /api/nms/access/playbooks` · `GET · PUT /{id}` · `POST /validate` · `POST /{id}/approve` · `/retire` | view / automation.execute / configuration.approve | Playbook library |
| `POST /api/nms/access/playbooks/{id}/runs` `{device_ids, mode}` · `GET /runs` · `GET /runs/{id}` · `POST /runs/{id}/approve` · `/reject` · `/cancel` | automation.execute / configuration.approve | Playbook runs |

## Existing NMS APIs (unchanged)

| Prefix | Area | Documentation |
|---|---|---|
| `/api/switches` | Inventory, discovery, interfaces, VLANs, MAC, topology, impact, polls, import / export | docs/SWITCHES.md |
| `/api/snmp` | Vendors, polling health, traps, OID registry, custom OIDs, MIBs, support matrix | docs/SNMP.md |
| `/api/wireless`, `/api/wireless/analytics`, `/api/wireless/rf` | Controllers, APs, clients, WLANs, roaming, rogues, history, RF | docs/WIRELESS.md, WIRELESS_CLIENT_ANALYTICS.md |
| `/api/isp`, `/api/wan` | ISP / WAN / SD-WAN, circuits, incidents | docs/WAN.md |
| `/api/bgp`, `/api/vpn-tunnels`, `/api/fwhealth` | BGP, VPN tunnels, firewall health | docs/NMS.md |
| `/api/nms` | Dashboard, analytics, capacity, anomalies, services, maintenance, dependencies, self-monitoring | docs/NMS_CAPABILITIES.md |
| `/api/nms/config` | Configuration backups and diffs | [CONFIGURATION_MANAGEMENT.md](CONFIGURATION_MANAGEMENT.md) |
| `/api/nms/flows` | Flow analytics | docs/NMS_CAPABILITIES.md §5 |
| `/api/iac`, `/api/tacacs`, `/api/nms/compliance` | FortiGate IaC, TACACS+, network compliance | docs/IAC.md, TACACS.md, NETWORK_COMPLIANCE.md |
