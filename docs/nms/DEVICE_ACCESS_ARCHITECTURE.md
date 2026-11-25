# Device Access Gateway: architecture

Code:
- `backend/app/access/`;
- API in `backend/app/api/access.py`;
- UI in `frontend/src/pages/nms/Access.tsx` and `Terminal.tsx`.

Service: `access` in `docker-compose.yml`.

## 1. Request path

```
Browser ── HTTPS / WSS ──► web (nginx)  location /api/nms/access/  (proxy_access.inc: WebSocket upgrade, 1 h read timeout)
                                │
                                ▼
                         access service (uvicorn, 1 process, port 8100, uid 10001, read-only root FS, cap_drop ALL)
                          1. session cookie + CSRF (REST) / cookie + Origin + one-time ticket (WebSocket)
                          2. nms.* permission (rbac.py) and the user's site scope
                          3. gateway.resolve(device id): inventory row → validate_address → fixed port
                          4. session caps (global / per user / per device), expired tickets released
                          5. vault.resolve(device, kind): device override → most specific group assignment
                          6. gateway._dial(): asyncssh, host key pinned (trust on first use), password only after the key matches
                                │
                                ▼
                         management network ──► device (SSH 22; TCP probes 22 / 443 / 830)
```

## 2. What the gateway will connect to

| Input | Source | Never from |
|---|---|---|
| Host | `switches.address` of an inventory device | the request |
| Allowed networks | `switch_networks` (administrators) | the request |
| Port | `PORTS = {ssh: 22, https: 443, netconf: 830}` | the request |
| Credential | the vault (device override or group assignment) | the browser |
| Commands (diagnostics) | `commands.TEMPLATES` by id | free text |
| Commands (terminal) | typed by the user, then classified by `LineGuard` | — |
| Commands (changes) | lines of an approved change request | an alert or a schedule |

`validate_address` refuses:
- a host that is not an IP literal (no DNS, so nothing to rebind);
- loopback, link-local, multicast and reserved addresses (`netguard.check_ip`);
- any address outside an authorised management network.

There is therefore no way to use the gateway as a general SSH proxy, a port scanner or an SSRF pivot. Tests:
`test_targets_are_inventory_devices_only` and `test_permissions_enforced_on_routes`.

## 3. Components

| Module | Role |
|---|---|
| `rbac.py` | `PERMISSIONS` (13), `ROLES` (7), `permissions_of`, `has`, `require` |
| `commands.py` | `classify()` with five risk levels; `TEMPLATES` (71 read-only templates on 11 platforms); `platform_of()`; `LineGuard` |
| `vault.py` | `seal` / `unseal` (TokenCipher), `resolve`, `describe` (never returns secrets) |
| `gateway.py` | `resolve`, `check_limits`, `expire_pending`, `tcp_probe`, `connect`, `_dial`, `Shell` (prompt-driven), `run_read_only` |
| `terminal.py` | WebSocket handler, watchdog, recording, `close_orphans`, `purge_recordings` |
| `diagnostics.py` | single and bulk jobs (semaphore, per-device timeout, cancel, orphan handling) |
| `changes.py` | change workflow (`create`, `decide`, `execute`, `rollback`) |
| `audit.py` | hash-chained audit with a per-process lock plus a PostgreSQL advisory lock |

## 4. Process model and failure behaviour

- **One process.** Terminal sessions live in memory. The session caps are counted in PostgreSQL, so they hold across
  restarts.
- **Restart.**
  - Sessions left pending or active by the previous process are closed with the reason "gateway restarted"
    (`close_orphans`).
  - Bulk jobs that were running are marked failed (`mark_orphans`).
- **Termination.** An administrator sets a flag; the session's watchdog checks it every 2 s. If the session runs in
  the same process it stops immediately.
- **Revocation.** A role change, password change, logout or disabled account bumps `session_version`. The watchdog
  notices within 2 s and ends the session ("account or permission revoked").
- **Isolation.** A slow or hung device holds one terminal or one bulk slot:
  - connect timeout `ACCESS_CONNECT_TIMEOUT_SECONDS`;
  - command timeout `ACCESS_COMMAND_TIMEOUT_SECONDS`;
  - per-device job timeout.

  The API container is unaffected, because it does not serve these routes in production.

## 5. In-process mode

`ACCESS_GATEWAY_INPROCESS=true` (the default) mounts the router in the main API. It is used for:
- development and tests;
- Kubernetes, until a separate Deployment exists (see [PRODUCTION_DEPLOYMENT.md](PRODUCTION_DEPLOYMENT.md)).

In this mode:
- the API's two uvicorn workers each hold their own terminals;
- caps and termination flags still work, because they are in the database;
- cancelling a bulk job running in another worker takes effect between devices, not mid-device.

## 6. Not built

| Item | Why / what instead |
|---|---|
| HTTPS reverse proxy of vendor web UIs | Proxying vendor UIs (cookies, absolute URLs, websockets, CSP) is a large attack surface. "Open web management" is audited and opens the device's address in the engineer's browser, which needs network reachability. |
| NETCONF / RESTCONF configuration changes | Read-only operations are built ([NMS_EXTENSIONS.md](NMS_EXTENSIONS.md) §3). Changes still use the CLI change workflow (Junos `commit confirmed`). |
| Telnet on by default | Built as opt-in only ([NMS_EXTENSIONS.md](NMS_EXTENSIONS.md) §4): installation switch plus per-device switch, marked clear text. |
| Console servers other than Opengear / Cisco | Opengear and Cisco terminal servers are built ([NMS_EXTENSIONS.md](NMS_EXTENSIONS.md) §5); others can use the Telnet method on 2000 + port. |
| External secrets managers (Vault, AWS SM) | The vault is the local Fernet store. `TokenCipher` is the seam for an external KMS. |
