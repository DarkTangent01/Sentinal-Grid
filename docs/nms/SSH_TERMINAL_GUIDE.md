# Browser SSH terminal: user and operator guide

## Opening a terminal

- **From a device:** open the device (Switch & Device Monitoring → device → **Access** tab) and click **Open SSH
  terminal**.
- **From Device Access:** NMS → Device Access → **Devices**, then **SSH** on the device's row. Several terminals can be
  open at once; each has its own tab with a ✕ to close it.

Requirements:
- the permission `nms.device.access.ssh` (Network Engineer, Network Operator, Site Administrator, NMS Administrator,
  Super Administrator);
- the device is inside your site scope;
- the device has an SSH credential, either its own or through a group assignment;
- its address is inside an authorised management network;
- the gateway has a free session slot (limits are shown on the Device Access page).

## What happens to what you type

- **Normal typing:** keystrokes reach the device as you type, so echo, `?` help and tab completion work normally.
- **Enter:** the gateway classifies the line you typed and then either:
  - **sends the Enter** when the line is `READ_ONLY` or `LOW_RISK` (show / get / display, ping, traceroute,
    terminal length, enable, exit);
  - **blocks it** for anything higher: configuration mode, `clear`, `debug`, `write`, `reload` …
- **When a line is blocked:**
  - the line is erased (Ctrl-U) and abandoned (Ctrl-C) on the device;
  - a red **blocked** notice explains why;
  - input is ignored until the device shows a fresh prompt.
- **Recalled or edited lines:** a line recalled with ↑ / ↓ or edited with ← / → cannot be tracked reliably and is
  refused. Press Ctrl-U and type it again.
- **Password prompts:** an answer to a device prompt such as `Password:` (enable password) is sent but never recorded
  or classified.

### Change sessions

When `NMS_CONFIG_CHANGES_ENABLED` is set, a terminal can be opened for an **approved** change request, inside its
window. It needs the permission `nms.device.access.configuration`. In a change session:
- configuration commands are allowed and recorded against the change;
- destructive commands (`reload`, `write erase`, `execute factoryreset` …) are still never allowed from the terminal.

## Ending a session

A session ends when any of these happens:
- you click **Disconnect** or close the tab;
- the device closes the session;
- idle timeout (`ACCESS_IDLE_TIMEOUT_SECONDS`, default 15 min);
- maximum duration (`ACCESS_MAX_SESSION_SECONDS`, default 4 h);
- an administrator clicks **Terminate** (Device Access → Sessions);
- your account changes: role change, logout, password change or disable.

**Reconnect** opens a new session with a new ticket. **Copy** copies the selection, or all output if nothing is
selected. **Download** saves the session output as text.

## Recording

`ACCESS_RECORDING`:

| Value | What is kept |
|---|---|
| `off` | Session rows and the access audit only |
| `commands` (default) | Every command line with its risk and whether it was sent or blocked (secrets masked) |
| `full` | Commands plus the output transcript, masked and capped at `ACCESS_RECORDING_MAX_BYTES`. Only users with `nms.device.access.audit.view` can download it; every download is audited. Kept `ACCESS_RECORDING_RETENTION_DAYS` (90). |

Full recording can capture sensitive device output: configurations, user names and neighbour data. Enable it only with
your organisation's privacy and retention policy in place.

## Limits of the guard

The line guard is defence in depth, not the authority over what an account may do on a device. The device's own AAA
(TACACS+ / RADIUS command authorisation, privilege levels) remains that authority. Give the vault credential the least
privilege that the engineers' read-only work needs.

## Troubleshooting

| Message | Meaning |
|---|---|
| `no SSH credential is assigned` | Assign one (Device Access → Credential vault, or the device override) |
| `not inside an authorised management network` | Add the network in Switch Monitoring → Settings → Networks (administrators) |
| `the device's SSH host key changed` | The device presented a different key from the pinned one. Verify it out of band, then accept the new key in Config Changes |
| `the device rejected the SSH login` | Wrong username / password / key in the vault |
| `limit` (HTTP 429) | Too many open sessions: close one or ask an administrator |
| `invalid or expired ticket` | The WebSocket opened more than 30 s after the ticket was issued; reconnect |
