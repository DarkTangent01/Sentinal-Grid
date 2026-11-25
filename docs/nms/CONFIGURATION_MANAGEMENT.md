# Configuration management

## Backup (existing, extended)

- **Scope:** read-only SSH backup of Cisco IOS / IOS-XE / 9800, Junos and Ruckus ICX (`app/configs/backup.py`).
  - Fixed show commands only.
  - Host key trusted on first use, and pinned.
  - Secrets masked before storage.
  - Volatile lines removed.
  - A new version is stored only when the text changes, with a unified diff.
- **Schedule and triggers:**
  - every 24 h (`CONFIG_BACKUP_INTERVAL_HOURS`);
  - after a `ciscoConfigManEvent` trap;
  - **Back up now** in the UI;
  - before and after every change request (trigger `change`).
- **Change detection:** the alert `switch_config_changed`, which notes maintenance windows.
- **Backup failures:** recorded on the device (`config_backup_error`) and shown in Config Changes. A changed host key
  raises `switch_ssh_hostkey_changed` and stops backups for that device until an administrator accepts the new key.
- **Compliance:** checks against the stored configurations (docs/NETWORK_COMPLIANCE.md).
- **Since this release:** the SSH connection uses the gateway's single dial function (`access.gateway._dial`), the
  same host-key pinning code as terminals and diagnostics.

**Not covered:** FortiGate configuration is handled by the IaC module (docs/IAC.md: REST API, plan / approve / deploy).
FortiOS backup over SSH is not included here.

## Change requests (new, `app/access/changes.py`)

### States

```
pending_approval ──approve──► approved ──execute──► executing ──► completed
       │                         │                      │      ├─► failed          ──rollback──► rolled_back
       └──reject──► rejected     └──cancel──► cancelled │      └─► verify_failed   ──rollback──► rolled_back
```

### Rules

- **Who:**
  - **Request:** `nms.device.access.configuration`.
  - **Approve:** `nms.configuration.approve`, and a **different person** from the requester. This applies to every
    change, not only high-risk ones.
  - **Execute:** `nms.device.access.configuration`.
  - **Roll back:** `nms.configuration.approve`.
- **Validation:**
  - device in inventory and in the user's site scope;
  - platform with a change procedure (`cisco_ios`, `cisco_nxos`, `arista_eos`, `ruckus_icx`, `fortios`, `junos`);
  - an SSH credential present;
  - at most 500 printable lines of at most 512 characters each.
- **Risk:** every line is classified in configuration context. The request takes the highest line risk, at least
  `MODERATE_RISK`. `DESTRUCTIVE` lines are refused, in both the change and its rollback. A `HIGH_RISK` change needs
  rollback lines, except on Junos, which uses `rollback 1`.
- **Window:**
  - optional start / end;
  - outside the window the change does not run;
  - a change-mode terminal opens only inside it.
- **Global switch:** `NMS_CONFIG_CHANGES_ENABLED` (default **false**). While it is off:
  - requests and approvals work;
  - execution, rollback and change-mode terminals are refused with "disabled".

### Execution

1. Back up (trigger `change`). If the backup fails, nothing is sent.
2. Open an interactive shell and send the platform's entry commands, then each line, reading to the prompt.
   - The first line whose output matches a CLI error (`% Invalid`, `syntax error`, `Command fail` …) stops the change.
   - The lines after it are not sent.
3. **Cisco / Arista / Ruckus:** `end`. **FortiOS:** the lines carry their own `config … end` blocks.
4. **Junos:** `show | compare` (recorded), then `commit confirmed <NMS_CHANGE_CONFIRM_MINUTES>`. On an error before
   the commit: `rollback 0` and leave configuration mode, so nothing is applied.
5. **Verify:**
   - a new SSH login;
   - the platform's read-only verification command (`show version` / `get system status`).
6. **If verified:**
   - Junos: `commit` to confirm;
   - other platforms: `write memory` / `copy running-config startup-config` when **save** was requested.
7. **If verification fails:**
   - status `verify_failed`;
   - Junos rolls back by itself when the confirm timer expires.
8. Back up after the change and store the diff between the two backups on the request.
9. Record the masked transcript, the change log and the hash-chained audit entry.

### Rollback

- **Junos:** `configure private`, `rollback 1`, `show | compare`, `commit`.
- **Other platforms:** the approved rollback lines are applied the same way as the change.
- A backup is taken afterwards.

**Tests:** `test_change_workflow` runs against a simulated IOS device. It covers:
- refused destructive lines;
- missing rollback lines;
- self-approval refused;
- the disabled switch;
- the exact line sequence sent;
- backups before and after, with the diff;
- rollback by an approver;
- a failing line that stops the rest.

## Not built

- Configuration templates with variables and Ansible playbooks.
- Scheduled change execution: deliberately not built, so that execution is always an explicit user action.
- Golden-configuration restore of a whole file (IOS `configure replace`): the rollback is line-based or Junos
  `rollback`.
- A device-side dry run for platforms other than Junos: the preview shows exactly what will be sent.
