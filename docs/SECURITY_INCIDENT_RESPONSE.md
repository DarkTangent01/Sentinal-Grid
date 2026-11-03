# Security incident response: leaked or suspected-leaked credentials

What to do when a platform secret, a stored device credential or the host may be compromised. Rotation commands are
in [CREDENTIAL_ROTATION.md](CREDENTIAL_ROTATION.md); the secret inventory is in [SECRET_MANAGEMENT.md](SECRET_MANAGEMENT.md).

**Never paste a secret value into the incident ticket, chat or this runbook's notes.** Refer to secrets by file name.

## 1. Triage (first 15 minutes)

Answer these and write the answers in the ticket:

| Question | Where to look |
|---|---|
| Which secret(s)? | the exposure itself: a pasted `docker inspect` / `docker compose config`, a committed file, a backup copy, a screenshot |
| Since when, and who could see it? | chat / ticket audience, repository visibility, backup storage ACLs |
| Was it a value or only a name / path? | `*_FILE` paths and variable names are not secrets |
| Is the host itself compromised? | unexpected `docker exec`, logins, processes, new containers or images (step 4) |

Severity guide:
- **Critical:** `token_encryption_key` together with a database dump or database access; host or `docker` group compromise; superuser database password with network access to PostgreSQL.
- **High:** `secret_key` (session forgery as any user, including administrators); `db_app_password` or `clickhouse_password`; any device API token.
- **Medium:** `token_encryption_key` alone (useless without the ciphertexts, but rotate); `anthropic_api_key`; bootstrap password after first sign-in.

## 2. Contain

Do the matching rows, most severe first.

| Leaked | Immediate containment |
|---|---|
| `secret_key` | rotate it now: all sessions end, forged tokens stop working |
| `token_encryption_key` | treat every stored device credential as exposed: rotate the key **and** the credentials on the devices (step 3) |
| database / ClickHouse password | rotate; confirm neither database publishes a port (`docker compose ps`) |
| a firewall / switch / SMTP credential | revoke it on the device or service first, then enter a new one in the UI |
| `anthropic_api_key` | revoke in the Anthropic console |
| host / Docker access | isolate the host from the network except your management path; preserve evidence before rebuilding (step 4) |

Remember: deleting the exposed copy (the chat message, the commit, the backup file) does not undo the exposure, and
removing a value from `.env` does not remove it from existing images, container metadata, logs, backups or source
control history. Only rotation does.

## 3. Eradicate

1. Rotate every affected secret ([CREDENTIAL_ROTATION.md](CREDENTIAL_ROTATION.md)). For `token_encryption_key`, finish
   `python -m app.rotate_keys --apply` with zero values left on the old key.
2. Rotate the device-side credentials (FortiGate / PAN-OS API tokens, SNMPv3 users, TACACS+ keys, SMTP / webhook
   secrets) and update them in the UI. Revoke the old ones on each device.
3. If the leak was through source control: remove the file in a new commit, then decide with the repository owner
   whether to rewrite history. A rewrite doesn't reach existing clones and forks, so rotation is still required.
4. If the leak was through a backup: delete or re-encrypt the affected backup copies and tighten the storage ACL.
   Older backups still hold the old encrypted values; keep the old encryption key in the vault alongside them, or destroy them.
5. Close the path that leaked it (for example: someone pasted `docker inspect` output; the secret was in `.env` because
   `migrate-secrets.sh` was never run on that host).

## 4. Investigate

Within the platform:
- **Audit log** (Settings → Audit log): sign-ins, user and role changes, credential changes, IaC deployments in the exposure window.
- **Sessions:** unknown source IPs or user agents for administrator sign-ins.
- **IaC:** any deployment or approval nobody remembers; compare device configs with the stored backups.
- **TACACS+ events** and firewall admin logins in the SIEM for the devices whose credentials were stored.

On the host:
- `docker events --since <time>` and the Docker daemon log for `exec`, `cp`, `run`, image pulls.
- `last`, `journalctl -u ssh`, `/var/log/auth.log` for logins; sudo use.
- Unexpected containers (`docker ps -a`), images, volumes or files in `./secrets` (`ls -l --time-style=full-iso secrets/`).
- PostgreSQL: unexpected roles (`\du`), connections from outside the `backend` network.

Preserve evidence before rebuilding: copy logs and the audit log export to separate storage, with the time window recorded.

## 5. Recover

- Bring the stack up with the new secrets (`docker compose up -d`) and confirm all services are healthy.
- Sign in, open a firewall page (decrypts a stored token), check event ingestion and a test alert notification.
- If the host was rebuilt: restore data from a backup taken **before** the compromise window, then restore `./secrets`
  from the vault and rotate again (the vault copy predates the rotation only if you didn't update it).

## 6. Afterwards

- Write up the timeline, root cause, which secrets were rotated and when (names only).
- Update the vault copy of `./secrets`.
- Check that `docker` group membership and SSH access are still limited to administrators.
- Add the cause to the checks if it can be automated (CI already runs gitleaks, image secret scans and a rendered-compose check).

## Contacts

Fill in for your organisation:

| Role | Name / channel |
|---|---|
| Platform owner | |
| Network team (device credentials) | |
| Security on-call | |
