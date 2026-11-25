# Credential vault: design

## Storage

- **Table:** `device_ssh_credentials`. It is reused rather than duplicated; migration 0035 added `kind`, `owner` and
  `rotated_at`.
- **Kinds:**

  | Kind | Secret fields |
  |---|---|
  | `ssh` | password, private key |
  | `https` | password |
  | `api_token` | token |
  | `netconf` | password, private key |

- **Encryption:** `secret_ciphertext` holds a JSON document encrypted with `TokenCipher` (Fernet; MultiFernet for
  rotation). The key comes from `TOKEN_ENCRYPTION_KEY_FILE` (Docker secret), never from the database or the image.
- **Key rotation:** `python -m app.rotate_keys` re-encrypts every stored secret, these included, with the new key
  while `TOKEN_ENCRYPTION_KEY_PREVIOUS` still decrypts the old ones.
- **SNMP credentials** (v2c community, v3 USM auth / priv) stay in `switch_credentials`, managed in Switch Monitoring.
  They are encrypted the same way.

## Never exposed

- No API returns a secret. `vault.describe()` returns only which fields are held (`secret_fields: ["password"]`), the
  rotation date and usage counts.
- Updating a credential with empty secret fields keeps the stored secret, so the UI never needs to read it back.
- Audit details are passed through `_redact()`: any key containing password / secret / token / key / ticket is
  replaced.
- Device output and command logs are masked with the configuration masker (`configs.backup.mask`) before storage.
- Secrets are decrypted only inside the gateway (or the worker for backups), immediately before the SSH
  authentication. They are never logged.
- Tests: `test_vault_never_returns_or_stores_plaintext` and `test_audit_chain_detects_tampering` (redaction).

## Assignment and resolution

1. **Device override:** `switches.ssh_credential_id` (kind `ssh`). This is the same field configuration backup uses,
   so one credential serves both.
2. **Group assignment:** `nms_credential_assignments` (kind + optional site / role / vendor). Every non-empty field
   must match.
3. **Most specific wins:** the assignment with more matching fields wins, then the oldest. Test:
   `test_group_assignment_resolution`.

## Access control

| Permission | Allows |
|---|---|
| `nms.device.access.credential.manage` | Create, update / rotate, delete, assign (NMS Administrator, Super Administrator) |
| `nms.device.access.ssh` / `diagnostics` / `configuration` | Using a credential implicitly through the gateway, never seeing it |

Deleting a credential that devices still use is refused. Every vault action is audited (`vault_create`,
`vault_update`, `vault_rotate`, `vault_delete`, `vault_assign`, `vault_unassign`).

## TACACS+ / RADIUS

The built-in TACACS+ service (docs/TACACS.md) can authenticate and authorise the vault account on devices. That does
not remove the need for a device-side account: give the vault account a read-only privilege level or command set, and
a separate change account where changes are enabled.

## Not built

- External secrets managers (HashiCorp Vault, cloud KMS). `TokenCipher` is the single seam to replace.
- Per-user personal credentials (each engineer signing in with their own device account). Sessions use the shared
  vault account. The access audit records the real user.
