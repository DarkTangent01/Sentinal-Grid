# Credential rotation

How to replace each credential without printing it. Run every command from the deployment directory on the server.
The secret files are described in [SECRET_MANAGEMENT.md](SECRET_MANAGEMENT.md).

**When to rotate:**
- after migrating secrets out of `.env` (the old values were visible in container metadata: audit finding DS-14);
- when someone with access leaves, or on a schedule (yearly at least);
- immediately when a value may have leaked ([SECURITY_INCIDENT_RESPONSE.md](SECURITY_INCIDENT_RESPONSE.md)).

Removing a value from `.env` or a file does **not** remove it from old backups, container metadata already captured,
shell history, tickets or source control history. Rotation is what makes those copies worthless.

## Rules

- Never type a secret on a command line (it lands in shell history and `ps`). Generate it into a file.
- Never `cat` a secret file to the terminal, and never paste one into chat or a ticket.
- Write the new file next to the old one, then `mv` it into place (atomic; no half-written file).
- Files stay `0444` inside the `0700` `secrets/` directory.

The helper used below:

```bash
newsecret() { (umask 077; openssl rand -hex 32 > "secrets/$1.new") && chmod 444 "secrets/$1.new"; }
```

## Order of difficulty

| Secret | Downtime | What breaks if done wrong |
|---|---|---|
| `anthropic_api_key` | api restart | AI assistant only |
| `bootstrap_admin_password` | none | nothing (only used while no user exists) |
| `secret_key` | api restart; everyone signs in again | sessions |
| `db_app_password` | short restart of the app services | database connections |
| `clickhouse_password` | restart of clickhouse and the app services | event ingestion and queries |
| `postgres_password` (superuser) | none | operator access only |
| `token_encryption_key` | two rolling restarts | every stored device credential, if the old key is lost before re-encryption |

## Application database role (`db_app_password`)

```bash
newsecret db_app_password
```

```bash
docker compose exec -T postgres sh -c 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
  < <(printf "\\set pw '%s'\nSELECT format('ALTER ROLE %%I PASSWORD %%L', '%s', :'pw') \\gexec\n" \
        "$(cat secrets/db_app_password.new)" "$(grep '^POSTGRES_APP_USER=' .env | cut -d= -f2)")
```

The password reaches `psql` on stdin only. Then switch the services over:

```bash
mv secrets/db_app_password.new secrets/db_app_password && docker compose up -d --force-recreate migrate api worker syslog traps
```

If `POSTGRES_APP_USER` is not set yet, run `./scripts/create-app-db-role.sh` instead: it creates the role and writes the file.

## PostgreSQL superuser (`postgres_password`)

`POSTGRES_PASSWORD_FILE` is read only when the data directory is first created, so changing the file alone changes nothing.

```bash
newsecret postgres_password
```

Apply it with the same stdin pattern as above, using `"$POSTGRES_USER"` as the role name:

```bash
docker compose exec -T postgres sh -c 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v role="$POSTGRES_USER"' \
  < <(printf "\\set pw '%s'\nSELECT format('ALTER ROLE %%I PASSWORD %%L', :'role', :'pw') \\gexec\n" "$(cat secrets/postgres_password.new)")
```

```bash
mv secrets/postgres_password.new secrets/postgres_password
```

Inside the container, local socket connections don't need the password, so nothing restarts.

## ClickHouse (`clickhouse_password`)

The clickhouse image writes the password from `CLICKHOUSE_PASSWORD_FILE` into its user config at start-up, so a
recreate applies the new file. Every service that uses ClickHouse must restart with it.

```bash
newsecret clickhouse_password && mv secrets/clickhouse_password.new secrets/clickhouse_password
```

```bash
docker compose up -d --force-recreate clickhouse && docker compose up -d --force-recreate migrate api worker syslog traps
```

Ingestion pauses for the restart; the ingress relay queues to disk meanwhile and replays afterwards.

## Session signing key (`secret_key`)

Every existing session becomes invalid (users sign in again). Sessions otherwise expire after `SESSION_TTL_MINUTES`.

```bash
newsecret secret_key && mv secrets/secret_key.new secrets/secret_key && docker compose up -d --force-recreate api
```

## Device credential encryption key (`token_encryption_key`)

This key encrypts every firewall token, SNMP community / USM key, notification secret, TACACS+ key and IaC
configuration backup in PostgreSQL. **Losing it before re-encryption makes those credentials unrecoverable**, so take a
backup first (`./scripts/backup.sh`) and keep the old key until step 4 reports zero.

1. Move the current key to the previous-key file, then generate the new one:

   ```bash
   cp secrets/token_encryption_key secrets/token_encryption_key_previous.new && chmod 444 secrets/token_encryption_key_previous.new && mv secrets/token_encryption_key_previous.new secrets/token_encryption_key_previous
   ```

   ```bash
   (umask 077; docker compose run --rm --no-deps --entrypoint python api -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" > secrets/token_encryption_key.new) && chmod 444 secrets/token_encryption_key.new && mv secrets/token_encryption_key.new secrets/token_encryption_key
   ```

   The key goes straight into the file; it is never shown.

2. Restart the services that hold it. They now encrypt with the new key and still decrypt with the old one:

   ```bash
   docker compose up -d --force-recreate api worker traps
   ```

3. Dry run (counts only):

   ```bash
   docker compose exec api python -m app.rotate_keys
   ```

4. Re-encrypt:

   ```bash
   docker compose exec api python -m app.rotate_keys --apply
   ```

   It must end with `0 value(s) still on a previous key` and `undecryptable=0` on every line. A non-zero
   `undecryptable` means a value was encrypted with a key that is in neither file: stop and find that key.

5. Retire the old key:

   ```bash
   : > secrets/token_encryption_key_previous.new && chmod 444 secrets/token_encryption_key_previous.new && mv secrets/token_encryption_key_previous.new secrets/token_encryption_key_previous && docker compose up -d --force-recreate api worker traps
   ```

`token_encryption_key_previous` accepts several comma-separated keys if a rotation has to be interrupted and restarted.
Backups taken before step 4 still need the old key to restore their encrypted columns; store it in the vault next to them.

## Bootstrap administrator (`bootstrap_admin_password`)

Used only while the user table is empty. Change the administrator's password in Settings after the first sign-in, then overwrite the file:

```bash
newsecret bootstrap_admin_password && mv secrets/bootstrap_admin_password.new secrets/bootstrap_admin_password
```

## Anthropic API key (`anthropic_api_key`)

Create the new key in the Anthropic console and revoke the old one there. Write the new key into the file without
echoing it (for example, paste into `read -rs k; printf '%s' "$k" > secrets/anthropic_api_key.new; unset k`), then:

```bash
chmod 444 secrets/anthropic_api_key.new && mv secrets/anthropic_api_key.new secrets/anthropic_api_key && docker compose up -d --force-recreate api
```

An empty file turns the assistant off.

## Credentials stored in the application

Firewall API tokens, SNMP credentials, SMTP / webhook secrets and TACACS+ keys are entered in the UI and stored encrypted.
Rotate them at the source first (create a new FortiGate / PAN-OS API token, change the SNMPv3 user, new SMTP password), then
update the entry in the UI; the old value is overwritten. Revoke the old credential on the device afterwards. The audit
log records that the value changed, never the value.

## After every rotation

- `docker compose ps`: all services healthy.
- Sign in, open a firewall page (decrypts a stored token), check that events still arrive.
- Delete any `*.new` leftovers and the `.env.pre-secrets.*.bak` file if it still exists.
- Update the vault copy of `./secrets`.
