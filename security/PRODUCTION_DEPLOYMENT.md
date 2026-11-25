# Production deployment

How to run Sentinel Grid securely on one host with Docker Compose: ports and firewall, first install, upgrades,
rollback, backups and validation. Container controls: [DOCKER_HARDENING.md](DOCKER_HARDENING.md). Secrets:
[SECRETS_MANAGEMENT.md](SECRETS_MANAGEMENT.md). Findings: [DOCKER_SECURITY_AUDIT.md](DOCKER_SECURITY_AUDIT.md).

`docker-compose.yml` **is** the production configuration and is secure by default (loopback-only listeners until you
set an interface address, no published database ports, no secret in any environment). `docker-compose.dev.yml` is for
laptops and lab copies only.

## Ports and firewall

| Port | Published by | Bound to | Who needs it | Purpose |
|---|---|---|---|---|
| 443/tcp | web (container 8443) | `WEB_BIND_IP` (default 127.0.0.1) | SOC analysts' networks | UI and API over TLS |
| 80/tcp | web (container 8080) | `WEB_BIND_IP` | same | redirect to HTTPS only |
| 514/udp, 514/tcp | ingress (container 5514) | `SYSLOG_BIND_IP` (default 127.0.0.1) | firewalls and switches | syslog |
| 162/udp | traps (container 1162) | `TRAP_BIND_IP` (default 127.0.0.1) | network devices | SNMP traps / informs |
| 49/tcp | tacacs (optional profile) | `TACACS_BIND` (default 0.0.0.0) | device management subnets | TACACS+ |
| 22/tcp | host sshd | management network | administrators | operations, `deploy.sh` |

Nothing else is published: PostgreSQL (5432) and ClickHouse (8123 / 9000) are reachable only on the internal `backend`
network. In the host firewall, allow each port only from the sources in the table (for example `firewalld` rich rules
or `nftables` sets); deny everything else inbound. Outbound: the `egress` network needs the FortiGate / switch
management addresses, threat-intelligence feeds and SMTP / webhook targets you configure; tac_plus-ng needs LDAPS (636)
if you use a directory.

## First installation

```bash
git clone <repo> sentinel && cd sentinel
```

```bash
cp .env.example .env && ./scripts/gen-secrets.sh
```

Set `WEB_BIND_IP`, `SYSLOG_BIND_IP`, `TRAP_BIND_IP` (and `TACACS_BIND`, `COMPOSE_PROFILES=tacacs` if used) in `.env`.

```bash
./scripts/gen-selfsigned-cert.sh siem.example.internal
```

Then replace `deploy/certs/siem.crt` / `siem.key` with a certificate from your internal CA. Keep the key mode `0600`,
and set `WEB_UID` in `.env` to its owner's uid (`stat -c %u deploy/certs/siem.key`): nginx runs as that unprivileged
user. `deploy.sh` does this automatically.

```bash
docker compose up -d --build
```

Give the services their own least-privilege database accounts, then restart them:

```bash
./scripts/create-app-db-role.sh && ./scripts/create-clickhouse-app-user.sh && docker compose up -d
```

Sign in with the password in `secrets/bootstrap_admin_password`, change it, then overwrite that file (SECRETS_MANAGEMENT.md).

## Upgrading (from a workstation)

`./scripts/deploy.sh` syncs the checkout to the server and rebuilds there.
1. The local security gate runs first: `tests/test_secret_files.py` must pass, or nothing is sent.
2. It never copies `.env`, `secrets/`, keys or backups.
3. It derives new secret files a newer version needs, records `WEB_UID`, refuses a server `.env` that still holds a
   secret, then runs `docker compose build`, `nginx -t` and `docker compose up -d`.

```bash
./scripts/deploy.sh
```

That is a dry run: it lists the files it would change.

```bash
./scripts/deploy.sh --apply
```

Deploy only a commit whose CI `security-gate` job passed.

**This release in particular** (container hardening, 2026-11):
- **Recreated containers:** `postgres` (16.6 → 16.15), `clickhouse` (24.8.11 → 24.8.14) and `web` (now listens on 8443 /
  8080 inside; the published ports are unchanged). Ingestion pauses for the ClickHouse restart while the ingress relay
  queues to disk.
- **After the deploy, once:** `./scripts/create-clickhouse-app-user.sh && docker compose up -d`. Until then the services
  keep using the ClickHouse admin account (`clickhouse_app_password` starts as a copy of the admin password).

## Rollback

- **Application code:** check out the previous commit and run `deploy.sh --apply` again. Images are rebuilt from it;
  data volumes are untouched.
- **PostgreSQL / ClickHouse minor versions** (16.15 → 16.6, 24.8.14 → 24.8.11): pin the previous tag in
  `docker-compose.yml` and redeploy. Same-major downgrades are data-compatible.
- **Database schema:** migrations are additive. Use `scripts/restore.sh <timestamp>` only for data loss: it replaces data.
- **ClickHouse app account:** set `CLICKHOUSE_APP_USER=` (empty) in `.env`, copy `secrets/clickhouse_password` over
  `secrets/clickhouse_app_password`, then `docker compose up -d`: the services return to the admin account.

## Backups

`./scripts/backup.sh` takes a PostgreSQL dump and a ClickHouse native backup into `backups/` (0700).

**Encryption:** generate a GnuPG key pair **on a separate, trusted machine**, import only the public key on the server,
and set `BACKUP_GPG_RECIPIENT` in `.env`.

```bash
gpg --import sentinel-backup.pub.asc
```

Every backup is then encrypted and the plaintext deleted. The server cannot decrypt its own backups; keep the private
key offline (and its passphrase in your vault). To restore, decrypt on the trusted machine (`restore.sh` prints the
commands) and copy the files back.

**Retention and storage:**
- `BACKUP_KEEP_DAYS` (default 14) prunes local copies.
- Copy backups to separate storage that the SIEM host cannot delete from (object storage with versioning or object lock).
- `./secrets` is **not** in the backups: store it in your vault separately. `token_encryption_key` is needed to read
  stored device credentials, and backups taken before a key rotation need the old key.
- Test a restore on a lab host quarterly.

## Validation after any deploy

```bash
docker compose ps
```

Every service should be healthy and `migrate` exited 0.

```bash
docker compose exec -T postgres sh -c 'grep ^Uid /proc/1/status'
```

The uid should be 70. For the web container, run `docker compose top web`: every nginx process should be your
`WEB_UID`, never 0.

```bash
curl -sS --cacert deploy/certs/siem.crt https://<server-name>/api/health
```

That checks the TLS chain and name.

```bash
openssl s_client -connect <server>:443 -tls1_1 </dev/null
```

This must fail; TLS 1.2 and 1.3 must work.

Also confirm the ClickHouse account in use: in `docker compose exec clickhouse clickhouse-client` (as the admin), run
`SELECT user, count() FROM system.query_log WHERE event_time > now() - 300 GROUP BY user`. It should show
`siem_ch_app` for the services.

## Production checklist

- [ ] Host: OS patched, disk encrypted, `docker` group limited to administrators, SSH keys only, no Docker TCP socket.
- [ ] Firewall: only the ports in the table, only from the listed sources.
- [ ] `.env` holds no secret (`deploy.sh` refuses otherwise); `secrets/` is 0700 and backed up to a vault.
- [ ] Certificate from the internal CA; `WEB_UID` = key owner; key mode 0600.
- [ ] `create-app-db-role.sh` and `create-clickhouse-app-user.sh` run; services use `siem_app` / `siem_ch_app`.
- [ ] Bootstrap admin password changed and the file overwritten.
- [ ] `BACKUP_GPG_RECIPIENT` set; backups copied off-host; a restore tested.
- [ ] CI `security-gate` required on the default branch; Dependabot pull requests reviewed weekly.
- [ ] Rotation schedule (CREDENTIAL_ROTATION.md) and incident runbook (INCIDENT_RESPONSE.md) known to the on-call team.
- [ ] ClickHouse 25.8 LTS upgrade planned (DS2-1).
