# Container hardening runbook (third pass, 2026-11-14)

Procedures for the changes in CONTAINER_SECURITY_ASSESSMENT.md that touch the host or need a maintenance window.
None of them was applied to production automatically.

## 1. Deploy the Compose hardening (C3-2, C3-4 … C3-7, C3-10)

**What changes when the new `docker-compose.yml` and images roll out:**

| Service | Before | After |
|---|---|---|
| all | no init | `init: true`; `/tmp` tmpfs `noexec,nosuid,nodev` |
| postgres | writable root | read-only root; tmpfs `/var/run/postgresql` (mode 3777, as in the image) |
| clickhouse | root entrypoint + 5 capabilities, no pids limit | `user: 101:101`, no capability, read-only root, tmpfs `users.d` / logs / `/tmp`, pids 4096 |
| ingress | writable root | read-only root, `/tmp` tmpfs |
| tacacs | root entrypoint + 6 capabilities, `no-new-privileges:false`, file capability on tac_plus-ng | `user: 10003:10050`, no capability, `no-new-privileges:true`, read-only root, `sysctls: net.ipv4.ip_unprivileged_port_start=49` |
| web | resolver inline in `siem.conf` | resolver + api address in `upstream.inc` (same values for Compose) |
| backend image | — | `XDG_CACHE_HOME=/tmp/.cache` (fontconfig cache for PDF reports) |

**Pre-checks (read-only):**

```bash
docker run --rm -v fortisiem_chdata:/d alpine stat -c '%u:%g' /d                                # must be 101:101
docker run --rm -v fortisiem_tacacs_config:/c -v fortisiem_tacacs_logs:/l alpine stat -c '%u:%g %n' /c /l   # 10003:10050
```

If either owner differs, run the previous tacacs / clickhouse image once (its root entrypoint re-owns the volume), or
`chown` the volume from a one-off container.

**Deploy:** the normal `./scripts/deploy.sh --apply`. It recreates every service. The ingress relay is recreated too
(read-only root, init), so there is a short pause in syslog intake: UDP senders retry nothing, so schedule it.

**Verify:**

```bash
./scripts/security/docker-security-audit.sh fortisiem      # on the server (deployed there); expect 0 FAIL
./scripts/security/validate-deployment.sh compose fortisiem   # from a repository checkout (not deployed to the server)
python3 scripts/lab/tacacs_e2e.py ...                      # LAB copy only, never production
```

**Rollback:** check out the previous `docker-compose.yml` and `deploy/tacacs` / `frontend` / `backend` from git, then
deploy. The volumes are untouched by the change.

## 2. Enable SELinux confinement for Docker containers (C3-1)

The host enforces SELinux, but Docker runs without `--selinux-enabled`, so containers are not labelled `container_t`.

1. **Relabel the secrets and the bind-mounted directories** (`:z` / `:Z` in Compose do this for volume mounts; Compose
   secrets are plain binds without a label option):
   ```bash
   sudo semanage fcontext -a -t container_file_t '/home/siem/fortisiem/secrets(/.*)?'
   sudo restorecon -Rv /home/siem/fortisiem/secrets
   ```
2. **Turn it on** in `/etc/docker/daemon.json`, adding `"selinux-enabled": true` to the existing keys, then restart:
   ```bash
   sudo systemctl restart docker
   ```
   The restart stops every container. Schedule it; `restart: unless-stopped` brings them back.
3. **Verify:**
   ```bash
   docker info | grep -i selinux
   ps -eZ | grep container_t        # the processes now carry container_t:s0:cX,cY
   ```
   Then run the audit script.
4. **If anything is denied,** read it with:
   ```bash
   ausearch -m avc -ts recent
   ```
   Fix the label; do not disable SELinux. Rollback is removing the key and restarting Docker.

## 3. Restrict the published ports with firewalld (C3-8)

Web, syslog, traps, flows and TACACS+ are published on all interfaces (`*_BIND_IP=0.0.0.0`). Allow them only from the
networks that need them (example networks, replace with yours):

```bash
sudo firewall-cmd --permanent --new-zone=sentinel-devices
sudo firewall-cmd --permanent --zone=sentinel-devices --add-source=10.200.0.0/16      # device management networks
sudo firewall-cmd --permanent --zone=sentinel-devices --add-port={514/udp,514/tcp,162/udp,49/tcp,2055/udp,4739/udp,6343/udp}
sudo firewall-cmd --permanent --new-zone=sentinel-users
sudo firewall-cmd --permanent --zone=sentinel-users --add-source=10.0.0.0/8            # user networks
sudo firewall-cmd --permanent --zone=sentinel-users --add-port={443/tcp,80/tcp}
sudo firewall-cmd --reload
```

Docker publishes ports through its own iptables chains, which bypass firewalld zones for forwarded traffic. Enforce
the same allowlist in the `DOCKER-USER` chain (or firewalld's `docker` zone policy on firewalld ≥ 1.0), and test from an
outside address before relying on it.

## 4. Runtime: rootful vs rootless (C3-3)

| Option | Effect | Cost |
|---|---|---|
| Keep rootful Docker, restrict the `docker` group | membership is root: only administrators, SSH keys only, no password sudo for `siem` | none |
| Rootless Docker / Podman for the deploy user | a container escape lands as an unprivileged user | published ports < 1024 need `net.ipv4.ip_unprivileged_port_start` on the host; storage moves to `~/.local/share`; a data migration |
| Kubernetes (k8s/) | restricted Pod Security, NetworkPolicies, per-workload RBAC | a planned migration (k8s/README.md) |

**Recommendation:** restrict the group now, and use rootless Podman or Kubernetes for the next platform move. No
application component needs rootful privileges any more: every container runs non-root with no capabilities.

## 5. Runtime threat detection (Phase 12)

**Falco** (eBPF driver) detects:
- shells in containers;
- writes to sensitive paths;
- unexpected outbound connections;
- privilege changes.

It needs host-level privileges (it runs privileged with host PID), so it is a separate, operator-owned component,
never part of the Sentinel stack.

**If adopted:**
- install it from its own package or chart in its own namespace / systemd unit;
- forward its JSON alerts to Sentinel Grid's syslog input (`json_output: true`, `program_output` to `logger` / rsyslog);
- the parser ingests them like any device log.

The Sentinel-side signals that need no extra agent already exist:
- container restarts and unhealthy services (`docker ps` / Compose health, Kubernetes events);
- the NMS self-monitoring objectives (`nms_self_slo_breach`);
- `scripts/security/docker-security-audit.sh` on a schedule. Run it from the operator's cron and alert on a non-zero
  exit.

## 6. Supply chain (Phase 11)

**Already in CI** (`.github/workflows/ci.yml`):
- base images pinned by digest;
- Trivy image scan (fails on fixable HIGH / CRITICAL);
- Trivy config scan, hadolint, gitleaks over the whole history;
- SPDX SBOMs.

**New:**
- **Local scans:** `scripts/security/image-scan.sh` runs the same pinned Trivy and writes a CycloneDX SBOM per image.
- **Kubernetes manifests in CI:** every overlay must render and pass `k8s_audit.py` (production: digest-pinned images).
- **Image admission:** the production overlay's ValidatingAdmissionPolicy refuses images that are not digest-pinned
  from the approved registry.

**Signing (next step, needs a registry):**
1. Build in CI.
2. Push by digest.
3. `cosign sign --key <kms-key> <image>@<digest>` (or keyless with the CI OIDC identity).
4. Enforce with the Sigstore policy-controller or Kyverno `verifyImages` in the cluster.

Not enabled here: there is no registry in the current Compose deployment (images are built on the host).

**Remediation policy:**
- **CRITICAL fixable:** blocks deploy; fix within 7 days.
- **HIGH fixable:** within 30 days.
- **Unfixed:** documented in `.trivyignore.yaml` with an expiry.
- **Base images:** updated through Dependabot PRs, never automatically in production.

## 7. Kind validation of the Kubernetes manifests

Status, see the final report: the manifests render, pass schema validation (kubeconform, strict) and the static audit
for every overlay. The live kind run depends on pulling `kindest/node` through the corporate TLS inspection, which
failed for the whole of this pass (95 attempts). To run it:

```bash
kind create cluster
for i in backend web ingress tacacs; do kind load docker-image fortisiem-$i:1.0.0; done
# create the three Secrets (k8s/README.md)
kubectl apply -k k8s/overlays/development
./scripts/security/validate-deployment.sh k8s sentinel   # pods, live audit, NetworkPolicy probes
```
