# Container infrastructure security assessment (2026-11-14)

Third pass. It builds on DOCKER_SECURITY_AUDIT.md (first and second pass) and DOCKER_HARDENING.md, and covers the
Compose stack, the images, the production host and, new in this pass, a Kubernetes deployment. Everything below was
observed on the repository and, read-only, on the production host (`docker inspect`, `docker top`, `docker stats`,
`ss`, SELinux and firewall status). Nothing was changed on the host by the assessment.

## Inventory

| Item | Found |
|---|---|
| Dockerfiles | `backend/Dockerfile` (API, worker, pollers, syslog, traps, flows, migrate), `frontend/Dockerfile` (nginx, multi-stage), `deploy/ingress/Dockerfile` (rsyslog relay), `deploy/tacacs/Dockerfile` (tac_plus-ng + agent, multi-stage) |
| Compose | `docker-compose.yml` (production), `docker-compose.dev.yml` (development override). No Podman-specific file; the stack is also run under Podman in the lab |
| Third-party images | `postgres:16.15-alpine`, `clickhouse/clickhouse-server:24.8.14.39`, all pinned by digest |
| Kubernetes / Helm | none in the repository; none installed on the host (`k3s` inactive, no `kubectl`) |
| Not part of this stack | Redis, Zeek sensors, Prometheus, Grafana, MySQL. Zeek and other sources reach Sentinel Grid as logs (syslog). `/api/metrics` is Prometheus-format for an external Prometheus |
| Host | CentOS Stream 9, kernel 5.14, **SELinux enforcing**, Docker (rootful), cgroup v2, built-in seccomp profile, firewalld active |

## What is already in place (verified on the running containers)

- **Non-root processes:** every container process runs as non-root:
  - app 10001;
  - nginx 1000 / 101;
  - postgres 70;
  - ClickHouse server 101;
  - rsyslog 10002;
  - tac_plus-ng / agent 10003.
- **Container settings:** no privileged containers, no host PID / IPC / network, no runtime socket mounts, and no host
  system directories mounted.
- **Read-only and minimal:** the backend services and the web service have a read-only root filesystem with
  `cap_drop: ALL` and `no-new-privileges`.
- **Secrets:** file-mounted (`/run/secrets`), scoped per service. None in environment variables, images or Git
  (`.dockerignore` excludes `.env*`, keys and certificates).
- **Networks:** segmented. `backend` and `ingest` are internal (no route out); databases are reachable only on
  `backend` and publish no port.
- **Limits:** CPU, memory and process limits on every long-running service except ClickHouse's process count.
- **Images:** pinned by digest. CI runs hadolint, Trivy (image and config), gitleaks and SBOMs, with a security gate.

## Findings

| # | Severity | Finding | Evidence | Remediation in this pass |
|---|---|---|---|---|
| C3-1 | High | Docker is not running with SELinux enabled on an SELinux-enforcing host, so containers are not confined by `container_t` / MCS labels. A container escape would land outside SELinux confinement | `docker info` security options: seccomp, cgroupns (no `selinux`) | Compose bind mounts get `:z` / `:Z` labels (no effect until enabled). The secrets directory needs a relabel. Enabling `"selinux-enabled": true` restarts Docker, so it is a scheduled host change with a procedure (CONTAINER_HARDENING_RUNBOOK.md); not applied automatically |
| C3-2 | High | `tacacs` starts as root with six capabilities and `no-new-privileges:false` (tac_plus-ng binds port 49 through a file capability), published on `0.0.0.0:49` | `docker inspect` | Runs as uid 10003 from the start. Port 49 via the namespaced sysctl `net.ipv4.ip_unprivileged_port_start=49`, so no capability and no file capability. `no-new-privileges:true`, `cap_drop: ALL` with nothing added, read-only root filesystem |
| C3-3 | High | The deploy user `siem` is in the `docker` group, which is root-equivalent on the host | `getent group docker` | Documented: keep the group to administrators, SSH key-only for `siem`, option of rootless Docker / Kubernetes. A host-access decision, not changed |
| C3-4 | Medium | `clickhouse` starts as root with five capabilities to chown its data and switch to uid 101; no process limit | `docker inspect`; 781 threads | `user: "101:101"`, no added capabilities (data volume already owned by 101). The entrypoint's generated user config goes to a tmpfs owned by 101. `pids` limit 4096 |
| C3-5 | Medium | Writable root filesystems: postgres, clickhouse, ingress, tacacs | `ReadonlyRootfs=false` | `read_only: true` with tmpfs for the paths each one writes (`/var/run/postgresql`, `/tmp`, ClickHouse `users.d` / `config.d` generated files) |
| C3-6 | Medium | No init process: PID 1 is the application (zombie reaping, signal forwarding) | `Init=<nil>` everywhere | `init: true` on every service |
| C3-7 | Low | `/tmp` tmpfs allows exec / suid / devices | compose `tmpfs` | `noexec,nosuid,nodev` on every tmpfs |
| C3-8 | Low | Web (443/80), syslog (514), traps (162) and TACACS+ (49) are published on all interfaces | `.env` `*_BIND_IP=0.0.0.0`, `ss -lntup` | Documented firewalld rich rules limiting each port to the management / device networks (runbook); bind addresses stay operator settings |
| C3-9 | Low | Secret files are 0444 (plain Compose ignores `mode` / owner) inside a 0700 directory | `stat` | Unchanged under Compose (documented limit). Kubernetes Secrets are mounted 0400 with `fsGroup` |
| C3-10 | Low | WeasyPrint / fontconfig has no writable cache in read-only containers (warnings on every PDF) | api output | `XDG_CACHE_HOME=/tmp` in the image |
| C3-11 | Info | The backend image is single-stage | Dockerfile | Accepted: no compiler or build tools are installed (slim base, binary wheels only). A shell remains for operations |
| C3-12 | Info | No Kubernetes deployment exists | — | New `k8s/` (Kustomize) with restricted Pod Security, least-privilege RBAC, default-deny NetworkPolicies, PVCs and probes; validated on a throwaway kind cluster. **Not deployed:** the production stack stays on Compose until a migration is planned |

## Special-requirement components

| Component | Need | Scoped grant |
|---|---|---|
| TACACS+ (port 49 TCP) | bind a port below 1024 | namespaced sysctl `ip_unprivileged_port_start=49` (Compose `sysctls`, Kubernetes pod `securityContext.sysctls`; a "safe" sysctl, allowed by the restricted profile). No capability |
| Syslog (514), SNMP traps (162), flows (2055 / 4739 / 6343) | receive UDP from devices, keep the source address (collectors allowlist by source IP) | unprivileged container ports (5514, 1162, 2055…). Compose publishes them; Kubernetes uses `externalTrafficPolicy: Local` Services so the source address is kept |
| SNMP polling, ICMP checks, SSH config backup | outbound to device management networks | egress network only for the services that poll; Kubernetes egress NetworkPolicies limited to the management CIDRs (set per site) |
| Packet capture (Zeek) | not in this stack | — (no raw-socket or `NET_ADMIN` grant anywhere) |
