# Container security: final report (third pass, 2026-11-14)

Assessment: CONTAINER_SECURITY_ASSESSMENT.md. Host procedures: CONTAINER_HARDENING_RUNBOOK.md. Kubernetes: k8s/README.md.

## What changed

| Area | Change | Files |
|---|---|---|
| Compose | `init: true` everywhere; tmpfs `noexec,nosuid,nodev`; postgres, clickhouse, ingress, tacacs read-only; ClickHouse non-root with no capability and a pids limit; TACACS+ non-root with no capability and `no-new-privileges:true` (port 49 via namespaced sysctl); SELinux labels on shared bind mounts (`:z` / `:Z`) | `docker-compose.yml` |
| Images | tac_plus-ng file capability removed (and `libcap2-bin`); image runs as `USER 10003:10050`; volume directories owned by tacacs; entrypoint works unprivileged (root path kept for legacy starts). Backend: writable fontconfig cache | `deploy/tacacs/Dockerfile`, `deploy/tacacs/entrypoint.sh`, `backend/Dockerfile` |
| Web | resolver and api address moved to `upstream.inc` (Compose default unchanged; Kubernetes replaces it: Docker's 127.0.0.11 does not exist in a cluster, and nginx ignores search domains) | `frontend/nginx.conf`, `frontend/proxy_params.inc`, `frontend/upstream.inc`, `frontend/Dockerfile` |
| Kubernetes | new: namespace (restricted PSA), 12 service accounts without tokens, 3 human Roles, default-deny + 14 workload NetworkPolicies, 2 StatefulSets, 9 Deployments, migrate Job, 6 PVCs, external Services, admission policy, 3 overlays | `k8s/` |
| Validation | 7 scripts + 2 checkers: Docker / Podman runtime audit, Kubernetes static / live audit, non-root, NetworkPolicy probes, image scan + SBOM, deployment validation | `scripts/security/` |
| Tests / CI | container policy test raised to the new baseline (no capability anywhere, init, read-only, hardened tmpfs, non-root ClickHouse / TACACS+); CI renders and audits every Kubernetes overlay | `backend/tests/test_secret_files.py`, `.github/workflows/ci.yml` |

## Verification

| Check | Result |
|---|---|
| Hardened stack, local Podman (scratch copy, throwaway secrets): PostgreSQL and ClickHouse read-only and non-root from a fresh volume | healthy |
| `scripts/security/docker-security-audit.sh` (Podman) on that stack | **160 PASS, 0 FAIL**; every process `capeff none`, none uid 0 |
| TACACS+ end to end through the hardened stack (`scripts/lab/tacacs_e2e.py`): tacacs as uid 10003, no capability, no-new-privileges, read-only | **62 / 62** |
| Reworked nginx config | `nginx -t` OK; `/api/health` through the proxy OK |
| `docker-compose.yml` policy tests (`backend/tests/test_secret_files.py`) | 25 / 25 |
| Full backend suite | 568 passed |
| Kubernetes overlays: `kubectl kustomize` + kubeconform (strict, k8s 1.31) | development 64 / staging 64 / production 66 objects, all valid |
| `scripts/security/k8s_audit.py` on the rendered overlays | development 241 PASS, staging 241 PASS, production 253 PASS (with digest requirement), **0 FAIL, 0 WARN** |
| Kubernetes on a live cluster (kind): admission, pods, NetworkPolicy probes | **not run**: the kind node image could not be pulled (corporate TLS inspection, 95 attempts over ~45 min) |

**Lab notes:**
- Local builds could not fetch Debian packages (the corporate proxy returns 403), so the lab used the existing local
  images with the new TACACS+ entrypoint and configuration layered on top.
- The new Compose file and nginx configuration were used as written.
- Podman's Docker-compatible API splits exec-form healthcheck commands, so `python -c` healthchecks report unhealthy
  under Podman. The services themselves answered. Docker, used in production, is not affected.

## Production deploy (2026-11-14 06:41 UTC)

| Check | Result |
|---|---|
| All services after the deploy | healthy (api, worker, 3 pollers, syslog, traps, flows, web, ingress, postgres, clickhouse); TACACS+ up |
| `scripts/security/container_audit.py` on production (Docker) | **208 PASS, 0 FAIL**, 6 WARN (web / syslog / traps / TACACS+ published on all interfaces: runbook §3) |
| TACACS+ process | uid 10003, `CapEff 0`, `NoNewPrivs 1`; tac_plus-ng running and listening; port 49 accepts connections |
| Syslog ingestion into ClickHouse (non-root, read-only) | 77–84k events per batch window, as before |
| PDF reports | render, with no fontconfig warnings |
| Errors since the deploy | one harmless line: the PostgreSQL entrypoint cannot `chmod` its tmpfs socket directory as uid 70 (the tmpfs is already mode 3777); PostgreSQL is healthy |

## Acceptance criteria

| Requirement | Compose (production host) after deploy | Kubernetes manifests |
|---|---|---|
| Application containers non-root | yes: every service runs as its own uid from the start | `runAsNonRoot`, fixed uids, audited |
| Privileged containers | none | none (restricted PSA) |
| Privilege escalation | disabled everywhere (`no-new-privileges:true`) | `allowPrivilegeEscalation: false` |
| Linux capabilities | none added anywhere, `cap_drop: ALL` | drop ALL, none added |
| Read-only root filesystem | every service | every container |
| Host filesystem access | read-only binds of certs / GeoIP / secrets; one RW bind (ClickHouse backups); no system directories | no hostPath |
| Runtime socket | never mounted (test-enforced) | n/a |
| Container isolation | separate networks, internal backend / ingest; SELinux confinement pending a host change (runbook §2) | default-deny NetworkPolicies, per-workload SAs |
| Least-privilege RBAC | n/a | no workload has API access; human Roles without wildcards or Secret reads |
| Pod Security | n/a | restricted, enforced, no exception namespace |
| Network policies | n/a | default deny + documented flows |
| Secrets | files, scoped per service, never in env / images / Git | Secret volumes 0440, per-workload keys; examples only in Git |
| Image security | pinned digests, Trivy + SBOM in CI, local `image-scan.sh` | + admission policy (digest + registry) in production |
| Resource limits | CPU / memory / pids on every service (ClickHouse pids 4096) | requests + limits incl. ephemeral storage |
| Persistent storage | volumes untouched by this change | PVCs, no deletes in any procedure |
| Automated validation | `docker-security-audit.sh`, `validate-*.sh` | `kubernetes-security-audit.sh`, `validate-network-policies.sh`, CI |

## Not done or not verified

- **Live Kubernetes run not done.** The manifests are schema-valid and pass the static audit, but they have not been
  admitted by a real API server and started. Run when a cluster is reachable:
  ```bash
  kind create cluster
  # load the four images
  kubectl apply -k k8s/overlays/development
  ./scripts/security/validate-deployment.sh k8s
  ```
- **Host changes are documented, not applied:**
  - Docker SELinux support (§2), which restarts Docker;
  - firewalld / `DOCKER-USER` allowlists (§3);
  - restricting the `docker` group (§4).
- **Image signing:** Cosign needs a registry, and there is none in the Compose deployment (runbook §6).
- **Falco:** evaluated, not installed (runbook §5).
- **Out of scope here:** Redis, Zeek sensors, Prometheus and Grafana are not part of this stack. Zeek data arrives as
  logs; Prometheus scrapes `/api/metrics`.
