# Sentinel on Kubernetes

Kustomize manifests for Sentinel Grid and Sentinel NMS. The production host still runs **Docker Compose**: nothing here
migrates it. These manifests are prepared and validated separately. Moving production is a planned migration with a data
copy (see the end of this file), never an automatic switch.

## Layout

```
k8s/
├── base/                     kustomization assembling everything below; namespace "sentinel"
│   └── configmaps/           backend-config (non-secret settings: the Compose .env)
├── namespaces/               namespace with Pod Security "restricted" (enforce / audit / warn)
├── security/
│   ├── service-accounts/     one per workload, token automount disabled
│   ├── rbac/                 operator (read-only), deployer (no Secret access), secret-admin (named Secrets only)
│   ├── network-policies/     default deny in + out, then one policy per workload (flows documented per policy)
│   └── admission-policies/   ValidatingAdmissionPolicy: approved registry + digest-pinned images (production overlay)
├── databases/                postgres and clickhouse StatefulSets (non-root, read-only roots, own PVCs)
├── storage/                  application PVCs (no hostPath anywhere)
├── applications/
│   ├── backend/              api, worker, poller, syslog, traps, flows, migrate Job
│   ├── frontend/             web (nginx, TLS)
│   └── integrations/         ingress-relay (rsyslog), tacacs (tac_plus-ng)
├── ingress/                  LoadBalancer Services for users and devices (externalTrafficPolicy: Local)
├── secrets/                  secrets.example.yaml only (never real values; not part of any build)
└── overlays/
    ├── development/          kind / local: local images, small requests, NodePort, ReadWriteOnce
    ├── staging/
    └── production/           digests, RWX class for TACACS+ volumes, source ranges, narrowed CIDRs, image policy
```

## Security model

| Control | How |
|---|---|
| Non-root | every pod `runAsNonRoot` with a fixed uid / gid: app 10001, nginx 101, rsyslog 10002, TACACS+ 10003 / 10050, postgres 70, ClickHouse 101 |
| No escalation | `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, nothing added, `seccompProfile: RuntimeDefault` |
| Read-only roots | `readOnlyRootFilesystem: true` everywhere. Writable paths are memory `emptyDir`s with size limits, or PVCs |
| Pod Security | namespace enforces **restricted**. There is no exception namespace: TACACS+ binds 49 through the safe sysctl `net.ipv4.ip_unprivileged_port_start` |
| Host isolation | no hostPath, hostNetwork, hostPID, hostIPC, privileged or devices (audited by `scripts/security/k8s_audit.py`) |
| API access | no workload calls the Kubernetes API: dedicated service accounts, no token mounted, no Role bound |
| Human RBAC | `sentinel-operator` read-only; `sentinel-deployer` rolls out but cannot read Secrets; `sentinel-secret-admin` touches only the three named Secrets. No wildcards; nobody has `pods/exec` here |
| Network | default deny in and out; explicit flows only. The databases accept only the backend services and have no egress. Syslog (untrusted input) reaches only the databases |
| Secrets | Secret volumes at `/run/secrets` (the apps' `*_FILE` settings), mode 0440 with the pod's group, only the keys each workload needs. Never in ConfigMaps or images |
| Images | production overlay: digest-pinned, admission policy refuses others |
| Resources | requests and limits for CPU, memory and ephemeral storage on every container. Base values come from production usage (2026-11-14) |
| Probes | startup / readiness / liveness on every long-running container |

## Prerequisites

- **Kubernetes:** ≥ 1.30 (ValidatingAdmissionPolicy GA).
- **CNI:** one that enforces NetworkPolicy (Calico, Cilium, kube-router; kind ≥ 0.24 kindnet).
- **Storage:** a default StorageClass (encrypted in production) and a **ReadWriteMany** class for `tacacs-config` /
  `tacacs-logs`, which are shared by tacacs, worker and api. On a single node, ReadWriteOnce works because one node
  can mount a claim in several pods.
- **Load balancer:** a provider that keeps the client address (MetalLB / cloud LB with `externalTrafficPolicy: Local`).
  The collectors accept only inventory devices by source IP.
- **ClickHouse file limit:** ClickHouse wants a high open-file limit. Set the node's container-runtime default (Kubernetes
  has no per-pod ulimit).

## Deploy

```bash
# 1. Namespace, RBAC, policies first (no workloads yet): see what will change
kubectl diff -k k8s/overlays/production

# 2. Secrets, out of band (same files as the Compose deployment: ./scripts/gen-secrets.sh)
kubectl create namespace sentinel --dry-run=client -o yaml | kubectl apply -f -
kubectl -n sentinel create secret generic sentinel-app-secrets \
  --from-file=secrets/db_app_password --from-file=secrets/clickhouse_app_password --from-file=secrets/secret_key \
  --from-file=secrets/token_encryption_key --from-file=secrets/token_encryption_key_previous \
  --from-file=secrets/anthropic_api_key --from-file=secrets/bootstrap_admin_password
kubectl -n sentinel create secret generic sentinel-db-secrets \
  --from-file=secrets/postgres_password --from-file=secrets/clickhouse_password
kubectl -n sentinel create secret tls sentinel-web-tls --cert=deploy/certs/siem.crt --key=deploy/certs/siem.key

# 3. Everything (databases start first; the migrate Job waits for them)
kubectl apply -k k8s/overlays/production
kubectl -n sentinel wait --for=condition=complete job/migrate --timeout=15m
kubectl -n sentinel rollout status deploy --timeout=10m

# 4. Least-privilege database users: the same scripts as Compose, run once against the pods; then keep
#    DATABASE_URL / CLICKHOUSE_USER on the siem_app users (base ConfigMap)
# 5. Validate
./scripts/security/validate-deployment.sh k8s sentinel
```

For later releases, run migrations first, then the rollout:

```bash
kubectl -n sentinel delete job migrate --ignore-not-found
kubectl apply -k k8s/overlays/production
```

## Validate

| Script | What it proves |
|---|---|
| `scripts/security/kubernetes-security-audit.sh render <overlay>` | the build renders, schemas are valid (kubeconform), restricted contexts, RBAC, policies, digests (production) |
| `scripts/security/kubernetes-security-audit.sh live` | the same on what is actually running |
| `scripts/security/validate-network-policies.sh` | allowed and denied connections, by real connection attempts from inside the pods |
| `scripts/security/validate-nonroot.sh k8s` | no container runs as uid 0 |
| `scripts/security/validate-deployment.sh k8s` | all of the above plus pod health |

The development overlay was applied to a throwaway kind cluster. See the "Kind validation" section of
security/CONTAINER_HARDENING_RUNBOOK.md for the results.

## Rollback

- **Workloads:**
  ```bash
  kubectl -n sentinel rollout undo deploy/<name>
  ```
  Or re-apply the previous commit's overlay.
- **Migrations:** they are additive, so older images run against the newer schema.
- **Never delete a PVC or PV** to roll back. `kubectl delete -k` would remove the claims together with the data; use
  `kubectl delete deploy,statefulset,svc,job -l app.kubernetes.io/part-of=sentinel -n sentinel` if you must stop
  everything, and keep the claims.

## Migrating production from Compose (planned change, not automatic)

1. Freeze changes and take the Compose backups (`scripts/backup.sh`: PostgreSQL dump, ClickHouse BACKUP).
2. Deploy to Kubernetes with empty volumes, restore both backups into the new databases, and run the migrate Job.
3. Move device-facing addresses (syslog, traps, flows, TACACS+) and the web address to the new Services, during a
   maintenance window. Keep the Compose stack stopped, not removed, until the new one is accepted.
