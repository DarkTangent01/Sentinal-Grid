#!/usr/bin/env python3
"""Kubernetes security audit of the Sentinel workloads: rendered manifests (kustomize build output) or a live cluster.

Usage:
  k8s_audit.py --manifests rendered.yaml        static: what will be applied
  k8s_audit.py --live [--namespace sentinel]    live: what is running (kubectl get -o json)
  [--only nonroot|netpol] [--require-digests]
PASS / FAIL / WARN per check; exit 1 on any FAIL. Needs PyYAML for --manifests (live mode uses JSON only).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys

results: list[tuple[str, str, str, str]] = []
WORKLOADS = ("Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod")
ALLOWED_SYSCTLS = {"net.ipv4.ip_unprivileged_port_start", "net.ipv4.ip_local_port_range", "net.ipv4.tcp_syncookies", "net.ipv4.ping_group_range",
                   "kernel.shm_rmid_forced", "net.ipv4.ip_local_reserved_ports", "net.ipv4.tcp_keepalive_time", "net.ipv4.tcp_fin_timeout",
                   "net.ipv4.tcp_keepalive_intvl", "net.ipv4.tcp_keepalive_probes"}


def rec(status, obj, check, detail=""):
    results.append((status, obj, check, detail))


def pod_spec(o):
    k = o["kind"]
    if k == "Pod":
        return o["spec"]
    if k == "CronJob":
        return o["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    return o["spec"]["template"]["spec"]


def audit_workload(o, only=None, require_digests=False):
    name = f"{o['kind']}/{o['metadata']['name']}"
    ps = pod_spec(o)
    psc = ps.get("securityContext") or {}
    containers = list(ps.get("containers") or []) + list(ps.get("initContainers") or [])
    # non-root
    for c in containers:
        csc = c.get("securityContext") or {}
        nonroot = csc.get("runAsNonRoot", psc.get("runAsNonRoot"))
        uid = csc.get("runAsUser", psc.get("runAsUser"))
        rec("PASS" if nonroot and uid not in (0, None) else ("FAIL" if uid == 0 or not nonroot else "WARN"), f"{name}:{c['name']}", "runs as non-root",
            f"runAsNonRoot={nonroot} runAsUser={uid}")
    if only == "nonroot":
        return
    rec("FAIL" if any(ps.get(k) for k in ("hostNetwork", "hostPID", "hostIPC")) else "PASS", name, "no host namespaces")
    sec = (psc.get("seccompProfile") or {}).get("type")
    for c in containers:
        csc = c.get("securityContext") or {}
        cn = f"{name}:{c['name']}"
        rec("FAIL" if csc.get("privileged") else "PASS", cn, "not privileged")
        rec("PASS" if csc.get("allowPrivilegeEscalation") is False else "FAIL", cn, "allowPrivilegeEscalation false")
        rec("PASS" if csc.get("readOnlyRootFilesystem") else "WARN", cn, "read-only root filesystem")
        caps = csc.get("capabilities") or {}
        rec("PASS" if "ALL" in (caps.get("drop") or []) else "FAIL", cn, "capabilities drop ALL")
        rec("FAIL" if caps.get("add") else "PASS", cn, "no added capabilities", str(caps.get("add") or ""))
        rec("PASS" if ((csc.get("seccompProfile") or {}).get("type") or sec) in ("RuntimeDefault", "Localhost") else "FAIL", cn, "seccomp profile")
        r = c.get("resources") or {}
        ok = all((r.get(s) or {}).get(k) for s in ("requests", "limits") for k in ("cpu", "memory"))
        rec("PASS" if ok else "FAIL", cn, "cpu / memory requests and limits")
        rec("PASS" if (r.get("limits") or {}).get("ephemeral-storage") else "WARN", cn, "ephemeral-storage limit")
        if o["kind"] != "Job" and c in (ps.get("containers") or []):
            rec("PASS" if c.get("livenessProbe") else "WARN", cn, "liveness probe")
            rec("PASS" if c.get("readinessProbe") or not c.get("ports") else "WARN", cn, "readiness probe")
        img = c.get("image", "")
        if require_digests:
            rec("PASS" if "@sha256:" in img else "FAIL", cn, "image pinned by digest", img)
        elif ":latest" in img or (":" not in img.split("/")[-1] and "@" not in img):
            rec("FAIL", cn, "image tag not latest / untagged", img)
    for v in ps.get("volumes") or []:
        rec("FAIL" if "hostPath" in v else "PASS", f"{name}:{v['name']}", "no hostPath volume")
    for s in psc.get("sysctls") or []:
        rec("PASS" if s["name"] in ALLOWED_SYSCTLS else "FAIL", name, "only safe sysctls", s["name"])
    rec("PASS" if ps.get("automountServiceAccountToken") is False else "WARN", name, "no service-account token mounted")
    rec("FAIL" if ps.get("serviceAccountName") in (None, "", "default") else "PASS", name, "dedicated service account",
        ps.get("serviceAccountName") or "default")


def selects(sel, labels):
    ml = (sel or {}).get("matchLabels") or {}
    return all(labels.get(k) == v for k, v in ml.items()) and not (sel or {}).get("matchExpressions")


def audit(objs, only=None, require_digests=False):
    work = [o for o in objs if o.get("kind") in WORKLOADS and not (o["kind"] == "Pod" and o["metadata"].get("ownerReferences"))]
    if not work:
        rec("WARN", "-", "workloads", "none found: nothing tested")
    for o in work:
        audit_workload(o, only, require_digests)
    if only == "nonroot":
        return
    nps = [o for o in objs if o.get("kind") == "NetworkPolicy"]
    if only in (None, "netpol"):
        deny = [n for n in nps if n["spec"].get("podSelector") in ({}, None) and set(n["spec"].get("policyTypes") or []) >= {"Ingress", "Egress"}
                and not n["spec"].get("ingress") and not n["spec"].get("egress")]
        rec("PASS" if deny else "FAIL", "NetworkPolicy", "default deny ingress + egress", ", ".join(n["metadata"]["name"] for n in deny))
        for o in work:
            labels = ((o["spec"].get("template") or {}).get("metadata") or {}).get("labels") or o["metadata"].get("labels") or {}
            own = [n["metadata"]["name"] for n in nps if n["spec"].get("podSelector") and selects(n["spec"]["podSelector"], labels)]
            rec("PASS" if own else "WARN", f"{o['kind']}/{o['metadata']['name']}", "has explicit NetworkPolicy", ", ".join(own) or "default deny only")
        for n in nps:
            for e in n["spec"].get("egress") or []:
                if not e.get("to") and not e.get("ports"):
                    rec("FAIL", f"NetworkPolicy/{n['metadata']['name']}", "no unrestricted egress rule")
            for i in n["spec"].get("ingress") or []:
                if not i.get("from") and not i.get("ports"):
                    rec("FAIL", f"NetworkPolicy/{n['metadata']['name']}", "no unrestricted ingress rule")
    if only == "netpol":
        return
    for ns in (o for o in objs if o.get("kind") == "Namespace"):
        lab = ns["metadata"].get("labels") or {}
        rec("PASS" if lab.get("pod-security.kubernetes.io/enforce") == "restricted" else "FAIL", f"Namespace/{ns['metadata']['name']}",
            "Pod Security restricted enforced", lab.get("pod-security.kubernetes.io/enforce", "-"))
    for r in (o for o in objs if o.get("kind") in ("Role", "ClusterRole")):
        wild = [rule for rule in r.get("rules") or [] if "*" in (rule.get("verbs") or []) + (rule.get("resources") or []) + (rule.get("apiGroups") or [])]
        rec("FAIL" if wild else "PASS", f"{r['kind']}/{r['metadata']['name']}", "no wildcard RBAC rules")
        broad = [rule for rule in r.get("rules") or [] if "secrets" in (rule.get("resources") or []) and set(rule.get("verbs") or []) & {"get", "list", "watch"}
                 and not rule.get("resourceNames")]
        rec("FAIL" if broad else "PASS", f"{r['kind']}/{r['metadata']['name']}", "no blanket Secret read access")
    for b in (o for o in objs if o.get("kind") in ("RoleBinding", "ClusterRoleBinding")):
        bad = b["roleRef"]["name"] in ("cluster-admin", "admin", "edit") and any(s.get("kind") == "ServiceAccount" for s in b.get("subjects") or [])
        rec("FAIL" if bad else "PASS", f"{b['kind']}/{b['metadata']['name']}", "no admin role bound to a service account", b["roleRef"]["name"])
    for sa in (o for o in objs if o.get("kind") == "ServiceAccount" and o["metadata"]["name"] != "default"):
        rec("PASS" if sa.get("automountServiceAccountToken") is False else "WARN", f"ServiceAccount/{sa['metadata']['name']}", "token automount disabled")
    for cm in (o for o in objs if o.get("kind") == "ConfigMap"):
        sus = [k for k in (cm.get("data") or {}) if any(w in k.upper() for w in ("PASSWORD", "SECRET", "TOKEN", "PRIVATE_KEY", "API_KEY"))
               and not k.upper().endswith("_FILE")]
        rec("FAIL" if sus else "PASS", f"ConfigMap/{cm['metadata']['name']}", "no secret values in ConfigMap", ", ".join(sus))
    for pvc in (o for o in objs if o.get("kind") == "PersistentVolume"):
        rec("FAIL" if "hostPath" in pvc.get("spec", {}) else "PASS", f"PV/{pvc['metadata']['name']}", "no hostPath PersistentVolume")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--manifests")
    g.add_argument("--live", action="store_true")
    ap.add_argument("--namespace", default="sentinel")
    ap.add_argument("--only", choices=["nonroot", "netpol"])
    ap.add_argument("--require-digests", action="store_true")
    a = ap.parse_args()
    if a.manifests:
        import yaml
        objs = [d for d in yaml.safe_load_all(open(a.manifests)) if d]
    else:
        def get(kinds, ns=True):
            out = subprocess.run(["kubectl", "get", kinds, "-o", "json"] + (["-n", a.namespace] if ns else []), capture_output=True, text=True, check=True)
            return json.loads(out.stdout)["items"]
        objs = get("deployments,statefulsets,daemonsets,jobs,cronjobs,pods,networkpolicies,roles,rolebindings,serviceaccounts,configmaps")
        objs += [n for n in get("namespaces", ns=False) if n["metadata"]["name"] == a.namespace]
        objs += [b for b in get("clusterrolebindings", ns=False)
                 if any(s.get("namespace") == a.namespace for s in b.get("subjects") or [])]
    audit(objs, a.only, a.require_digests)
    for st, n, c, d in results:
        print(f"{st:<5} {n:<52} {c:<42} {d}")
    counts = {s: sum(1 for r in results if r[0] == s) for s in ("PASS", "WARN", "FAIL")}
    print(f"summary: {counts['PASS']} PASS, {counts['WARN']} WARN, {counts['FAIL']} FAIL")
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
