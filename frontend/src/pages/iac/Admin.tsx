import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { Card, Empty, Loading, TableWrap, Time } from "../../components/ui";
import { Confirm, ErrorBox, Note, Pager, can, useAct, useMeta } from "./common";

export function Backups({ onPlan }: { onPlan: (id: number) => void }) {
  const meta = useMeta().data;
  const q = useQuery({ queryKey: ["iac-backups"], queryFn: () => api<any[]>("/iac/backups", { params: { size: 100 } }) });
  const verify = useAct((id: number) => api<any>(`/iac/backups/${id}/verify`, { method: "POST" }));
  const rec = useAct((id: number) => api<any>(`/iac/backups/${id}/recovery-plan`, { method: "POST" }), (r) => { setConfirm(null); onPlan(r.id); });
  const [confirm, setConfirm] = useState<any>(null);
  return <Card title="Backups and recovery" bodyClass="p-0">
    <div className="p-3"><Note>Every deployment captures a checksummed backup of each device first: the managed resources (no secrets) and, when the API profile allows it, the full
      configuration file stored encrypted. Recovery builds a normal plan from a backup — it is reviewed, approved and deployed like any change; nothing is restored automatically.</Note></div>
    <ErrorBox error={verify.error || rec.error} />
    {verify.data && <div className="px-3"><Note tone={verify.data.ok ? "info" : "bad"}>Backup check: {verify.data.detail}</Note></div>}
    <Loading q={q} />
    {q.data?.length ? <TableWrap><table className="tbl"><thead><tr><th>#</th><th>Device</th><th>Taken</th><th>Job / plan</th><th>Contents</th><th>Checksum</th><th>Validated</th><th /></tr></thead>
      <tbody>{q.data.map((b: any) => <tr key={b.id}><td className="font-mono">{b.id}</td><td className="text-sm">{b.firewall_name}</td><td><Time v={b.created_at} /></td>
        <td className="font-mono text-xs">{b.job_id ? `job ${b.job_id}` : "—"}{b.plan_id ? ` · plan ${b.plan_id}` : ""}</td>
        <td className="text-xs">{Object.entries(b.objects).map(([k, v]) => `${v} ${k}`).join(", ")}<div className={b.full_config ? "text-emerald-300" : "text-amber-300"}>{b.full_config ? "full configuration (encrypted)" : b.note}</div></td>
        <td className="font-mono text-2xs" title={b.snapshot_sha256}>{b.snapshot_sha256.slice(0, 12)}</td><td className="text-xs">{b.validated ? <span className="text-emerald-300">yes</span> : <span className="text-red-300">no</span>}</td>
        <td className="whitespace-nowrap"><button className="btn py-0.5 text-xs" disabled={!can(meta, "deployer")} onClick={() => verify.mutate(b.id)}>Verify</button>
          <button className="btn py-0.5 text-xs ml-1" disabled={!can(meta, "deployer") || !b.validated} onClick={() => setConfirm(b)}>Recovery plan…</button></td></tr>)}</tbody></table></TableWrap>
      : !q.isLoading && <Empty text="No backups yet. They are taken automatically before each deployment." />}
    {confirm && <Confirm title={`Recovery plan from backup #${confirm.id}`} confirmLabel="Generate recovery plan" busy={rec.isPending} onClose={() => setConfirm(null)} onConfirm={() => rec.mutate(confirm.id)}>
      <p className="text-sm">Reads {confirm.firewall_name} now and plans the changes that bring the resources touched by job {confirm.job_id ?? "—"} back to this backup: objects that job created are deleted,
        modified ones restored. Manual changes made since then to other objects are left alone. Review the plan carefully — it still needs approval and a deployment.</p>
      <ErrorBox error={rec.error} /></Confirm>}
  </Card>;
}

export function Audit({ projectId }: { projectId: number | null }) {
  const [page, setPage] = useState(1);
  const [verify, setVerify] = useState(false);
  const q = useQuery({ queryKey: ["iac-audit", projectId, page, verify], queryFn: () => api<any>("/iac/audit", { params: { project_id: projectId || undefined, page, size: 100, verify } }), placeholderData: (p) => p });
  return <Card title="IaC audit trail" bodyClass="p-0" right={<button className="btn py-0.5 text-xs" onClick={() => setVerify(true)}>Verify hash chain</button>}>
    {q.data?.chain && <div className="p-3"><Note tone={q.data.chain.ok ? "info" : "bad"}>{q.data.chain.ok ? `Hash chain intact (${q.data.chain.checked} records).`
      : `Hash chain BROKEN at record ${q.data.chain.broken_at}: the audit log was modified outside the application.`}</Note></div>}
    <Loading q={q} />
    {q.data?.items?.length ? <><TableWrap maxH="max-h-[40rem]"><table className="tbl"><thead><tr><th>Time</th><th>User</th><th>Action</th><th>Target</th><th className="w-full">Detail</th><th>From</th><th>Hash</th></tr></thead>
      <tbody>{q.data.items.map((a: any) => <tr key={a.id}><td><Time v={a.ts} /></td><td className="text-xs">{a.username}</td><td className="font-mono text-xs">{a.action}</td>
        <td className="text-xs">{a.target || (a.plan_id ? `plan ${a.plan_id}` : a.job_id ? `job ${a.job_id}` : "")}</td>
        <td className="text-2xs font-mono break-all">{JSON.stringify(a.detail)}</td><td className="font-mono text-2xs">{a.client_ip}</td><td className="font-mono text-2xs">{a.hash}</td></tr>)}</tbody></table></TableWrap>
      <Pager page={page} size={100} total={q.data.total} onPage={setPage} /></> : !q.isLoading && <Empty text="No IaC activity yet." />}
  </Card>;
}

export function Settings() {
  const meta = useMeta().data;
  const admin = can(meta, "admin");
  const rules = useQuery({ queryKey: ["iac-rules"], queryFn: () => api<any>("/iac/rules") });
  const roles = useQuery({ queryKey: ["iac-roles"], queryFn: () => api<any[]>("/iac/roles"), enabled: admin });
  const [writesConfirm, setWritesConfirm] = useState(false);
  const putSettings = useAct((d: any) => api("/iac/settings", { method: "PUT", body: d }), () => setWritesConfirm(false));
  const putRule = useAct((r: any) => api(`/iac/rules/${r.rule_id}`, { method: "PUT", body: { severity: r.severity, blocks_deploy: r.blocks_deploy, enabled: r.enabled, params: r.params } }));
  const putRoles = useAct((x: any) => api(`/iac/roles/${x.id}`, { method: "PUT", body: { roles: x.roles } }));
  const delExc = useAct((id: number) => api(`/iac/exceptions/${id}`, { method: "DELETE" }));
  const [exc, setExc] = useState({ rule_id: "IAC-SEC-001", resource: "*", owner: "", justification: "", expires_at: "" });
  const addExc = useAct(() => api("/iac/exceptions", { method: "POST", body: { ...exc, expires_at: exc.expires_at ? new Date(exc.expires_at).toISOString() : "" } }),
    () => setExc({ ...exc, owner: "", justification: "", expires_at: "" }));
  const st = meta?.settings || {};
  const set = (k: string, v: unknown) => putSettings.mutate({ [k]: v });
  return <div className="space-y-4">
    {!admin && <Note>Read-only: changing IaC settings, rules, exceptions and roles requires the IaC admin role.</Note>}
    <ErrorBox error={putSettings.error || putRule.error || putRoles.error || delExc.error} />
    <Card title="Deployment safety">
      <div className="space-y-2 text-sm">
        <div className={meta?.writes_effective ? "text-amber-200" : "text-muted"}>Device writes: <b>{meta?.writes_effective ? "ENABLED" : "disabled"}</b>{!meta?.writes_effective && ` — ${meta?.writes_reason}`}</div>
        <label className="flex gap-2 items-center"><input type="checkbox" disabled={!admin} checked={!!st.writes_enabled} onChange={(e) => e.target.checked ? setWritesConfirm(true) : set("writes_enabled", false)} />
          Allow approved plans to be deployed to devices (also requires IAC_DEVICE_WRITES=true on the server)</label>
        <label className="flex gap-2 items-center"><input type="checkbox" disabled={!admin} checked={!!st.sod_production} onChange={(e) => set("sod_production", e.target.checked)} />
          Separation of duties for production (plan / version author cannot approve)</label>
        <label className="flex gap-2 items-center"><input type="checkbox" disabled={!admin} checked={!!st.sod_all_environments} onChange={(e) => set("sod_all_environments", e.target.checked)} />
          Separation of duties in every environment</label>
        <label className="flex gap-2 items-center"><input type="checkbox" disabled={!admin} checked={!!st.fail_fast} onChange={(e) => set("fail_fast", e.target.checked)} />
          Stop a multi-device deployment at the first failed device</label>
        <label className="flex gap-2 items-center"><input type="checkbox" disabled={!admin} checked={!!st.require_full_backup_production} onChange={(e) => set("require_full_backup_production", e.target.checked)} />
          Production: require a full configuration backup before any change</label>
        <label className="flex gap-2 items-center">Drift check every <input aria-label="Drift interval" type="number" min={5} className="input w-24 py-0.5" disabled={!admin} defaultValue={st.drift_interval_minutes}
          onBlur={(e) => Number(e.target.value) !== st.drift_interval_minutes && set("drift_interval_minutes", Number(e.target.value))} /> minutes</label>
        <label className="flex gap-2 items-center">Plans expire after <input aria-label="Plan max age" type="number" min={1} max={168} className="input w-24 py-0.5" disabled={!admin} defaultValue={st.plan_max_age_hours}
          onBlur={(e) => Number(e.target.value) !== st.plan_max_age_hours && set("plan_max_age_hours", Number(e.target.value))} /> hours</label>
      </div>
    </Card>
    <Card title="Validation and drift rules" bodyClass="p-0">
      <Loading q={rules} />
      {rules.data && <TableWrap maxH="max-h-[30rem]"><table className="tbl"><thead><tr><th>Rule</th><th className="w-full">Title</th><th>Severity</th><th>Blocks deploy</th><th>Enabled</th></tr></thead>
        <tbody>{rules.data.rules.map((r: any) => <tr key={r.rule_id}><td className="font-mono text-xs whitespace-nowrap">{r.rule_id}</td><td className="text-xs">{r.title}<div className="text-muted">{r.remediation}</div></td>
          <td><select aria-label={`${r.rule_id} severity`} className="input py-0.5 text-xs" disabled={!admin} value={r.severity} onChange={(e) => putRule.mutate({ ...r, severity: e.target.value })}>
            {["info", "low", "medium", "high", "critical"].map((s) => <option key={s}>{s}</option>)}</select></td>
          <td><input type="checkbox" aria-label={`${r.rule_id} blocks`} disabled={!admin || r.family !== "security"} checked={r.blocks_deploy} onChange={(e) => putRule.mutate({ ...r, blocks_deploy: e.target.checked })} /></td>
          <td><input type="checkbox" aria-label={`${r.rule_id} enabled`} disabled={!admin} checked={r.enabled} onChange={(e) => putRule.mutate({ ...r, enabled: e.target.checked })} /></td></tr>)}</tbody></table></TableWrap>}
    </Card>
    <Card title="Exceptions (owner, justification, expiry)">
      {rules.data?.exceptions?.length ? <TableWrap><table className="tbl"><thead><tr><th>Rule</th><th>Resource</th><th>Owner</th><th className="w-full">Justification</th><th>Expires</th><th /></tr></thead>
        <tbody>{rules.data.exceptions.map((e: any) => <tr key={e.id}><td className="font-mono text-xs">{e.rule_id}</td><td className="font-mono text-xs">{e.resource}</td><td className="text-xs">{e.owner}</td>
          <td className="text-xs">{e.justification}</td><td><Time v={e.expires_at} /></td><td><button className="btn py-0.5 text-xs" disabled={!admin} onClick={() => delExc.mutate(e.id)}>Remove</button></td></tr>)}</tbody></table></TableWrap>
        : <p className="text-xs text-muted mb-2">No exceptions.</p>}
      {admin && <div className="grid gap-2 md:grid-cols-6 mt-3 items-end">
        <select aria-label="Rule" className="input text-xs" value={exc.rule_id} onChange={(e) => setExc({ ...exc, rule_id: e.target.value })}>
          {(rules.data?.rules || []).filter((r: any) => r.family === "security").map((r: any) => <option key={r.rule_id}>{r.rule_id}</option>)}</select>
        <input aria-label="Resource" className="input text-xs" placeholder="policy:100 or address:*" value={exc.resource} onChange={(e) => setExc({ ...exc, resource: e.target.value })} />
        <input aria-label="Owner" className="input text-xs" placeholder="owner" value={exc.owner} onChange={(e) => setExc({ ...exc, owner: e.target.value })} />
        <input aria-label="Justification" className="input text-xs md:col-span-2" placeholder="justification (min 10 chars)" value={exc.justification} onChange={(e) => setExc({ ...exc, justification: e.target.value })} />
        <input aria-label="Expires" type="date" className="input text-xs" value={exc.expires_at} onChange={(e) => setExc({ ...exc, expires_at: e.target.value })} />
        <button className="btn btn-primary text-xs md:col-span-6 justify-self-start" disabled={addExc.isPending || !exc.owner || exc.justification.length < 10 || !exc.expires_at} onClick={() => addExc.mutate(undefined)}>Add exception</button>
        <div className="md:col-span-6"><ErrorBox error={addExc.error} /></div></div>}
    </Card>
    {admin && <Card title="IaC roles" bodyClass="p-0">
      <Loading q={roles} />
      {roles.data && <TableWrap><table className="tbl"><thead><tr><th>User</th><th>SIEM role</th>{["editor", "approver", "deployer", "admin"].map((r) => <th key={r}>{r}</th>)}</tr></thead>
        <tbody>{roles.data.map((u: any) => <tr key={u.id}><td className="text-sm">{u.username}</td><td className="text-xs">{u.siem_role}{u.siem_role === "admin" && <span className="text-muted"> (all IaC roles)</span>}</td>
          {["editor", "approver", "deployer", "admin"].map((r) => <td key={r}><input type="checkbox" aria-label={`${u.username} ${r}`} disabled={u.siem_role === "admin"} checked={u.effective.includes(r)}
            onChange={(e) => putRoles.mutate({ id: u.id, roles: e.target.checked ? [...u.iac_roles, r] : u.iac_roles.filter((x: string) => x !== r) })} /></td>)}</tr>)}</tbody></table></TableWrap>}
      <p className="text-2xs text-muted p-3">Everyone signed in can view IaC (viewer). Changing a user's roles signs them out of existing sessions.</p>
    </Card>}
    {writesConfirm && <Confirm title="Enable device writes" confirmLabel="Enable writes" danger busy={putSettings.isPending} onClose={() => setWritesConfirm(false)} onConfirm={() => set("writes_enabled", true)}>
      <p className="text-sm">Deployers will be able to apply approved, non-stale plans to FortiGates through the REST API. This is the only way the SIEM ever changes a firewall.
        The server must also run with IAC_DEVICE_WRITES=true.</p></Confirm>}
  </div>;
}

