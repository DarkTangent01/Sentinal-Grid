import { Fragment, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { Card, Drawer, Empty, Loading, TableWrap, Time, rowProps } from "../../components/ui";
import { Confirm, ErrorBox, FieldDiff, Note, Pager, SevBadge, SideBySide, Status, can, useAct, useMeta } from "./common";

export function Devices({ projects, projectId, status, onDrift }: { projects: any[]; projectId: number | null; status: string; onDrift: (fw: number) => void }) {
  const meta = useMeta().data;
  const [q, setQ] = useState("");
  const [site, setSite] = useState("");
  const [st, setSt] = useState(status);
  const [page, setPage] = useState(1);
  const [sel, setSel] = useState<number[]>([]);
  const [add, setAdd] = useState(false);
  const [detail, setDetail] = useState<any>(null);
  const [onlyProject, setOnlyProject] = useState(true);
  const data = useQuery({ queryKey: ["iac-devices", onlyProject ? projectId : null, q, site, st, page],
    queryFn: () => api<any>("/iac/devices", { params: { project_id: onlyProject && projectId ? projectId : undefined, q, site, status: st, page, size: 50 } }), placeholderData: (p) => p });
  const caps = useAct(async (ids: number[]) => { for (const id of ids) await api(`/iac/devices/${id}/capabilities`, { method: "POST" }); });
  const items = data.data?.items || [];
  const sites = useMemo(() => Array.from(new Set(items.map((d: any) => d.site).filter(Boolean))).sort() as string[], [items]);
  const selectable = items.filter((d: any) => d.device_id);
  return <Card title="Device inventory" bodyClass="p-0" right={<>
    <label className="text-xs flex items-center gap-1"><input type="checkbox" checked={onlyProject} onChange={(e) => { setOnlyProject(e.target.checked); setPage(1); }} disabled={!projectId} />this project only</label>
    <input aria-label="Search devices" className="input py-0.5 text-xs w-40" placeholder="search name / IP" value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} />
    <select aria-label="Site" className="input py-0.5 text-xs" value={site} onChange={(e) => { setSite(e.target.value); setPage(1); }}><option value="">All sites</option>{sites.map((s) => <option key={s}>{s}</option>)}</select>
    <select aria-label="Sync status" className="input py-0.5 text-xs" value={st} onChange={(e) => { setSt(e.target.value); setPage(1); }}>
      <option value="">Any status</option>{["in_sync", "drift", "unknown", "error", "unmanaged"].map((s) => <option key={s} value={s}>{s.replace("_", " ")}</option>)}</select>
    <button className="btn py-0.5 text-xs" disabled={!sel.length || !can(meta, "editor") || caps.isPending} onClick={() => caps.mutate(sel)}>{caps.isPending ? "Checking…" : `Detect capabilities (${sel.length})`}</button>
    <button className="btn btn-primary py-0.5 text-xs" disabled={!can(meta, "admin") || !projectId} title={can(meta, "admin") ? "" : "IaC admin role required"} onClick={() => setAdd(true)}>Add device to project</button></>}>
    <ErrorBox error={caps.error} />
    <Loading q={data} />
    {items.length ? <><TableWrap><table className="tbl"><thead><tr>
      <th><input type="checkbox" aria-label="Select all" checked={selectable.length > 0 && selectable.every((d: any) => sel.includes(d.device_id))}
        onChange={(e) => setSel(e.target.checked ? selectable.map((d: any) => d.device_id) : [])} /></th>
      <th>Device</th><th>Management address</th><th>Site</th><th>Model / firmware</th><th>Integration</th><th>Project</th><th>Sync</th><th>Last backup</th><th>Last drift check</th><th>Last deployment</th></tr></thead>
      <tbody>{items.map((d: any) => <tr key={`${d.firewall_id}:${d.project_id}`} {...rowProps(() => setDetail(d))}>
        <td onClick={(e) => e.stopPropagation()}>{d.device_id && <input type="checkbox" aria-label={`Select ${d.name}`} checked={sel.includes(d.device_id)}
          onChange={(e) => setSel(e.target.checked ? [...sel, d.device_id] : sel.filter((x) => x !== d.device_id))} />}</td>
        <td className="font-semibold text-sm whitespace-nowrap">{d.name}</td><td className="font-mono text-xs">{d.host}</td><td className="text-xs">{d.site || "—"}</td>
        <td className="text-xs whitespace-nowrap">{d.model || "—"} · {d.firmware || "?"}</td>
        <td className="text-xs">{d.integration ? (d.integration === "fortimanager" ? <span className="text-amber-300">FortiManager</span> : "FortiGate REST") : "—"}
          {d.capabilities?.checked_at && <div className="text-2xs text-muted">{d.capabilities.readable?.length} types readable</div>}</td>
        <td className="text-xs">{d.project || "—"}{d.environment && <div className="text-2xs text-muted">{d.environment}</div>}</td>
        <td><Status s={d.managed || d.drift_status === "unmanaged" ? d.drift_status : "unmanaged"} /></td>
        <td><Time v={d.last_backup_at} /></td><td><Time v={d.last_drift_check} /></td>
        <td>{d.last_deploy_at ? <><Time v={d.last_deploy_at} /> <Status s={d.last_deploy_status} /></> : "—"}</td></tr>)}</tbody></table></TableWrap>
      <Pager page={page} size={50} total={data.data.total} onPage={setPage} /></> : !data.isLoading && <Empty text="No devices match. Register FortiGates under Firewalls, then add them to a project." />}
    {add && projectId && <AddDevice projectId={projectId} project={projects.find((p) => p.id === projectId)} onClose={() => setAdd(false)} />}
    {detail && <DeviceDrawer d={detail} onClose={() => setDetail(null)} onDrift={onDrift} />}
  </Card>;
}

function parseVars(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  text.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#")).forEach((l) => { const i = l.indexOf("="); if (i > 0) out[l.slice(0, i).trim()] = l.slice(i + 1).trim(); });
  return out;
}

function AddDevice({ projectId, project, onClose }: { projectId: number; project: any; onClose: () => void }) {
  const fws = useQuery({ queryKey: ["iac-devices", "all-fw"], queryFn: () => api<any>("/iac/devices", { params: { size: 200 } }) });
  const [fw, setFw] = useState<number | "">("");
  const [vars, setVars] = useState("");
  const addm = useAct(() => api(`/iac/projects/${projectId}/devices`, { method: "POST", body: { firewall_id: fw, variables: parseVars(vars) } }), onClose);
  const free = (fws.data?.items || []).filter((d: any) => !d.managed && d.vendor === "fortinet");
  return <Confirm title={`Add a FortiGate to ${project?.name}`} confirmLabel="Add device" busy={addm.isPending} disabled={!fw} onClose={onClose} onConfirm={() => addm.mutate(undefined)}>
    <p className="text-xs text-muted">The device keeps its existing API token (stored encrypted). Adding it changes nothing on the firewall; one project owns each device.</p>
    <select aria-label="Firewall" className="input w-full" value={fw} onChange={(e) => setFw(Number(e.target.value))}><option value="">Select a FortiGate…</option>
      {free.map((d: any) => <option key={d.firewall_id} value={d.firewall_id}>{d.name} · {d.host} · {d.site}</option>)}</select>
    {!fws.isLoading && !free.length && <Note tone="warn">Every registered FortiGate is already managed by a project.</Note>}
    <label className="text-xs block">Device variables (name=value per line)
      <textarea aria-label="Variables" className="input w-full h-24 font-mono mt-1" placeholder={"wan_gateway=203.0.113.1\nlan_subnet=10.21.0.0/16"} value={vars} onChange={(e) => setVars(e.target.value)} /></label>
    <ErrorBox error={addm.error} />
  </Confirm>;
}

function DeviceDrawer({ d, onClose, onDrift }: { d: any; onClose: () => void; onDrift: (fw: number) => void }) {
  const meta = useMeta().data;
  const [vars, setVars] = useState(Object.entries(d.variables || {}).map(([k, v]) => `${k}=${v}`).join("\n"));
  const [remove, setRemove] = useState(false);
  const save = useAct(() => api(`/iac/devices/${d.device_id}`, { method: "PUT", body: { firewall_id: d.firewall_id, variables: parseVars(vars), managed: d.managed } }));
  const del = useAct(() => api(`/iac/devices/${d.device_id}`, { method: "DELETE" }), onClose);
  const caps = useAct(() => api<any>(`/iac/devices/${d.device_id}/capabilities`, { method: "POST" }));
  const c = caps.data || d.capabilities || {};
  return <Drawer title={`${d.name} · ${d.host}`} onClose={onClose}>
    <div className="space-y-4">
      <div className="text-sm flex flex-wrap gap-3"><Status s={d.drift_status} /><span>{d.project || "not managed"}</span><span className="text-muted">{d.model} {d.firmware}</span>
        {d.device_id && <button className="btn py-0.5 text-xs" onClick={() => onDrift(d.firewall_id)}>Drift history</button>}</div>
      {d.device_id ? <>
        <Card title="Capabilities" right={<button className="btn py-0.5 text-xs" disabled={!can(meta, "editor") || caps.isPending} onClick={() => caps.mutate(undefined)}>{caps.isPending ? "Reading…" : "Detect"}</button>}>
          <ErrorBox error={caps.error} />
          {c.checked_at ? <div className="text-xs space-y-1"><div>Integration: <b>{c.integration}</b>{c.fortimanager && <span className="text-amber-300"> — managed by FortiManager, direct deployment blocked</span>}</div>
            <div>Readable: {c.readable?.join(", ") || "none"}</div>
            {Object.keys(c.unreadable || {}).length > 0 && <div className="text-amber-200">Not readable: {Object.entries(c.unreadable).map(([k, v]) => `${k} (${v})`).join("; ")}</div>}
            <div className="text-muted">{c.reason} · checked <Time v={c.checked_at} /></div></div>
            : <Note>Not detected yet. Detection reads the device (GET only).</Note>}
        </Card>
        <Card title="Device variables" right={<button className="btn py-0.5 text-xs" disabled={!can(meta, "editor") || save.isPending} onClick={() => save.mutate(undefined)}>Save</button>}>
          <textarea aria-label="Device variables" className="input w-full h-24 font-mono" value={vars} onChange={(e) => setVars(e.target.value)} readOnly={!can(meta, "editor")} />
          <p className="text-2xs text-muted mt-1">Override project and site variables for this device. Never put secrets here.</p><ErrorBox error={save.error} /></Card>
        {can(meta, "admin") && <button className="btn btn-danger" onClick={() => setRemove(true)}>Remove from project</button>}
      </> : <Note>This FortiGate is not managed by any IaC project.</Note>}
    </div>
    {remove && <Confirm title="Remove device from project" confirmLabel="Remove" danger busy={del.isPending} onClose={() => setRemove(false)} onConfirm={() => del.mutate(undefined)}>
      <p className="text-sm">IaC stops managing {d.name}. Its configuration on the firewall is not changed.</p><ErrorBox error={del.error} /></Confirm>}
  </Drawer>;
}

export function Drift({ projectId, firewallId, severity: sev0 }: { projectId: number | null; firewallId: number | null; severity: string }) {
  const meta = useMeta().data;
  const [sev, setSev] = useState(sev0);
  const [history, setHistory] = useState(false);
  const [days, setDays] = useState(30);
  const [open, setOpen] = useState<number | null>(null);
  const q = useQuery({ queryKey: ["iac-drift", projectId, firewallId, sev, history, days], placeholderData: (p) => p,
    queryFn: () => api<any[]>("/iac/drift", { params: { project_id: projectId || undefined, firewall_id: firewallId || undefined, severity: sev ? [sev] : [], latest: !history, days } }) });
  const run = useAct(() => api(`/iac/projects/${projectId}/drift`, { method: "POST" }));
  return <div className="space-y-4">
    <div className="flex flex-wrap gap-2 items-center">
      <p className="text-xs text-muted flex-1 min-w-[16rem]">Live configuration compared with the approved desired state (and the last deployed version). Drift never triggers an automatic
        overwrite: remediate by planning the approved version again, or update the desired state to accept the change.</p>
      <select aria-label="Severity" className="input py-1 text-xs" value={sev} onChange={(e) => setSev(e.target.value)}><option value="">Any severity</option>
        {["critical", "high", "medium", "low", "info"].map((s) => <option key={s}>{s}</option>)}</select>
      <select aria-label="Time range" className="input py-1 text-xs" value={days} onChange={(e) => setDays(Number(e.target.value))}>{[1, 7, 30, 90].map((d) => <option key={d} value={d}>{d} days</option>)}</select>
      <label className="text-xs flex items-center gap-1"><input type="checkbox" checked={history} onChange={(e) => setHistory(e.target.checked)} />history</label>
      <button className="btn btn-primary py-1" disabled={!projectId || !can(meta, "editor") || run.isPending} onClick={() => run.mutate(undefined)}>{run.isPending ? "Queuing…" : "Run drift check"}</button>
    </div>
    <ErrorBox error={run.error} />
    {run.isSuccess && <Note>Drift check queued; results appear here when the worker finishes (usually seconds).</Note>}
    <Loading q={q} />
    {q.data?.length ? q.data.map((r: any) => <Card key={r.id} title={<span>{r.firewall_name} <Status s={r.status} /> <span className="text-muted text-xs font-normal">checked <Time v={r.checked_at} /></span></span>}
      right={<span className="flex gap-1">{Object.entries(r.counts || {}).filter(([, v]) => v).map(([k, v]: any) => <span key={k} className="text-xs"><SevBadge s={k} /> {v}</span>)}</span>} bodyClass="p-0">
      {r.error && <div className="p-3"><Note tone="bad">{r.error}</Note></div>}
      {r.findings.length ? <TableWrap maxH="max-h-[30rem]"><table className="tbl"><thead><tr><th>Severity</th><th>Resource</th><th>Change on device</th><th className="w-full">Explanation</th><th>Rule</th></tr></thead>
        <tbody>{r.findings.map((f: any, i: number) => <Fragment key={i}><tr {...rowProps(() => setOpen(open === r.id * 10000 + i ? null : r.id * 10000 + i))}>
          <td><SevBadge s={f.severity} /></td><td className="font-mono text-xs whitespace-nowrap">{f.type}{f.key ? `:${f.key}` : ""}</td><td className="text-xs">{f.change}</td>
          <td className="text-xs">{f.explanation}</td><td className="font-mono text-2xs">{f.rule_id}</td></tr>
          {open === r.id * 10000 + i && <tr><td colSpan={5} className="bg-white/5"><div className="space-y-2 p-1"><FieldDiff fields={f.fields} leftLabel="approved" rightLabel="live" />
            <SideBySide left={f.desired} right={f.live} leftLabel="approved desired state" rightLabel="live on the device" /></div></td></tr>}</Fragment>)}</tbody></table></TableWrap>
        : !r.error && <div className="p-3 text-sm text-emerald-300">In sync with the approved configuration.</div>}
    </Card>) : !q.isLoading && <Empty text="No drift checks yet. Drift is measured against an approved version; checks run on schedule (IaC settings) or on demand." />}
  </div>;
}
