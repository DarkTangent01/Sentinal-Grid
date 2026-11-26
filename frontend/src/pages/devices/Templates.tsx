/** Monitoring templates (polling intervals per metric group, thresholds, interface rules) and interface-history
 *  retention. Editing a template updates every device that uses it; a device's own settings still win. */
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { Card, Empty, Loading, Modal, rowProps, TableWrap, Time } from "../../components/ui";
import { TYPE_LABEL } from "../switches/SwitchesPage";

const THRESHOLDS: [string, string][] = [["util_warn_pct", "Utilisation warning %"], ["util_high_pct", "Utilisation high %"], ["util_crit_pct", "Utilisation critical %"],
  ["cpu_pct", "CPU %"], ["mem_pct", "Memory %"], ["storage_pct", "Storage %"], ["celsius", "Temperature °C"], ["min_errors", "Errors per window"],
  ["min_discards", "Discards per window"]];

export function TemplatesPage() {
  const q = useQuery<any>({ queryKey: ["templates"], queryFn: () => api("/devices/templates") });
  const [edit, setEdit] = useState<any | null>(null);
  return <div className="space-y-4">
    <Card title="Monitoring templates" bodyClass="p-0" right={<button className="btn btn-primary btn-sm" onClick={() => setEdit({})}>New template</button>}>
      <Loading q={q} />
      {q.data && (!q.data.items.length ? <div className="p-4"><Empty text="No templates." /></div> :
        <TableWrap><table className="tbl"><thead><tr><th>Name</th><th>Device type</th><th className="num">Poll interval</th><th>Groups turned off</th>
          <th className="num">Devices</th><th>Updated</th></tr></thead>
          <tbody>{q.data.items.map((t: any) => <tr key={t.id} {...rowProps(() => setEdit(t))}>
            <td><span className="font-medium">{t.name}</span>{t.builtin && <span className="pill text-subtle ml-1.5">built-in</span>}
              <div className="text-2xs text-subtle max-w-xl truncate" title={t.description}>{t.description}</div></td>
            <td className="text-muted">{TYPE_LABEL[t.device_type] || "—"}</td><td className="num">{t.poll_interval_seconds} s</td>
            <td className="text-xs text-muted">{Object.entries(t.group_intervals).filter(([, v]) => v === 0).map(([k]) => k).join(", ") || "—"}</td>
            <td className="num">{t.devices}</td><td><Time v={t.updated_at} /></td></tr>)}</tbody></table></TableWrap>)}
      <p className="text-2xs text-subtle p-3">A device added without a template gets the one for its detected type. Order of precedence: interface → device → template → global rule.</p>
    </Card>
    <Retention />
    {edit && <TemplateForm t={edit} groups={q.data?.groups || []} onClose={() => setEdit(null)} />}
  </div>;
}

function TemplateForm({ t, groups, onClose }: { t: any; groups: any[]; onClose: () => void }) {
  const qc = useQueryClient();
  const [f, setF] = useState(() => ({ name: t.name || "", device_type: t.device_type || "", description: t.description || "", poll_interval_seconds: String(t.poll_interval_seconds || 60),
    gi: Object.fromEntries(Object.entries(t.group_intervals || {}).map(([k, v]) => [k, String(v)])) as Record<string, string>,
    th: Object.fromEntries(Object.entries(t.thresholds || {}).map(([k, v]) => [k, String(v)])) as Record<string, string>,
    exTypes: (t.interface_rules?.exclude_types || []).join(", "), exRe: t.interface_rules?.exclude_regex || "" }));
  const body = () => ({ name: f.name, device_type: f.device_type, description: f.description, poll_interval_seconds: Number(f.poll_interval_seconds) || 60,
    group_intervals: Object.fromEntries(Object.entries(f.gi).filter(([, v]) => v !== "").map(([k, v]) => [k, Number(v)])),
    thresholds: Object.fromEntries(Object.entries(f.th).filter(([, v]) => v !== "").map(([k, v]) => [k, Number(v)])),
    interface_rules: { exclude_types: f.exTypes.split(/[\s,]+/).filter(Boolean).map(Number), exclude_regex: f.exRe || undefined } });
  const save = useMutation<any>({ mutationFn: () => api(t.id ? `/devices/templates/${t.id}` : "/devices/templates", { method: t.id ? "PUT" : "POST", body: body() }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["templates"] }); qc.invalidateQueries({ queryKey: ["devices-meta"] }); onClose(); } });
  const del = useMutation({ mutationFn: () => api(`/devices/templates/${t.id}`, { method: "DELETE" }), onSuccess: () => { qc.invalidateQueries({ queryKey: ["templates"] }); onClose(); } });
  return <Modal title={t.id ? `Edit ${t.name}` : "New monitoring template"} onClose={onClose} wide>
    <div className="grid gap-3 sm:grid-cols-3">
      <label><span className="label">Name</span><input className="input w-full" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></label>
      <label><span className="label">Device type</span><select className="input w-full" value={f.device_type} onChange={(e) => setF({ ...f, device_type: e.target.value })}>
        <option value="">Any</option>{Object.entries(TYPE_LABEL).map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></label>
      <label><span className="label">Device polling interval (s)</span><input className="input w-full" inputMode="numeric" value={f.poll_interval_seconds}
        onChange={(e) => setF({ ...f, poll_interval_seconds: e.target.value.replace(/\D/g, "") })} /></label>
      <label className="sm:col-span-3"><span className="label">Description</span><input className="input w-full" value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></label>
    </div>
    <h3 className="section-title mt-4 mb-2">Metric groups</h3>
    <p className="text-xs text-muted mb-2">Seconds between collections. Empty = the group default; 0 = not collected.</p>
    <div className="grid gap-x-4 gap-y-1.5 sm:grid-cols-2 lg:grid-cols-3">{groups.map((g) => <label key={g.key} className="flex items-center gap-2 text-sm">
      <input className="input w-20 py-1" inputMode="numeric" placeholder={String(g.interval)} aria-label={g.label} value={f.gi[g.key] ?? ""}
        onChange={(e) => setF({ ...f, gi: { ...f.gi, [g.key]: e.target.value.replace(/\D/g, "") } })} /><span className="text-muted truncate" title={g.label}>{g.label}</span></label>)}</div>
    <h3 className="section-title mt-4 mb-2">Thresholds</h3>
    <div className="grid gap-3 sm:grid-cols-3">{THRESHOLDS.map(([k, l]) => <label key={k}><span className="label">{l}</span><input className="input w-full" inputMode="decimal"
      placeholder="rule default" value={f.th[k] ?? ""} onChange={(e) => setF({ ...f, th: { ...f.th, [k]: e.target.value.replace(/[^0-9.]/g, "") } })} /></label>)}</div>
    <h3 className="section-title mt-4 mb-2">Interface rules</h3>
    <div className="grid gap-3 sm:grid-cols-2">
      <label><span className="label">Do not alert on ifTypes</span><input className="input w-full" placeholder="24 (loopback), 131 (tunnel)" value={f.exTypes}
        onChange={(e) => setF({ ...f, exTypes: e.target.value })} /></label>
      <label><span className="label">Do not alert on names matching (regex)</span><input className="input w-full font-mono text-xs" placeholder="^(lo|docker|veth)" value={f.exRe}
        onChange={(e) => setF({ ...f, exRe: e.target.value })} /></label>
    </div>
    {(save.error || del.error) && <div role="alert" className="text-sm text-red-400 mt-3">{((save.error || del.error) as Error).message}</div>}
    <div className="flex gap-2 mt-4"><button className="btn btn-primary" disabled={!f.name || save.isPending} onClick={() => save.mutate()}>{save.isPending ? "Saving…" : "Save"}</button>
      <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
      {t.id && !t.builtin && <button className="btn btn-danger ml-auto" onClick={() => confirm(`Delete ${t.name}? Devices using it keep their own settings.`) && del.mutate()}>Delete</button>}</div>
  </Modal>;
}

function Retention() {
  const qc = useQueryClient();
  const q = useQuery<any>({ queryKey: ["if-retention"], queryFn: () => api("/devices/retention") });
  const [f, setF] = useState<Record<string, string> | null>(null);
  const cur = f ?? Object.fromEntries(Object.entries(q.data?.value || {}).map(([k, v]) => [k, String(v)]));
  const save = useMutation({ mutationFn: () => api("/devices/retention", { method: "PUT", body: Object.fromEntries(Object.entries(cur).map(([k, v]) => [k, Number(v)])) }),
    onSuccess: () => { setF(null); qc.invalidateQueries({ queryKey: ["if-retention"] }); } });
  const rows: [string, string][] = [["raw_days", "Every poll (≈1 min)"], ["five_min_days", "5-minute rollup"], ["hourly_days", "Hourly rollup"]];
  return <Card title="Interface history retention">
    <Loading q={q} />
    {q.data && <>
      <div className="grid gap-3 sm:grid-cols-3">{rows.map(([k, l]) => <label key={k}><span className="label">{l} — days</span>
        <input className="input w-full" inputMode="numeric" value={cur[k] ?? ""} onChange={(e) => setF({ ...cur, [k]: e.target.value.replace(/\D/g, "") })} />
        <span className="help">{q.data.limits[k][0]}–{q.data.limits[k][1]} days · default {q.data.defaults[k]}</span></label>)}</div>
      <p className="text-xs text-muted mt-3">Graphs use the finest resolution that still covers the chosen range. Shortening a period removes older data at the next background merge.</p>
      {save.error && <div role="alert" className="text-sm text-red-400 mt-2">{(save.error as Error).message}</div>}
      <button className="btn btn-primary btn-sm mt-3" disabled={!f || save.isPending} onClick={() => save.mutate()}>{save.isPending ? "Applying…" : "Apply retention"}</button>
    </>}
  </Card>;
}
