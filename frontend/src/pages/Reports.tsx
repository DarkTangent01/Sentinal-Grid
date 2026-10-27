import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useMe } from "../lib/context";
import { Card, Empty, Loading, Modal, TableWrap, Time } from "../components/ui";

const SECTION_LABEL: Record<string, string> = {
  summary: "Traffic summary", alerts: "Alerts", incidents: "Incidents & MTTR", threats: "Top threats", threat_intel: "Threat-intel matches",
  vpn: "VPN", policy_hygiene: "Firewall policy hygiene", compliance: "Compliance evidence", isp_sla: "ISP availability vs SLA",
  firewall_health: "Firewall health", vpn_tunnels: "Site-to-site VPN tunnels",
};

export function Reports() {
  const me = useMe();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["reports"], queryFn: () => api<any>("/reports"), refetchInterval: 60_000 });
  const chs = useQuery({ queryKey: ["n-channels"], queryFn: () => api<any[]>("/notifications/channels"), enabled: me.role === "admin" });
  const [edit, setEdit] = useState<any>(null);
  const run = useMutation({ mutationFn: (id: number) => api<any>(`/reports/${id}/run`, { method: "POST" }), onSuccess: (r) => { qc.invalidateQueries({ queryKey: ["reports"] }); window.open(`/api/reports/runs/${r.id}.html`, "_blank", "noopener"); } });
  const del = useMutation({ mutationFn: (id: number) => api(`/reports/${id}`, { method: "DELETE" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["reports"] }) });
  return (
    <div className="space-y-4 min-w-0">
      <p className="text-xs text-muted">Reports are generated at the chosen local hour and delivered as HTML email through notification channels. Every run is kept here; open a run and use the browser's Print → Save as PDF for a PDF copy.</p>
      <Card title="Scheduled reports" right={me.role === "admin" && <button className="btn btn-primary" onClick={() => setEdit({ name: "Daily SOC report", period: "daily", sections: q.data?.sections || [], channel_ids: [], enabled: true, send_hour: 8, tz: "Asia/Kolkata" })}>+ Report</button>}>
        <Loading q={q} />
        {q.data && !q.data.definitions.length && <Empty text="No scheduled reports." />}
        {!!q.data?.definitions.length && <TableWrap><table className="tbl"><thead><tr><th>Name</th><th>Period</th><th>Delivery</th><th className="w-full">Sections</th><th>Last run</th><th /></tr></thead>
          <tbody>{q.data.definitions.map((d: any) => <tr key={d.id}><td>{d.name}{!d.enabled && <span className="pill bg-slate-800 text-slate-400 ml-1">disabled</span>}</td><td className="text-xs">{d.period}</td>
            <td className="text-xs">{String(d.send_hour).padStart(2, "0")}:00 {d.tz} · {d.channel_ids.length} channel(s)</td><td className="text-xs">{d.sections.map((s: string) => SECTION_LABEL[s] || s).join(", ")}</td>
            <td><Time v={d.last_run} /></td>
            <td className="nowrap">{me.role === "admin" && <><button className="btn" disabled={run.isPending} onClick={() => run.mutate(d.id)}>{run.isPending ? "Running…" : "Run now"}</button>
              <button className="btn ml-1" onClick={() => setEdit(d)}>Edit</button><button className="btn btn-danger ml-1" onClick={() => confirm(`Delete ${d.name}?`) && del.mutate(d.id)}>Delete</button></>}</td></tr>)}</tbody></table></TableWrap>}
      </Card>
      <Card title="Report history">
        {q.data?.runs?.length ? <TableWrap><table className="tbl"><thead><tr><th>Generated</th><th className="w-full">Report</th><th>Period</th><th>Highlights</th><th /></tr></thead>
          <tbody>{q.data.runs.map((r: any) => <tr key={r.id}><td><Time v={r.generated_at} /></td><td>{r.name}</td><td className="text-xs nowrap"><Time v={r.period_start} /> – <Time v={r.period_end} /></td>
            <td className="text-xs">{r.summary?.alerts != null ? `${r.summary.alerts} alerts` : ""}{r.summary?.incidents ? ` · ${r.summary.incidents.total} incidents` : ""}</td>
            <td><a className="btn" href={`/api/reports/runs/${r.id}.html`} target="_blank" rel="noopener noreferrer">Open</a></td></tr>)}</tbody></table></TableWrap>
          : <Empty text="No reports generated yet." />}
      </Card>
      {edit && <ReportForm d={edit} sections={q.data?.sections || []} channels={chs.data || []} onClose={() => { setEdit(null); qc.invalidateQueries({ queryKey: ["reports"] }); }} />}
    </div>
  );
}

function ReportForm({ d, sections, channels, onClose }: { d: any; sections: string[]; channels: any[]; onClose: () => void }) {
  const [f, setF] = useState<any>({ ...d });
  const save = useMutation({ mutationFn: () => {
    const body = { name: f.name, period: f.period, sections: f.sections, channel_ids: f.channel_ids, enabled: f.enabled, send_hour: Number(f.send_hour), tz: f.tz };
    return d.id ? api(`/reports/${d.id}`, { method: "PUT", body }) : api("/reports", { method: "POST", body });
  }, onSuccess: onClose });
  const tog = (k: string, v: any) => setF({ ...f, [k]: f[k].includes(v) ? f[k].filter((x: any) => x !== v) : [...f[k], v] });
  return (
    <Modal title={d.id ? `Edit ${d.name}` : "New report"} onClose={onClose}>
      <div className="grid gap-2 sm:grid-cols-2">
        <div className="sm:col-span-2"><label className="label">Name</label><input className="input w-full" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></div>
        <div><label className="label">Period</label><select className="input w-full" value={f.period} onChange={(e) => setF({ ...f, period: e.target.value })}><option value="daily">Daily (last 24 h)</option><option value="weekly">Weekly (last 7 days)</option><option value="monthly">Monthly (previous calendar month, sent on the 1st)</option></select></div>
        <div className="grid grid-cols-2 gap-2"><div><label className="label">Send at hour</label><input type="number" min={0} max={23} className="input w-full" value={f.send_hour} onChange={(e) => setF({ ...f, send_hour: e.target.value })} /></div>
          <div><label className="label">Timezone</label><input className="input w-full" value={f.tz} onChange={(e) => setF({ ...f, tz: e.target.value })} /></div></div>
        <div className="sm:col-span-2"><label className="label">Sections</label><div className="flex flex-wrap gap-3 text-sm">{sections.map((s) => <label key={s} className="flex items-center gap-1"><input type="checkbox" checked={f.sections.includes(s)} onChange={() => tog("sections", s)} />{SECTION_LABEL[s] || s}</label>)}</div></div>
        <div className="sm:col-span-2"><label className="label">Deliver to channels (email recommended)</label>{channels.length ? <div className="flex flex-wrap gap-3 text-sm">{channels.map((c) => <label key={c.id} className="flex items-center gap-1"><input type="checkbox" checked={f.channel_ids.includes(c.id)} onChange={() => tog("channel_ids", c.id)} />{c.name} ({c.type})</label>)}</div> : <p className="text-xs text-muted">No channels yet; runs are still stored here.</p>}</div>
        <label className="text-sm flex items-center gap-2"><input type="checkbox" checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked })} />Enabled</label>
      </div>
      {save.error && <div role="alert" className="text-sm text-red-400 mt-2">{(save.error as Error).message}</div>}
      <button className="btn btn-primary mt-3" disabled={!f.name || !f.sections.length} onClick={() => save.mutate()}>Save</button>
    </Modal>
  );
}
