import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useMe } from "../lib/context";
import { fmtNum } from "../lib/format";
import { Card, Empty, IpLink, Kpi, Loading, Modal, TableWrap, Time, Trunc, rowProps, useDebounced } from "../components/ui";

export const CRIT_CLS: Record<string, string> = {
  critical: "bg-red-500/15 text-red-300", high: "bg-orange-500/15 text-orange-300", normal: "bg-slate-700/60 text-slate-300", low: "bg-slate-800 text-slate-400",
};

export function Assets() {
  const me = useMe();
  const [q, setQ] = useState("");
  const dq = useDebounced(q);
  const [crit, setCrit] = useState("");
  const [page, setPage] = useState(1);
  const [edit, setEdit] = useState<any>(null);
  const r = useQuery({ queryKey: ["assets", dq, crit, page], queryFn: () => api<any>("/assets", { params: { q: dq, criticality: crit, page, size: 50 } }), placeholderData: (p) => p });
  const c = r.data?.counts || {};
  const pages = r.data ? Math.max(1, Math.ceil(r.data.total / 50)) : 1;
  return (
    <div className="space-y-4 min-w-0">
      <p className="text-xs text-muted">Internal hosts are learned every 10 minutes from traffic (FortiGate device identification: host name, MAC, OS; user from firewall authentication). Mark business-critical assets: alerts involving a <b>critical</b> asset are raised one severity level, and incidents show the asset context.</p>
      <div className="kpi-grid">
        <Kpi label="Assets" value={fmtNum(r.data?.total)} onClick={() => setCrit("")} />
        {["critical", "high", "normal", "low"].map((k) => <Kpi key={k} label={k} value={fmtNum(c[k] || 0)} tone={k === "critical" && c[k] ? "bad" : undefined} onClick={() => { setCrit(crit === k ? "" : k); setPage(1); }} />)}
      </div>
      <Card title={`Inventory${crit ? ` · ${crit}` : ""}`} right={<div className="flex flex-wrap gap-2 items-center">
        <input aria-label="Search assets" className="input w-64" placeholder="IP, hostname, MAC, user, owner" value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} />
        {me.role === "admin" && <button className="btn btn-primary" onClick={() => setEdit({ ip: "", criticality: "critical", tags: [], owner: "", notes: "", hostname: "" })}>+ Add asset</button>}
        <button className="btn" disabled={page <= 1} onClick={() => setPage(page - 1)}>‹</button><span className="text-muted text-sm">{page}/{pages}</span><button className="btn" disabled={page >= pages} onClick={() => setPage(page + 1)}>›</button>
      </div>}>
        <Loading q={r} />
        {r.data && !r.data.items.length && <Empty text={dq || crit ? "No assets match." : "No assets learned yet. They appear after traffic from internal hosts is ingested."} />}
        {!!r.data?.items.length && <TableWrap><table className="tbl"><thead><tr><th>IP</th><th>Hostname</th><th>Criticality</th><th>MAC</th><th>OS</th><th>Last user</th><th>Owner</th><th>Tags</th><th>Source</th><th>Last seen</th></tr></thead>
          <tbody>{r.data.items.map((a: any) => <tr key={a.ip} {...(me.role === "admin" ? rowProps(() => setEdit(a)) : {})}>
            <td><IpLink ip={a.ip} /></td><td className="min-w-[9rem]"><Trunc text={a.hostname} max="max-w-[14rem]" /></td>
            <td className="nowrap"><span className={`pill ${CRIT_CLS[a.criticality]}`}>{a.criticality}</span></td>
            <td className="font-mono text-xs nowrap">{a.mac || "—"}</td><td className="text-xs nowrap">{a.os || "—"}</td><td className="text-xs">{a.last_user || "—"}</td>
            <td className="text-xs">{a.owner || "—"}</td><td className="text-xs">{(a.tags || []).join(", ") || "—"}</td><td className="text-xs">{a.source}</td><td><Time v={a.last_seen} /></td>
          </tr>)}</tbody></table></TableWrap>}
      </Card>
      {edit && <EditAsset a={edit} onClose={() => setEdit(null)} />}
    </div>
  );
}

function EditAsset({ a, onClose }: { a: any; onClose: () => void }) {
  const qc = useQueryClient();
  const [f, setF] = useState({ ip: a.ip, hostname: a.hostname || "", criticality: a.criticality || "normal", tags: (a.tags || []).join(", "), owner: a.owner || "", notes: a.notes || "" });
  const m = useMutation({
    mutationFn: () => api(`/assets/${encodeURIComponent(f.ip.trim())}`, { method: "PUT", body: { hostname: f.hostname, criticality: f.criticality, owner: f.owner, notes: f.notes,
      tags: f.tags.split(",").map((t: string) => t.trim()).filter(Boolean) } }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["assets"] }); onClose(); },
  });
  return (
    <Modal title={a.ip ? `Asset ${a.ip}` : "Add asset"} onClose={onClose}>
      <div className="grid gap-2 sm:grid-cols-2">
        <div><label className="label">IP address</label><input className="input w-full font-mono" disabled={!!a.ip} value={f.ip} onChange={(e) => setF({ ...f, ip: e.target.value })} /></div>
        <div><label className="label">Criticality</label><select className="input w-full" value={f.criticality} onChange={(e) => setF({ ...f, criticality: e.target.value })}>{["low", "normal", "high", "critical"].map((k) => <option key={k}>{k}</option>)}</select></div>
        <div><label className="label">Hostname</label><input className="input w-full" value={f.hostname} onChange={(e) => setF({ ...f, hostname: e.target.value })} /></div>
        <div><label className="label">Owner / team</label><input className="input w-full" value={f.owner} onChange={(e) => setF({ ...f, owner: e.target.value })} /></div>
        <div className="sm:col-span-2"><label className="label">Tags (comma-separated)</label><input className="input w-full" value={f.tags} onChange={(e) => setF({ ...f, tags: e.target.value })} placeholder="pci, database, finance" /></div>
        <div className="sm:col-span-2"><label className="label">Notes</label><textarea className="input w-full h-20" value={f.notes} onChange={(e) => setF({ ...f, notes: e.target.value })} /></div>
      </div>
      {a.users?.length > 0 && <p className="text-xs text-muted mt-2">Users seen: {a.users.join(", ")} · first seen <Time v={a.first_seen} /></p>}
      {m.error && <div role="alert" className="text-sm text-red-400 mt-2">{(m.error as Error).message}</div>}
      <button className="btn btn-primary mt-3" disabled={!f.ip.trim()} onClick={() => m.mutate()}>Save</button>
    </Modal>
  );
}
