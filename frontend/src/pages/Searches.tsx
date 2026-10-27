import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, qs } from "../lib/api";
import { useMe } from "../lib/context";
import { fmtNum } from "../lib/format";
import { Card, Empty, Loading, Modal, TableWrap, Time } from "../components/ui";

export const QL_HELP = "Fields: src_ip/dst_ip/ip (IP or CIDR), port, src_port, proto, action, category, severity, app, service, user, firewall, site, country, src_country, dst_country, asn, as_org, domain, url, qname, qtype, rcode, threat, ti, policy, bytes, os, mac, name, msg. Operators: AND, OR, NOT / -, parentheses, field:value, field!=value, field>=n, port:1-1024, wildcards app:*cloud*, field:* (present), \"quoted text\", bare words search the raw log.";

export function SaveSearch({ query, range, onClose }: { query: string; range: string; onClose: () => void }) {
  const me = useMe();
  const [f, setF] = useState({ name: "", query, range, shared: true, schedule: "none", threshold: 1, severity: "medium" });
  const m = useMutation({ mutationFn: () => api("/searches", { method: "POST", body: { ...f, threshold: Number(f.threshold) } }), onSuccess: onClose });
  return (
    <Modal title="Save search" onClose={onClose}>
      <div className="grid gap-2 sm:grid-cols-2">
        <div className="sm:col-span-2"><label className="label">Name</label><input className="input w-full" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></div>
        <div className="sm:col-span-2"><label className="label">Query</label><input className="input w-full font-mono" value={f.query} onChange={(e) => setF({ ...f, query: e.target.value })} /></div>
        <div><label className="label">Time range</label><select className="input w-full" value={f.range} onChange={(e) => setF({ ...f, range: e.target.value })}>{["5m", "15m", "1h", "24h", "7d", "30d"].map((r) => <option key={r}>{r}</option>)}</select></div>
        <label className="text-sm flex items-center gap-2 self-end"><input type="checkbox" checked={f.shared} onChange={(e) => setF({ ...f, shared: e.target.checked })} />Share with team</label>
        {me.role === "admin" && <>
          <div><label className="label">Schedule (alert when matches ≥ threshold)</label><select className="input w-full" value={f.schedule} onChange={(e) => setF({ ...f, schedule: e.target.value })}><option value="none">Not scheduled</option><option value="hourly">Hourly</option><option value="daily">Daily</option></select></div>
          <div><label className="label">Threshold</label><input type="number" min={1} className="input w-full" value={f.threshold} onChange={(e) => setF({ ...f, threshold: Number(e.target.value) })} /></div>
          <div><label className="label">Notification severity</label><select className="input w-full" value={f.severity} onChange={(e) => setF({ ...f, severity: e.target.value })}>{["low", "medium", "high", "critical"].map((x) => <option key={x}>{x}</option>)}</select></div>
        </>}
      </div>
      {m.error && <div role="alert" className="text-sm text-red-400 mt-2">{(m.error as Error).message}</div>}
      <button className="btn btn-primary mt-3" disabled={!f.name} onClick={() => m.mutate()}>Save</button>
    </Modal>
  );
}

export function Searches() {
  const me = useMe();
  const nav = useNavigate();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["searches"], queryFn: () => api<any[]>("/searches") });
  const [counts, setCounts] = useState<Record<number, number | string>>({});
  const [add, setAdd] = useState(false);
  const run = useMutation({ mutationFn: (id: number) => api<any>(`/searches/${id}/run`, { method: "POST" }), onSuccess: (r, id) => setCounts((c) => ({ ...c, [id]: r.count })),
    onError: (e, id) => setCounts((c) => ({ ...c, [id]: (e as Error).message })) });
  const del = useMutation({ mutationFn: (id: number) => api(`/searches/${id}`, { method: "DELETE" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["searches"] }) });
  return (
    <div className="space-y-4 min-w-0">
      <p className="text-xs text-muted">{QL_HELP}</p>
      <Card title="Saved searches" right={<button className="btn btn-primary" onClick={() => setAdd(true)}>+ New search</button>}>
        <Loading q={q} />
        {q.data && !q.data.length && <Empty text="No saved searches. Build a query in the Event Explorer and click Save." />}
        {!!q.data?.length && <TableWrap><table className="tbl"><thead><tr><th>Name</th><th className="w-full">Query</th><th>Range</th><th>Schedule</th><th>Owner</th><th>Last run</th><th className="num">Matches</th><th /></tr></thead>
          <tbody>{q.data.map((s) => <tr key={s.id}><td>{s.name}{!s.shared && <span className="pill bg-slate-800 text-slate-400 ml-1">private</span>}</td>
            <td className="font-mono text-xs cell-wrap">{s.query || "(all events)"}</td><td className="text-xs">{s.range}</td>
            <td className="text-xs">{s.schedule === "none" ? "—" : `${s.schedule}, ≥${fmtNum(s.threshold)} → ${s.severity}`}</td><td className="text-xs">{s.owner}</td>
            <td><Time v={s.last_run} /></td><td className="num">{counts[s.id] ?? (s.last_count != null ? fmtNum(s.last_count) : "—")}</td>
            <td className="nowrap"><button className="btn" onClick={() => nav(`/explorer${qs({ ql: s.query, range: s.range })}`)}>Open</button>
              <button className="btn ml-1" onClick={() => run.mutate(s.id)}>Count</button>
              {(s.owner === me.username || me.role === "admin") && <button className="btn btn-danger ml-1" onClick={() => confirm(`Delete ${s.name}?`) && del.mutate(s.id)}>Delete</button>}</td></tr>)}</tbody></table></TableWrap>}
      </Card>
      {add && <SaveSearch query="" range="24h" onClose={() => { setAdd(false); qc.invalidateQueries({ queryKey: ["searches"] }); }} />}
    </div>
  );
}
