import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useMe } from "../lib/context";
import { fmtNum, fmtTime } from "../lib/format";
import { Card, Drawer, Empty, IpLink, Loading, Sev, Tabs, Time, Trunc, rowProps, useExplore } from "../components/ui";
import { Mitre } from "./Incidents";
import { useNavigate } from "react-router-dom";

const STATUS_COLORS: Record<string, string> = { new: "bg-red-600/30 text-red-200", investigating: "bg-amber-600/30 text-amber-200", resolved: "bg-emerald-700/30 text-emerald-200", suppressed: "bg-slate-700 text-slate-300" };

export function Alerts() {
  const [status, setStatus] = useState("open");
  const [sel, setSel] = useState<any>(null);
  const [sp, setSp] = useSearchParams();
  const linkId = sp.get("id");
  useEffect(() => {  // deep link from investigations: /alerts?id=123
    if (linkId) api<any>(`/alerts/${linkId}`).then(setSel).catch(() => setSel(null));
  }, [linkId]);
  const close = () => { setSel(null); if (linkId) { sp.delete("id"); setSp(sp, { replace: true }); } };
  const rule = sp.get("rule") || undefined;  // /alerts?rule=<key> from Detections
  const statuses = status === "open" ? ["new", "investigating"] : status === "all" ? [] : [status];
  const q = useQuery({ queryKey: ["alerts", status, rule], queryFn: () => api<any>("/alerts", { params: { status: statuses, size: 200, rule_key: rule } }), refetchInterval: 30_000 });
  const c = q.data?.status_counts || {};
  return (
    <div className="space-y-3">
      {rule && <div className="text-sm">Showing alerts from rule <code className="font-mono">{rule}</code>{" "}
        <button className="link" onClick={() => { sp.delete("rule"); setSp(sp, { replace: true }); }}>Clear filter ✕</button></div>}
      <Tabs value={status} onChange={setStatus} tabs={[
        { key: "open", label: `Open (${(c.new || 0) + (c.investigating || 0)})` }, { key: "new", label: `New (${c.new || 0})` },
        { key: "investigating", label: `Investigating (${c.investigating || 0})` }, { key: "resolved", label: `Resolved (${c.resolved || 0})` },
        { key: "suppressed", label: `Suppressed (${c.suppressed || 0})` }, { key: "all", label: "All" }]} />
      <p className="text-xs text-muted">Detections are indicators requiring investigation, not definitive proof of malicious activity. Thresholds are configurable in Settings → Detection rules.</p>
      <Card>
        <Loading q={q} />
        {q.data && !q.data.items.length && <Empty text="No alerts." />}
        {!!q.data?.items.length && <div className="tbl-wrap"><table className="tbl">
          <thead><tr><th>Severity</th><th>Detection</th><th>ATT&CK</th><th>Status</th><th>Source</th><th>Sites</th><th>First seen</th><th>Last seen</th><th className="num">Events</th><th>Why it triggered</th></tr></thead>
          <tbody>{q.data.items.map((a: any) => (
            <tr key={a.id} {...rowProps(() => setSel(a))} aria-label={`Open alert ${a.name}`}>
              <td className="nowrap"><Sev s={a.severity} /></td><td className="min-w-[12rem]">{a.name}{a.incident_id && <span className="pill bg-sky-500/15 text-sky-300 ml-1">incident #{a.incident_id}</span>}</td>
              <td className="min-w-[9rem]"><Mitre m={a.mitre} /></td>
              <td className="nowrap"><span className={`pill ${STATUS_COLORS[a.status]}`}>{a.status}</span></td>
              <td><IpLink ip={a.src_ip} /></td><td className="text-xs min-w-[7rem]">{(a.sites || []).join(", ") || "—"}</td>
              <td className="text-xs"><Time v={a.first_seen} /></td><td className="text-xs"><Time v={a.last_seen} /></td>
              <td className="num">{fmtNum(a.event_count)}</td><td className="text-xs text-muted"><Trunc text={a.explanation} max="max-w-[28rem]" /></td>
            </tr>))}</tbody></table></div>}
      </Card>
      {sel && <AlertDrawer key={sel.id} alert={sel} onClose={close} />}
    </div>
  );
}

function AlertDrawer({ alert, onClose }: { alert: any; onClose: () => void }) {
  const me = useMe();
  const nav = useNavigate();
  const qc = useQueryClient();
  const explore = useExplore();
  const [notes, setNotes] = useState(alert.notes || "");
  const [a, setA] = useState(alert);
  const upd = useMutation({
    mutationFn: (body: any) => api(`/alerts/${a.id}`, { method: "PATCH", body }),
    onSuccess: (r) => { setA(r); qc.invalidateQueries({ queryKey: ["alerts"] }); },
  });
  const sup = useMutation({
    mutationFn: (hours: number) => api(`/alerts/${a.id}/suppress`, { method: "POST", body: { hours, reason: notes } }),
    onSuccess: (r) => { setA(r); qc.invalidateQueries({ queryKey: ["alerts"] }); },
  });
  const f = a.event_filter || {};
  return (
    <Drawer title={`Alert #${a.id}: ${a.name}`} onClose={onClose}>
      <div className="space-y-3 text-sm">
        <div className="flex flex-wrap gap-2 items-center"><Sev s={a.severity} /><span className={`pill ${STATUS_COLORS[a.status]}`}>{a.status}</span><Mitre m={a.mitre} /><span className="text-muted text-xs">rule: {a.rule_key}</span>
          {a.base_severity && a.base_severity !== a.severity && <span className="text-xs text-amber-300">raised from {a.base_severity} (critical asset)</span>}</div>
        {a.incident_id && <button className="btn" onClick={() => nav(`/incidents/${a.incident_id}`)}>Part of incident #{a.incident_id} →</button>}
        <div className="card p-3 bg-panel2"><div className="text-xs text-muted mb-1">Why it triggered</div>{a.explanation}</div>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs [&>*]:min-w-0 [&>*]:break-words">
          <div>Source: <IpLink ip={a.src_ip} /></div><div>Destination: <IpLink ip={a.dst_ip} /></div>
          <div>First seen: {fmtTime(a.first_seen)}</div><div>Last seen: {fmtTime(a.last_seen)}</div>
          <div>Peak events in a detection window: {fmtNum(a.event_count)}</div><div>Sites: {(a.sites || []).join(", ") || "—"}</div>
          <div>Firewall IDs: {(a.firewall_ids || []).join(", ")}</div><div>Group key: <span className="font-mono">{a.group_key}</span></div>
        </div>
        <button className="btn btn-primary" onClick={() => explore({ ...f, range: undefined, start: f.start, end: new Date().toISOString() })}>View related events →</button>
        {a.evidence && Object.keys(a.evidence).length > 0 && <pre className="text-xs bg-panel2 p-2 rounded overflow-auto">{JSON.stringify(a.evidence, null, 2)}</pre>}
        <div><label className="label">Notes</label><textarea className="input w-full h-24" value={notes} onChange={(e) => setNotes(e.target.value)} /></div>
        <div className="flex flex-wrap gap-2">
          <button className="btn" onClick={() => upd.mutate({ notes })}>Save notes</button>
          {["new", "investigating", "resolved"].map((s) => <button key={s} className="btn" disabled={a.status === s} onClick={() => upd.mutate({ status: s, notes, assignee: s === "investigating" ? me.username : a.assignee })}>Mark {s}</button>)}
          {me.role === "admin" && <><button className="btn btn-danger" onClick={() => sup.mutate(24)}>Suppress 24h</button><button className="btn btn-danger" onClick={() => sup.mutate(24 * 30)}>Suppress 30d</button></>}
        </div>
        {(upd.error || sup.error) && <div className="text-red-400 text-xs">{String(((upd.error || sup.error) as Error).message)}</div>}
      </div>
    </Drawer>
  );
}
