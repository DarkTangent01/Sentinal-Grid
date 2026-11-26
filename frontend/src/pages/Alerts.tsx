import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useMe } from "../lib/context";
import { fmtNum, fmtTime } from "../lib/format";
import { Card, Drawer, Empty, IpLink, Loading, Sev, TableWrap, Tabs, Time, Trunc, rowProps, useExplore } from "../components/ui";
import { ActionForm } from "./Soc";
import { Mitre } from "../components/Mitre";
import { useNavigate } from "react-router-dom";

const STATUS_COLORS: Record<string, string> = { new: "text-red-300", investigating: "text-amber-300", resolved: "text-emerald-300", suppressed: "bg-slate-700 text-slate-300" };

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
  const product = sp.get("product") || undefined;  // /alerts?product=grid|nms from the product sidebars
  const rulePrefix = sp.get("rule_prefix") || undefined;  // /alerts?rule_prefix=wireless_ from module pages
  const q = useQuery({ queryKey: ["alerts", status, rule, product, rulePrefix], queryFn: () => api<any>("/alerts", { params: { status: statuses, size: 200, rule_key: rule, product, rule_prefix: rulePrefix } }), refetchInterval: 30_000 });
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
              <td className="nowrap"><Sev s={a.severity} /></td><td className="min-w-[12rem]">{a.name}{a.incident_id && <span className="pill text-sky-300 ml-1">incident #{a.incident_id}</span>}</td>
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
        <Brief id={a.id} srcIp={a.src_ip} incidentId={a.incident_id} />
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs [&>*]:min-w-0 [&>*]:break-words">
          <div>Source: <IpLink ip={a.src_ip} /></div><div>Destination: <IpLink ip={a.dst_ip} /></div>
          <div>First seen: {fmtTime(a.first_seen)}</div><div>Last seen: {fmtTime(a.last_seen)}</div>
          <div>Peak events in a detection window: {fmtNum(a.event_count)}</div><div>Sites: {(a.sites || []).join(", ") || "—"}</div>
          <div>Firewall IDs: {(a.firewall_ids || []).join(", ")}</div><div>Group key: <span className="font-mono">{a.group_key}</span></div>
        </div>
        <button className="btn btn-primary" onClick={() => explore({ ...f, range: undefined, start: f.start, end: new Date().toISOString() })}>View related events →</button>
        {a.evidence && Object.keys(a.evidence).length > 0 && <pre className="text-xs bg-panel2 p-2 rounded overflow-auto">{JSON.stringify(a.evidence, null, 2)}</pre>}
        <label className="block min-w-0"><span className="label">Notes</span><textarea className="input w-full h-24" value={notes} onChange={(e) => setNotes(e.target.value)} /></label>
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

/** Investigation brief (stored records only, every activity statement cites an event id) and, when an administrator
 *  enabled AI data sharing, a narrative written from that same brief. */
function Brief({ id, srcIp, incidentId }: { id: number; srcIp?: string; incidentId?: number }) {
  const q = useQuery({ queryKey: ["alert-brief", id], queryFn: () => api<any>(`/alerts/${id}/brief`) });
  const ai = useMutation({ mutationFn: () => api<any>(`/ai/alerts/${id}/explain`, { method: "POST" }) });
  const [act, setAct] = useState(false);
  const b = q.data;
  return <Card title="Investigation brief">
    <Loading q={q} />
    {b && <div className="space-y-2 text-sm">
      <p><b>What happened.</b> {b.what_happened.summary} <span className="text-2xs text-muted">[{b.what_happened.cite}]</span></p>
      <p><b>Why it was detected.</b> {b.why_detected.description || b.why_detected.rule}{b.why_detected.confidence ? ` Rule confidence: ${b.why_detected.confidence}.` : ""}</p>
      {b.assets.length > 0 && <p><b>Assets.</b> {b.assets.map((x: any) => `${x.ip} (${x.role}${x.known ? `, ${x.hostname || "no hostname"}, criticality ${x.criticality}${x.owner ? `, owner ${x.owner}` : ""}` : ", not in the inventory"})`).join("; ")}</p>}
      {b.users.length > 0 && <p><b>Users.</b> {b.users.join(", ")}</p>}
      <p><b>Potential impact.</b> {b.impact.statement}{b.impact.severity_raised_by_asset ? " Severity was raised because a critical asset is involved." : ""}</p>
      {b.attack.techniques.length > 0 && <p><b>ATT&CK.</b> {b.attack.tactic_name}: {b.attack.techniques.map((t: any) => <a key={t.id} className="link mr-2" href={t.url} target="_blank" rel="noreferrer noopener">{t.id} {t.name}</a>)}</p>}
      {b.entity_risk && <p><b>Entity risk.</b> {b.entity_risk.score} ({b.entity_risk.level}){b.entity_risk.top_factors.length ? `: ${b.entity_risk.top_factors.join(", ")}` : ""}</p>}
      {b.why_detected.known_false_positives.length > 0 && <p><b>Known false positives.</b> {b.why_detected.known_false_positives.join("; ")}</p>}
      <div><b>Evidence.</b> {b.evidence.events.length ? <TableWrap><table className="tbl mt-1"><thead><tr><th>Time</th><th>Event</th><th>Detail</th></tr></thead>
        <tbody>{b.evidence.events.map((e: any) => <tr key={e.event_id}><td><Time v={e.event_time} /></td><td className="font-mono text-2xs">{e.event_id}</td>
          <td className="cell-wrap text-xs">{[e.action, e.src_ip && `${e.src_ip} → ${e.dst_ip || "?"}${e.dst_port ? `:${e.dst_port}` : ""}`, e.user, e.threat, e.msg].filter(Boolean).join(" · ")}</td></tr>)}</tbody></table></TableWrap>
        : <span className="text-muted">{b.evidence.note}</span>}</div>
      {b.related_alerts.length > 0 && <p><b>Related alerts (24 h).</b> {b.related_alerts.map((r: any) => `${r.name} (${r.severity})`).join("; ")}</p>}
      <div><b>Next steps.</b><ol className="list-decimal ml-5">{b.next_steps.map((s: string) => <li key={s}>{s}</li>)}</ol></div>
      <div className="flex flex-wrap gap-2 pt-1">
        <button type="button" className="btn" disabled={ai.isPending} onClick={() => ai.mutate()}>{ai.isPending ? "Asking the AI assistant…" : "Explain with AI"}</button>
        {srcIp && <button type="button" className="btn" onClick={() => setAct(true)}>Request response…</button>}
      </div>
      {ai.error && <div role="alert" className="text-xs text-red-400">{String((ai.error as Error).message)}</div>}
      {ai.data && <div className="card p-3 bg-panel2"><div className="text-2xs text-muted mb-1">AI narrative ({ai.data.model}) from this brief only; check the cited events before acting.</div>
        <div className="whitespace-pre-wrap text-sm">{ai.data.explanation}</div></div>}
    </div>}
    {act && <ActionForm firewalls={[]} init={{ kind: "enrich_ip", target: srcIp, alert_id: id, incident_id: incidentId }} onClose={() => setAct(false)} />}
  </Card>;
}
