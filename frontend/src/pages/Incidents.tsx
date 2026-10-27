import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useMe } from "../lib/context";
import { fmtNum } from "../lib/format";
import { Card, Empty, IpLink, Kpi, Loading, Sev, TableWrap, Tabs, Time, Trunc, rowProps, useExplore } from "../components/ui";

export const TACTIC_NAMES: Record<string, string> = {
  TA0043: "Reconnaissance", TA0001: "Initial Access", TA0006: "Credential Access", TA0007: "Discovery",
  TA0005: "Defense Evasion", TA0011: "Command and Control", TA0010: "Exfiltration", TA0008: "Lateral Movement",
};
const STATUS_CLS: Record<string, string> = {
  open: "bg-red-500/15 text-red-300", in_progress: "bg-amber-500/15 text-amber-300", resolved: "bg-emerald-500/15 text-emerald-300", closed: "bg-slate-700/60 text-slate-300",
};
const REASONS: [string, string][] = [["true_positive", "True positive"], ["false_positive", "False positive"], ["benign", "Benign / expected"], ["duplicate", "Duplicate"]];

export function Mitre({ m }: { m?: any }) {
  if (!m?.tactic) return null;
  return (
    <span className="inline-flex flex-wrap gap-1 items-center">
      <span className="pill bg-indigo-500/15 text-sky-200 ring-1 ring-sky-500/20" title={m.tactic}>{m.tactic_name || TACTIC_NAMES[m.tactic] || m.tactic}</span>
      {(m.techniques || []).map((t: string) => (
        <a key={t} className="pill bg-slate-800 text-slate-300 hover:text-brand-400" href={`https://attack.mitre.org/techniques/${t.replace(".", "/")}/`}
          target="_blank" rel="noopener noreferrer" onClick={(e) => e.stopPropagation()}>{t}</a>))}
    </span>
  );
}

function SlaBadge({ sla, status }: { sla: any; status: string }) {
  if (!sla?.resolve_due) return null;
  if (status === "resolved" || status === "closed") return sla.resolve_breached ? <span className="pill bg-red-500/15 text-red-300">SLA missed</span> : <span className="pill bg-emerald-500/15 text-emerald-300">within SLA</span>;
  if (sla.ack_breached && status === "open") return <span className="pill bg-red-500/20 text-red-300" title={`Acknowledge by ${sla.ack_due}`}>ack overdue</span>;
  if (sla.resolve_breached) return <span className="pill bg-red-500/20 text-red-300">resolve overdue</span>;
  return <span className="pill bg-slate-800 text-slate-300" title="Resolve-by">due <Time v={sla.resolve_due} /></span>;
}

export function Incidents() {
  const nav = useNavigate();
  const [status, setStatus] = useState("open");
  const statuses = status === "open" ? ["open", "in_progress"] : status === "all" ? [] : [status];
  const q = useQuery({ queryKey: ["incidents", status], queryFn: () => api<any>("/incidents", { params: { status: statuses, size: 200 } }), refetchInterval: 30_000 });
  const stats = useQuery({ queryKey: ["incident-stats"], queryFn: () => api<any>("/incidents/stats", { params: { days: 30 } }), refetchInterval: 60_000 });
  const c = q.data?.status_counts || {};
  const st = stats.data || {};
  return (
    <div className="space-y-4 min-w-0">
      <div className="kpi-grid">
        <Kpi label="Open critical" value={fmtNum(st.open_by_severity?.critical)} tone={st.open_by_severity?.critical ? "bad" : undefined} />
        <Kpi label="Open high" value={fmtNum(st.open_by_severity?.high)} tone={st.open_by_severity?.high ? "warn" : undefined} />
        <Kpi label="MTTA (30 d)" value={st.mtta_hours != null ? `${st.mtta_hours} h` : "—"} sub="mean time to acknowledge" />
        <Kpi label="MTTR (30 d)" value={st.mttr_hours != null ? `${st.mttr_hours} h` : "—"} sub="mean time to resolve" />
        <Kpi label="SLA breaches (30 d)" value={fmtNum((st.sla_ack_breaches || 0) + (st.sla_resolve_breaches || 0))} tone={(st.sla_ack_breaches || st.sla_resolve_breaches) ? "bad" : undefined}
          sub={`${fmtNum(st.sla_ack_breaches)} ack · ${fmtNum(st.sla_resolve_breaches)} resolve`} />
        <Kpi label="False positives (30 d)" value={fmtNum(st.closure_reasons?.false_positive)} sub={`of ${fmtNum(Object.values(st.closure_reasons || {}).reduce((a: number, b: any) => a + Number(b), 0))} closed`} />
      </div>
      <Tabs value={status} onChange={setStatus} tabs={[
        { key: "open", label: `Open (${(c.open || 0) + (c.in_progress || 0)})` }, { key: "in_progress", label: `In progress (${c.in_progress || 0})` },
        { key: "resolved", label: `Resolved (${c.resolved || 0})` }, { key: "closed", label: `Closed (${c.closed || 0})` }, { key: "all", label: "All" }]} />
      <p className="text-xs text-muted">Incidents group related alerts about one entity (IP, VPN user or firewall) within 24 h. Severity rises when alerts span several MITRE ATT&CK tactics or a critical asset is involved.</p>
      <Card>
        <Loading q={q} />
        {q.data && !q.data.items.length && <Empty text="No incidents in this view." />}
        {!!q.data?.items.length && <TableWrap><table className="tbl">
          <thead><tr><th>#</th><th>Severity</th><th className="w-full">Incident</th><th>Status</th><th>Tactics</th><th className="num">Alerts</th><th>Assignee</th><th>Last activity</th><th>SLA</th></tr></thead>
          <tbody>{q.data.items.map((i: any) => (
            <tr key={i.id} {...rowProps(() => nav(`/incidents/${i.id}`))} aria-label={`Open incident ${i.id}`}>
              <td className="num font-mono">{i.id}</td><td className="nowrap"><Sev s={i.severity} /></td>
              <td className="min-w-[16rem]"><Trunc text={i.title} max="max-w-[34rem]" />{i.asset_criticality === "critical" && <span className="pill bg-red-500/15 text-red-300 ml-1">critical asset</span>}</td>
              <td className="nowrap"><span className={`pill ${STATUS_CLS[i.status]}`}>{i.status.replace("_", " ")}</span></td>
              <td className="text-xs min-w-[10rem]">{i.tactics.map((t: string) => TACTIC_NAMES[t] || t).join(" → ") || "—"}</td>
              <td className="num">{i.alert_count}</td><td className="text-xs nowrap">{i.assignee || <span className="text-slate-400">unassigned</span>}</td>
              <td><Time v={i.last_seen} /></td><td className="nowrap"><SlaBadge sla={i.sla} status={i.status} /></td>
            </tr>))}</tbody></table></TableWrap>}
      </Card>
      <AnalystWorkload />
    </div>
  );
}

function AnalystWorkload() {
  const q = useQuery({ queryKey: ["incident-analysts"], queryFn: () => api<any[]>("/incident-analysts", { params: { days: 30 } }), refetchInterval: 60_000 });
  if (!q.data?.length) return null;
  return (
    <Card title="Analyst workload (open now + last 30 days)">
      <TableWrap><table className="tbl"><thead><tr><th>Analyst</th><th className="num">Open</th><th className="num">In progress</th><th className="num">Critical open</th>
        <th className="num">Open tasks</th><th className="num">Closed</th><th className="num">MTTA</th><th className="num">MTTR</th><th className="num">Ack SLA missed</th><th className="num">Resolve SLA missed</th></tr></thead>
        <tbody>{q.data.map((r) => <tr key={r.analyst}><td>{r.analyst}</td><td className="num">{r.open}</td><td className="num">{r.in_progress}</td>
          <td className={`num ${r.critical_open ? "text-red-300 font-semibold" : ""}`}>{r.critical_open}</td><td className="num">{r.tasks_open}</td><td className="num">{r.closed}</td>
          <td className="num">{r.mtta_minutes == null ? "—" : `${r.mtta_minutes} min`}</td><td className="num">{r.mttr_hours == null ? "—" : `${r.mttr_hours} h`}</td>
          <td className={`num ${r.ack_breached ? "text-amber-300" : ""}`}>{r.ack_breached}</td><td className={`num ${r.resolve_breached ? "text-red-300" : ""}`}>{r.resolve_breached}</td></tr>)}</tbody></table></TableWrap>
    </Card>
  );
}

function TaskList({ i, onChange }: { i: any; onChange: () => void }) {
  const [text, setText] = useState("");
  const add = useMutation({ mutationFn: () => api(`/incidents/${i.id}/tasks`, { method: "POST", body: { text } }), onSuccess: () => { setText(""); onChange(); } });
  const toggle = useMutation({ mutationFn: (t: any) => api(`/incidents/${i.id}/tasks/${t.id}`, { method: "PATCH", body: { done: !t.done } }), onSuccess: onChange });
  const del = useMutation({ mutationFn: (t: any) => api(`/incidents/${i.id}/tasks/${t.id}`, { method: "DELETE" }), onSuccess: onChange });
  const done = i.tasks.filter((t: any) => t.done).length;
  return (
    <Card title={`Tasks (${done}/${i.tasks.length})`}>
      {i.tasks.length > 0 && <div className="h-1.5 bg-slate-800 rounded mb-3" aria-hidden><div className="h-1.5 bg-emerald-500 rounded" style={{ width: `${(100 * done) / i.tasks.length}%` }} /></div>}
      <ul className="space-y-1.5 mb-3">{i.tasks.map((t: any) => (
        <li key={t.id} className="flex items-start gap-2 text-sm group">
          <input type="checkbox" className="mt-1" checked={t.done} aria-label={t.text} onChange={() => toggle.mutate(t)} />
          <span className={`flex-1 ${t.done ? "line-through text-muted" : ""}`}>{t.text}{t.done && t.done_by && <span className="text-2xs text-muted no-underline"> · {t.done_by}</span>}</span>
          <button className="text-muted hover:text-red-300 opacity-0 group-hover:opacity-100 focus:opacity-100" aria-label={`Remove task ${t.text}`} onClick={() => del.mutate(t)}>✕</button>
        </li>))}</ul>
      <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); if (text.trim()) add.mutate(); }}>
        <input aria-label="New task" className="input flex-1" placeholder="Add a task…" value={text} onChange={(e) => setText(e.target.value)} />
        <button className="btn" disabled={!text.trim()}>Add</button>
      </form>
    </Card>
  );
}

function LinkedIncidents({ i, onChange }: { i: any; onChange: () => void }) {
  const nav = useNavigate();
  const [other, setOther] = useState("");
  const [err, setErr] = useState("");
  const link = useMutation({ mutationFn: () => api(`/incidents/${i.id}/links`, { method: "POST", body: { incident_id: Number(other) } }),
    onSuccess: () => { setOther(""); setErr(""); onChange(); }, onError: (e) => setErr((e as Error).message) });
  const unlink = useMutation({ mutationFn: (o: number) => api(`/incidents/${i.id}/links/${o}`, { method: "DELETE" }), onSuccess: onChange });
  return (
    <Card title={`Linked incidents (${i.linked.length})`}>
      {i.linked.length > 0 && <ul className="text-sm space-y-1 mb-3">{i.linked.map((o: number) => <li key={o} className="flex gap-2">
        <button className="link" onClick={() => nav(`/incidents/${o}`)}>Incident #{o}</button><span className="flex-1" />
        <button className="text-xs text-muted hover:text-red-300" onClick={() => unlink.mutate(o)}>unlink</button></li>)}</ul>}
      <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); if (other) link.mutate(); }}>
        <input aria-label="Incident number to link" className="input w-32" inputMode="numeric" placeholder="#" value={other} onChange={(e) => setOther(e.target.value.replace(/\D/g, ""))} />
        <button className="btn" disabled={!other}>Link</button>
      </form>
      {err && <div role="alert" className="text-xs text-red-400 mt-1">{err}</div>}
    </Card>
  );
}

export function IncidentDetail() {
  const { id = "" } = useParams();
  const me = useMe();
  const nav = useNavigate();
  const explore = useExplore();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["incident", id], queryFn: () => api<any>(`/incidents/${id}`), refetchInterval: 30_000 });
  const [comment, setComment] = useState("");
  const [reason, setReason] = useState("true_positive");
  const [ev, setEv] = useState({ type: "note", ref: "", label: "" });
  const [err, setErr] = useState("");
  const refresh = () => { qc.invalidateQueries({ queryKey: ["incident", id] }); qc.invalidateQueries({ queryKey: ["incidents"] }); };
  const patch = useMutation({ mutationFn: (body: any) => api(`/incidents/${id}`, { method: "PATCH", body }), onSuccess: () => { setErr(""); refresh(); }, onError: (e) => setErr((e as Error).message) });
  const addComment = useMutation({ mutationFn: () => api(`/incidents/${id}/comments`, { method: "POST", body: { body: comment } }), onSuccess: () => { setComment(""); refresh(); } });
  const addEv = useMutation({ mutationFn: () => api(`/incidents/${id}/evidence`, { method: "POST", body: ev }), onSuccess: () => { setEv({ type: "note", ref: "", label: "" }); refresh(); }, onError: (e) => setErr((e as Error).message) });
  const i = q.data;
  return (
    <div className="space-y-4 min-w-0">
      <button className="link text-xs" onClick={() => nav("/incidents")}>← Incidents</button>
      <Loading q={q} />
      {i && <>
        <div className="flex flex-wrap items-start gap-3">
          <div className="min-w-0 flex-1">
            <h1 className="text-lg font-semibold break-words">#{i.id} {i.title}</h1>
            <div className="flex flex-wrap items-center gap-2 mt-1 text-xs">
              <Sev s={i.severity} /><span className={`pill ${STATUS_CLS[i.status]}`}>{i.status.replace("_", " ")}</span><SlaBadge sla={i.sla} status={i.status} />
              <span className="text-muted">{i.entity_type}: {i.entity_type === "ip" ? <IpLink ip={i.entity} /> : <b>{i.entity}</b>}</span>
              <span className="text-muted">score {i.score} · {i.alert_count} alerts · first <Time v={i.first_seen} /> · last <Time v={i.last_seen} /></span>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            {i.status === "open" && <button className="btn" onClick={() => patch.mutate({ status: "in_progress", assignee: i.assignee || me.username })}>Acknowledge</button>}
            {!i.assignee && <button className="btn" onClick={() => patch.mutate({ assignee: me.username })}>Assign to me</button>}
            {["open", "in_progress"].includes(i.status) ? <>
              <select aria-label="Closure reason" className="input" value={reason} onChange={(e) => setReason(e.target.value)}>{REASONS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
              <button className="btn btn-primary" onClick={() => patch.mutate({ status: "resolved", closure_reason: reason })}>Resolve</button>
            </> : <button className="btn" onClick={() => patch.mutate({ status: "open" })}>Reopen</button>}
            {i.status === "resolved" && <button className="btn" onClick={() => patch.mutate({ status: "closed" })}>Close</button>}
          </div>
        </div>
        {err && <div role="alert" className="text-sm text-red-400">{err}</div>}
        <div className="grid-cards xl:grid-cols-3">
          <Card title="ATT&CK tactics and techniques" className="xl:col-span-2">
            <div className="flex flex-wrap items-center gap-2 text-sm">
              {i.tactics.length ? i.tactics.map((t: string, n: number) => <span key={t} className="flex items-center gap-2">{n > 0 && <span className="text-slate-400" aria-hidden>→</span>}<span className="pill bg-indigo-500/15 text-sky-200">{TACTIC_NAMES[t] || t}</span></span>) : <span className="text-muted">—</span>}
            </div>
            <div className="mt-2 flex flex-wrap gap-1">{i.techniques.map((t: string) => <a key={t} className="pill bg-slate-800 text-slate-300 hover:text-brand-400" href={`https://attack.mitre.org/techniques/${t.replace(".", "/")}/`} target="_blank" rel="noopener noreferrer">{t}</a>)}</div>
          </Card>
          <Card title="Case">
            <div className="space-y-2 text-sm">
              <div className="flex justify-between gap-2"><span className="text-muted">Assignee</span><span>{i.assignee || "unassigned"}</span></div>
              <div className="flex justify-between gap-2"><span className="text-muted">Acknowledge by</span><span><Time v={i.sla.ack_due} /></span></div>
              <div className="flex justify-between gap-2"><span className="text-muted">Resolve by</span><span><Time v={i.sla.resolve_due} /></span></div>
              {i.closure_reason && <div className="flex justify-between gap-2"><span className="text-muted">Closure</span><span>{REASONS.find(([k]) => k === i.closure_reason)?.[1]}</span></div>}
              {i.asset_criticality && <div className="flex justify-between gap-2"><span className="text-muted">Asset criticality</span><span>{i.asset_criticality}</span></div>}
            </div>
          </Card>
        </div>
        <Card title={`Alerts (${i.alerts.length})`}>
          <TableWrap><table className="tbl"><thead><tr><th>Severity</th><th>Detection</th><th>ATT&CK</th><th>Source</th><th>First seen</th><th className="num">Events</th><th className="w-full">Why</th></tr></thead>
            <tbody>{i.alerts.map((a: any) => <tr key={a.id} {...rowProps(() => nav(`/alerts?id=${a.id}`))}>
              <td className="nowrap"><Sev s={a.severity} /></td><td className="min-w-[12rem]">{a.name}</td><td className="min-w-[10rem]"><Mitre m={a.mitre} /></td>
              <td><IpLink ip={a.src_ip} /></td><td><Time v={a.first_seen} /></td><td className="num">{fmtNum(a.event_count)}</td>
              <td className="text-xs text-muted"><Trunc text={a.explanation} max="max-w-[30rem]" /></td></tr>)}</tbody></table></TableWrap>
          {i.entity_type === "ip" && <button className="btn mt-2" onClick={() => explore({ ip: i.entity, start: i.first_seen, end: i.last_seen })}>All events for {i.entity} in this period →</button>}
          {(i.entity_type === "ip" || i.entity_type === "user") && <button className="btn mt-2 ml-2" onClick={() => nav(`/graph?kind=${i.entity_type}&value=${encodeURIComponent(i.entity)}&range=7d`)}>Entity graph →</button>}
        </Card>
        <div className="grid-cards xl:grid-cols-2">
          <Card title="Timeline">
            <ol className="relative border-l border-line ml-2 space-y-3">
              {i.timeline.map((t: any, n: number) => (
                <li key={n} className="ml-4">
                  <span className={`absolute -left-1.5 mt-1.5 h-3 w-3 rounded-full ${t.kind === "alert" ? "bg-red-400" : t.kind === "status" ? "bg-amber-400" : t.kind === "evidence" ? "bg-emerald-400" : "bg-sky-400"}`} aria-hidden />
                  <div className="text-2xs text-muted"><Time v={t.ts} /> · {t.kind}{t.author ? ` · ${t.author}` : ""}{t.tactic ? ` · ${t.tactic}` : ""}</div>
                  <div className="text-sm cell-wrap">{t.kind === "alert" && <Sev s={t.severity} />} {t.title}</div>
                </li>))}
            </ol>
          </Card>
          <div className="space-y-4 min-w-0">
            <Card title="Summary / handover notes">
              <SummaryEditor value={i.summary} onSave={(v) => patch.mutate({ summary: v })} />
            </Card>
            <AiSummary id={i.id} onSaved={refresh} />
            <TaskList i={i} onChange={refresh} />
            <Card title="Comment">
              <textarea aria-label="Comment" className="input w-full h-20" value={comment} onChange={(e) => setComment(e.target.value)} placeholder="Findings, actions taken, next steps…" />
              <button className="btn mt-2" disabled={!comment.trim()} onClick={() => addComment.mutate()}>Add comment</button>
            </Card>
            <Card title={`Evidence (${i.evidence.length})`}>
              {i.evidence.length > 0 && <ul className="text-sm space-y-1 mb-3">{i.evidence.map((e: any, n: number) => (
                <li key={n} className="cell-wrap"><span className="pill bg-slate-800 text-slate-300 mr-1">{e.type}</span>
                  {e.type === "link" ? <a className="link" href={e.ref} target="_blank" rel="noopener noreferrer">{e.label || e.ref}</a> : e.type === "ip" ? <IpLink ip={e.ref} />
                    : e.type === "bookmark" ? <button className="link" onClick={() => nav("/hunting?tab=bookmarks")}>{e.label} (bookmark #{e.ref})</button> : <span>{e.label ? `${e.label}: ` : ""}{e.ref}</span>}
                  <span className="text-2xs text-muted ml-1">{e.added_by}</span></li>))}</ul>}
              <div className="grid gap-2 sm:grid-cols-[8rem_1fr_1fr_auto]">
                <select aria-label="Evidence type" className="input" value={ev.type} onChange={(e) => setEv({ ...ev, type: e.target.value })}>{["note", "event", "alert", "ip", "link"].map((t) => <option key={t}>{t}</option>)}</select>
                <input aria-label="Evidence reference" className="input" placeholder={ev.type === "link" ? "https://ticket/123" : ev.type === "event" ? "event id" : "value"} value={ev.ref} onChange={(e) => setEv({ ...ev, ref: e.target.value })} />
                <input aria-label="Evidence label" className="input" placeholder="label (optional)" value={ev.label} onChange={(e) => setEv({ ...ev, label: e.target.value })} />
                <button className="btn" disabled={!ev.ref.trim()} onClick={() => addEv.mutate()}>Add</button>
              </div>
            </Card>
            <LinkedIncidents i={i} onChange={refresh} />
          </div>
        </div>
      </>}
    </div>
  );
}

function SummaryEditor({ value, onSave }: { value: string; onSave: (v: string) => void }) {
  const [v, setV] = useState(value || "");
  return (<>
    <textarea aria-label="Summary" className="input w-full h-24" value={v} onChange={(e) => setV(e.target.value)} placeholder="What happened, impact, containment, root cause…" />
    <button className="btn mt-2" disabled={v === (value || "")} onClick={() => onSave(v)}>Save summary</button>
  </>);
}

function AiSummary({ id, onSaved }: { id: number; onSaved: () => void }) {
  const st = useQuery({ queryKey: ["ai-status"], queryFn: () => api<any>("/ai/status"), staleTime: 300_000 });
  const m = useMutation({ mutationFn: () => api<any>(`/ai/incidents/${id}/summary`, { method: "POST" }) });
  const save = useMutation({ mutationFn: () => api(`/incidents/${id}/comments`, { method: "POST", body: { body: `AI summary (${m.data.model}):\n${m.data.summary}` } }), onSuccess: onSaved });
  if (!st.data?.enabled) return null;
  return (
    <Card title="AI summary" right={st.data.data_sharing && <button className="btn" disabled={m.isPending} onClick={() => m.mutate()}>{m.isPending ? "Summarising…" : m.data ? "Regenerate" : "Summarise"}</button>}>
      {!st.data.data_sharing && <p className="text-xs text-muted">Incident summaries send incident and alert details (IPs, users, hosts) to the AI service, so an administrator must enable
        AI_ALLOW_DATA_SHARING on the server first.</p>}
      {st.data.data_sharing && !m.data && !m.isPending && <p className="text-xs text-muted">Generates what happened, an assessment and next steps from this incident's alerts and notes. Incident data is sent to the AI service.</p>}
      {m.error && <div role="alert" className="text-sm text-red-400">{(m.error as Error).message}</div>}
      {m.data && <>
        <div className="text-sm whitespace-pre-wrap leading-relaxed">{m.data.summary}</div>
        <div className="flex items-center gap-2 mt-2"><span className="text-2xs text-muted">{m.data.model} · AI-generated, verify before acting</span>
          <button className="btn ml-auto" disabled={save.isPending || save.isSuccess} onClick={() => save.mutate()}>{save.isSuccess ? "Saved" : "Save as comment"}</button></div>
      </>}
    </Card>
  );
}
