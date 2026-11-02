import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { useMe } from "../../lib/context";
import { fmtNum, getTimezone } from "../../lib/format";
import { Card, Drawer, Empty, Loading, Sev, TableWrap, Time, useDebounced } from "../../components/ui";
import { Dur, Field, IncStatus, Pager, RangePicker, dur, rangeParams, useWanMeta } from "./common";

export function WanIncidents() {
  const [sp, setSp] = useSearchParams();
  const meta = useWanMeta();
  const initRange = sp.get("start") && sp.get("end") ? { range: "custom", start: sp.get("start")!.slice(0, 16), end: sp.get("end")!.slice(0, 16) } : { range: sp.get("range") || "30d" };
  const [r, setR] = useState<any>(initRange);
  const [status, setStatus] = useState(sp.get("status") || "");
  const [site, setSite] = useState(sp.get("site") || "");
  const [isp, setIsp] = useState(sp.get("isp") || "");
  const [missing, setMissing] = useState(sp.get("missing_root_cause") === "1");
  const [openOnly, setOpenOnly] = useState(sp.get("open_only") === "1");
  const [rc, setRc] = useState(sp.get("root_cause") || "");
  const [day, setDay] = useState(sp.get("day") || "");
  const [text, setText] = useState("");
  const [page, setPage] = useState(1);
  const sel = sp.get("id") ? Number(sp.get("id")) : null;
  const setSel = (id: number | null) => { const n = new URLSearchParams(sp); if (id) n.set("id", String(id)); else n.delete("id"); setSp(n); };
  const qd = useDebounced(text, 300);
  const params = { ...rangeParams(r), status: status ? [status] : undefined, site: site || undefined, isp: isp || undefined, missing_root_cause: missing || undefined,
    open_only: openOnly || undefined, root_cause: rc || undefined, day: day || undefined, tz: sp.get("tz") || getTimezone(), circuit_id: sp.get("circuit_id") || undefined,
    q: qd || undefined, page, size: 50 };
  const q = useQuery({ queryKey: ["wan-incidents", params], queryFn: () => api<any>("/wan/incidents", { params }), refetchInterval: 30_000, placeholderData: (p) => p });
  const rcl = Object.fromEntries((meta.data?.root_causes || []).map((x: any) => [x.key, x.label]));
  const reset = () => { setStatus(""); setSite(""); setIsp(""); setMissing(false); setOpenOnly(false); setRc(""); setDay(""); setText(""); setPage(1); setSp({ tab: "incidents" }); };
  return (
    <div className="space-y-4 min-w-0">
      <div className="flex flex-wrap items-center gap-2">
        <RangePicker value={r} onChange={(x) => { setR(x); setDay(""); setPage(1); }} extra={[["90d", "Last 90 days"], ["365d", "Last 12 months"]]} />
        <select aria-label="Status" className="input py-1" value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }}><option value="">Any status</option>
          {(meta.data?.statuses || []).map((x: any) => <option key={x.key} value={x.key}>{x.label}</option>)}</select>
        <select aria-label="Site" className="input py-1" value={site} onChange={(e) => { setSite(e.target.value); setPage(1); }}><option value="">All sites</option>
          {(meta.data?.sites || []).map((x: string) => <option key={x}>{x}</option>)}</select>
        <select aria-label="ISP" className="input py-1" value={isp} onChange={(e) => { setIsp(e.target.value); setPage(1); }}><option value="">All ISPs</option>
          {(meta.data?.isps || []).map((x: string) => <option key={x}>{x}</option>)}</select>
        <select aria-label="Root cause" className="input py-1" value={rc} onChange={(e) => { setRc(e.target.value); setPage(1); }}><option value="">Any root cause</option>
          {(meta.data?.root_causes || []).map((x: any) => <option key={x.key} value={x.key}>{x.label}</option>)}</select>
        <label className="text-sm flex items-center gap-1"><input type="checkbox" checked={missing} onChange={(e) => { setMissing(e.target.checked); setPage(1); }} />Missing root cause</label>
        <label className="text-sm flex items-center gap-1"><input type="checkbox" checked={openOnly} onChange={(e) => { setOpenOnly(e.target.checked); setPage(1); }} />Open only (any date)</label>
        <input aria-label="Search incidents" className="input py-1 w-44" placeholder="Search" value={text} onChange={(e) => { setText(e.target.value); setPage(1); }} />
        {(day || status || site || isp || missing || openOnly || rc) && <button className="btn" onClick={reset}>Clear filters</button>}
      </div>
      {day && <div className="text-sm">Showing incidents that started on <b>{day}</b> ({sp.get("tz") || getTimezone()}){isp && <> for <b>{isp}</b></>}.</div>}
      <Loading q={q} />
      {q.data && <Card title={`ISP incidents (${fmtNum(q.data.total)})`} bodyClass="p-0" right={<span className="text-2xs text-muted">an incident belongs to the day its first outage started</span>}>
        {!q.data.items.length ? <Empty text="No ISP incidents match." /> : <>
          <TableWrap><table className="tbl"><thead><tr><th>#</th><th>Status</th><th>Severity</th><th>Incident</th><th>ISP</th><th>Site</th><th>Started</th>
            <th className="num">Outages</th><th className="num">Downtime</th><th className="num">Time to resolve</th><th>Root cause</th><th>Owner</th></tr></thead>
            <tbody>{q.data.items.map((i: any) => <tr key={i.id} className="cursor-pointer hover:bg-white/5" onClick={() => setSel(i.id)}>
              <td className="text-muted">{i.id}</td><td><IncStatus s={i.status} />{i.ongoing && <span className="pill bg-red-500/15 text-red-300 ml-1">ongoing</span>}</td>
              <td><Sev s={i.severity} /></td><td className="font-medium max-w-[22rem] truncate" title={i.title}>{i.title}</td><td>{i.isp}</td><td>{i.site}</td>
              <td className="text-xs"><Time v={i.first_seen} /></td><td className="num">{i.outage_count}</td><td className="num"><Dur s={i.ongoing ? null : i.downtime_s} /></td>
              <td className="num"><Dur s={i.resolve_s} /></td>
              <td className="text-xs">{i.root_cause_category ? rcl[i.root_cause_category] || i.root_cause_category : <span className="text-amber-300">not set</span>}</td>
              <td className="text-xs">{i.assignee || "—"}</td></tr>)}</tbody></table></TableWrap>
          <Pager page={page} size={50} total={q.data.total} onPage={setPage} /></>}
      </Card>}
      {sel && <IncidentDrawer id={sel} onClose={() => setSel(null)} />}
    </div>
  );
}

export function IncidentDrawer({ id, onClose }: { id: number; onClose: () => void }) {
  const me = useMe();
  const qc = useQueryClient();
  const meta = useWanMeta();
  const q = useQuery({ queryKey: ["wan-incident", id], queryFn: () => api<any>(`/wan/incidents/${id}`), refetchInterval: 30_000 });
  const [form, setForm] = useState<any>(null);
  const [comment, setComment] = useState("");
  const d = q.data;
  const f = form || (d ? { status: d.status, assignee: d.assignee || "", severity: d.severity, root_cause_category: d.root_cause_category || "",
    root_cause_detail: d.root_cause_detail || "", summary: d.summary || "" } : null);
  const done = () => { setForm(null); qc.invalidateQueries({ queryKey: ["wan-incident", id] }); qc.invalidateQueries({ queryKey: ["wan-incidents"] }); qc.invalidateQueries({ queryKey: ["wan-overview"] }); };
  const save = useMutation({ mutationFn: () => api(`/wan/incidents/${id}`, { method: "PATCH", body: { ...f, assignee: f.assignee || null, root_cause_category: f.root_cause_category || null } }), onSuccess: done });
  const ack = useMutation({ mutationFn: () => api(`/wan/incidents/${id}/acknowledge`, { method: "POST" }), onSuccess: done });
  const add = useMutation({ mutationFn: () => api(`/wan/incidents/${id}/comments`, { method: "POST", body: { body: comment } }), onSuccess: () => { setComment(""); done(); } });
  const set = (k: string) => (e: any) => setForm({ ...f, [k]: e.target.value });
  return (
    <Drawer title={d ? `ISP incident #${d.id}` : "ISP incident"} onClose={onClose}>
      <Loading q={q} />
      {d && f && <div className="space-y-4">
        <div><div className="text-base font-semibold">{d.title}</div>
          <div className="text-sm flex flex-wrap gap-x-3 gap-y-1 mt-1"><IncStatus s={d.status} /><Sev s={d.severity} /><span>{d.isp} · {d.site}</span>
            <span className="text-muted">started <Time v={d.first_seen} /></span>{d.resolved_at && <span className="text-muted">resolved <Time v={d.resolved_at} /> ({dur(d.resolve_s)})</span>}
            {d.ongoing && <span className="pill bg-red-500/15 text-red-300">outage in progress</span>}</div></div>
        <Card title="Symptom and probable cause">
          <p className="text-sm">{d.summary}</p>
          {d.probable_cause && <p className="text-sm mt-2"><span className="text-muted">Probable cause (from correlated monitoring evidence): </span>{d.probable_cause}</p>}
          {d.investigation && <ul className="text-xs mt-2 space-y-0.5">{d.investigation.evidence.map((e: any, i: number) => <li key={i} className={e.ok ? "text-emerald-300" : "text-red-300"}>{e.ok ? "✓" : "✗"} {e.text}</li>)}</ul>}
          <p className="text-2xs text-muted mt-2">ICMP failures alone never confirm an ISP root cause; record the confirmed cause below.</p>
        </Card>
        <Card title="Workflow">
          <div className="grid gap-2 sm:grid-cols-2">
            <Field label="Status"><select className="input w-full" value={f.status} onChange={set("status")}>
              {(meta.data?.statuses || []).map((x: any) => <option key={x.key} value={x.key}>{x.label}</option>)}</select></Field>
            <Field label="Owner"><input className="input w-full" value={f.assignee} onChange={set("assignee")} placeholder={me.username} /></Field>
            <Field label="Severity"><select className="input w-full" value={f.severity} onChange={set("severity")}>{["low", "medium", "high", "critical"].map((x) => <option key={x}>{x}</option>)}</select></Field>
            <Field label="Confirmed root cause"><select className="input w-full" value={f.root_cause_category} onChange={set("root_cause_category")}><option value="">— not set —</option>
              {(meta.data?.root_causes || []).map((x: any) => <option key={x.key} value={x.key}>{x.label}</option>)}</select></Field>
            <div className="sm:col-span-2"><Field label="Root-cause description / provider ticket"><textarea className="input w-full h-16" value={f.root_cause_detail} onChange={set("root_cause_detail")} /></Field></div>
            <div className="sm:col-span-2"><Field label="Resolution notes / summary"><textarea className="input w-full h-16" value={f.summary} onChange={set("summary")} /></Field></div>
          </div>
          {(save.error || ack.error) && <div role="alert" className="text-sm text-red-400 mt-2">{((save.error || ack.error) as Error).message}</div>}
          <div className="flex gap-2 mt-2">
            <button className="btn btn-primary" disabled={!form || save.isPending} onClick={() => save.mutate()}>Save</button>
            {!d.acknowledged_at && <button className="btn" disabled={ack.isPending} onClick={() => ack.mutate()}>Acknowledge</button>}
            {d.acknowledged_at && <span className="text-2xs text-muted self-center">acknowledged <Time v={d.acknowledged_at} /></span>}
          </div>
        </Card>
        <Card title={`Outages (${d.outages.length})`} bodyClass="p-0">
          <TableWrap maxH="max-h-64"><table className="tbl"><thead><tr><th>Target</th><th>Source</th><th>Last healthy</th><th>First failure</th><th>Confirmed</th><th>Recovered</th>
            <th className="num">Duration</th></tr></thead>
            <tbody>{d.outages.map((o: any) => <tr key={o.id}><td>{o.target}<div className="font-mono text-2xs text-muted">{o.address}</div></td><td className="text-xs">{o.source}</td>
              <td className="text-xs"><Time v={o.last_ok_at} /></td><td className="text-xs"><Time v={o.started_at} /></td><td className="text-xs"><Time v={o.detected_at} /></td>
              <td className="text-xs">{o.ongoing ? <span className="text-red-300">ongoing</span> : <Time v={o.recovered_at} />}</td><td className="num"><Dur s={o.duration_s} /></td></tr>)}</tbody></table></TableWrap>
        </Card>
        {d.concurrent?.length > 0 && <Card title="Other ISP incidents at the same time">
          <ul className="text-sm space-y-0.5">{d.concurrent.map((x: any) => <li key={x.id}>#{x.id} <IncStatus s={x.status} /> {x.title}</li>)}</ul></Card>}
        <Card title="Timeline">
          <ol className="text-sm space-y-1">{d.timeline.map((x: any, i: number) => <li key={i} className="flex gap-2"><span className="text-xs text-muted whitespace-nowrap w-40"><Time v={x.ts} /></span>
            <span className={x.kind === "recovered" ? "text-emerald-300" : x.kind === "outage" || x.kind === "detected" ? "text-red-300" : ""}>{x.title}{x.author && x.author !== "system" && <span className="text-muted"> — {x.author}</span>}</span></li>)}</ol>
          <div className="flex gap-2 mt-3"><input aria-label="Add a comment" className="input flex-1" placeholder="Add a note (provider ticket, findings…)" value={comment} onChange={(e) => setComment(e.target.value)} />
            <button className="btn" disabled={!comment.trim() || add.isPending} onClick={() => add.mutate()}>Add</button></div>
        </Card>
      </div>}
    </Drawer>
  );
}
