import { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, downloadUrl, Params } from "../lib/api";
import { useData, useGlobal } from "../lib/context";
import { fmtBytes, fmtTime } from "../lib/format";
import { Action, Card, Drawer, Empty, IpLink, Loading, Sev, Tabs, Time, Trunc, rowProps, useDebounced } from "../components/ui";
import { QL_HELP, SaveSearch } from "./Searches";

const FIELDS: [string, string, string?][] = [
  ["src_ip", "Source IP / CIDR"], ["dst_ip", "Destination IP / CIDR"], ["src_port", "Source port"], ["dst_port", "Destination port"],
  ["proto", "Protocol number", "6=TCP 17=UDP"], ["app", "Application"], ["domain", "Domain / hostname"], ["dns_query", "DNS query contains"],
  ["policy_id", "Policy ID"], ["event_type", "FortiGate type"], ["event_subtype", "Subtype"], ["user", "User"], ["q", "Text search (raw log)"],
];
const MULTI = ["category", "action", "severity", "firewall_id", "site"];

function paramsFromSearch(sp: URLSearchParams): Params {
  const p: Params = {};
  sp.forEach((v, k) => {
    if (MULTI.includes(k)) p[k] = [...((p[k] as string[]) || []), v];
    else p[k] = v;
  });
  return p;
}

export function EventTable({ fixed = {}, filters = {} }: { fixed?: Params; filters?: Params }) {
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(50);
  const [sort, setSort] = useState("event_time");
  const [order, setOrder] = useState<"asc" | "desc">("desc");
  const [sel, setSel] = useState<string | null>(null);
  const g = useGlobal();
  const extra = { ...filters, ...fixed, page, size, sort, order };
  useEffect(() => setPage(1), [JSON.stringify(filters), JSON.stringify(g.params)]);
  const q = useData<any>("/events", extra);
  const pages = q.data ? Math.max(1, Math.ceil(q.data.total / size)) : 1;
  const th = (k: string, l: string) => (
    <th className="cursor-pointer select-none" onClick={() => { if (sort === k) setOrder(order === "asc" ? "desc" : "asc"); else { setSort(k); setOrder("desc"); } }}>
      {l}{sort === k ? (order === "asc" ? " ▲" : " ▼") : ""}
    </th>
  );
  const exportParams = { ...g.params, ...filters, ...fixed };
  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 mb-2 text-sm">
        <span className="text-muted">{q.data ? `${q.data.total.toLocaleString()} events` : ""}</span>
        <div className="flex-1" />
        <a className="btn" href={downloadUrl("/events/export.csv", exportParams)}>Export CSV</a>
        <select className="input py-1" value={size} onChange={(e) => { setSize(Number(e.target.value)); setPage(1); }}>
          {[25, 50, 100, 250].map((n) => <option key={n} value={n}>{n} / page</option>)}
        </select>
        <button className="btn" disabled={page <= 1} onClick={() => setPage(page - 1)}>‹</button>
        <span className="text-muted">{page} / {pages}</span>
        <button className="btn" disabled={page >= pages} onClick={() => setPage(page + 1)}>›</button>
      </div>
      <Loading q={q} />
      {q.data && !q.data.items.length && <Empty text="No matching events." />}
      {!!q.data?.items.length && (
        <div className="tbl-wrap"><table className="tbl">
          <thead><tr>{th("event_time", "Time")}<th>Firewall</th><th>Type</th>{th("severity", "Sev")}{th("src_ip", "Source")}{th("dst_ip", "Destination")}{th("dst_port", "Port")}<th>Proto</th>{th("action", "Action")}<th>Policy</th><th>App / Service</th><th>Detail</th>{th("sent_bytes", "Sent")}{th("rcvd_bytes", "Rcvd")}<th>Src</th></tr></thead>
          <tbody>{q.data.items.map((e: any) => (
            <tr key={e.event_id} {...rowProps(() => setSel(e.event_id))}>
              <td className="text-xs"><Time v={e.event_time} /></td>
              <td className="text-xs nowrap">{e.firewall_name}<div className="text-muted">{e.site}</div></td>
              <td className="text-xs nowrap">{e.category}<div className="text-muted">{e.event_subtype}</div></td>
              <td><Sev s={e.severity} /></td>
              <td className="text-xs nowrap"><IpLink ip={e.src_ip} />{e.src_port != null && <span className="text-muted">:{e.src_port}</span>}{e.src_name && <div className="text-muted">{e.src_name}</div>}</td>
              <td className="text-xs nowrap"><IpLink ip={e.dst_ip} />{e.dst_country && <div className="text-muted">{e.dst_country}</div>}</td>
              <td className="font-mono text-xs">{e.dst_port ?? "—"}</td><td className="text-xs">{e.proto_name}</td>
              <td className="text-xs"><Action a={e.action} /></td><td className="text-xs">{e.policy_id ?? "—"}</td>
              <td className="text-xs"><Trunc text={e.app || e.service} max="max-w-[10rem]" /></td>
              <td className="text-xs">
                {e.ti_match && <span className="pill bg-red-500/20 text-red-300 mr-1" title={`Threat intel: ${e.ti_category}`}>TI</span>}
                {e.category === "dns" ? <Trunc className="font-mono" text={[e.dns_qtype, e.dns_qname, e.dns_rcode].filter(Boolean).join(" ")} />
                  : e.category === "web" ? <Trunc className="font-mono" text={e.url_is_full ? e.url : [e.hostname, e.url].filter(Boolean).join(" · path ")} />
                  : <Trunc text={e.threat || e.msg || e.hostname} />}
              </td>
              <td className="text-xs num">{e.sent_bytes ? fmtBytes(e.sent_bytes) : ""}</td><td className="text-xs num">{e.rcvd_bytes ? fmtBytes(e.rcvd_bytes) : ""}</td>
              <td><span className={`pill ${e.source === "demo" ? "bg-amber-600/30 text-amber-200" : "bg-slate-800 text-slate-400"}`}>{e.source}</span></td>
            </tr>))}</tbody>
        </table></div>
      )}
      {sel && <EventDrawer id={sel} onClose={() => setSel(null)} />}
    </div>
  );
}

function EventDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const [tab, setTab] = useState("context");
  const q = useQuery({ queryKey: ["event", id], queryFn: () => api<any>(`/events/${id}`) });
  const e = q.data;
  let raw = e?.raw || "";
  try { if (raw.startsWith("{")) raw = JSON.stringify(JSON.parse(raw), null, 2); } catch { /* keep */ }
  return (
    <Drawer title="Event detail" onClose={onClose}>
      <Loading q={q} />
      {e && <>
        <div className="text-xs text-muted mb-2">Source: <b>{e.source}</b> · parser {e.parser_version} · ingested {fmtTime(e.ingest_time)}{e.source === "demo" && <span className="text-amber-300"> · DEMO DATA</span>}</div>
        <Tabs value={tab} onChange={setTab} tabs={[{ key: "context", label: "Context" }, { key: "normalized", label: "Normalized fields" }, { key: "raw", label: "Raw log" }]} />
        {tab === "context" ? <EventContext id={id} e={e} /> : tab === "normalized" ? (
          <div className="tbl-wrap"><table className="tbl"><tbody>{Object.entries(e).filter(([k]) => k !== "raw").map(([k, v]) => (
            <tr key={k}><td className="text-muted text-xs w-40 nowrap">{k}</td><td className="font-mono text-xs whitespace-pre-wrap break-all">{v === null || v === "" ? <span className="text-slate-600">—</span> : Array.isArray(v) ? v.join(", ") : String(v)}</td></tr>
          ))}</tbody></table></div>
        ) : <pre className="text-xs bg-panel2 p-3 rounded whitespace-pre-wrap break-all font-mono">{raw}</pre>}
      </>}
    </Drawer>
  );
}

function EventContext({ id, e }: { id: string; e: any }) {
  const nav = useNavigate();
  const q = useQuery({ queryKey: ["event-ctx", id], queryFn: () => api<any>(`/events/${id}/context`) });
  const c = q.data;
  const [added, setAdded] = useState("");
  const toIncident = async () => {
    const n = prompt("Add this event as evidence to incident #");
    if (!n || !/^\d+$/.test(n)) return;
    try {
      await api(`/incidents/${n}/evidence`, { method: "POST", body: { type: "event", ref: id, label: `${e.category} ${e.src_ip || ""} → ${e.dst_ip || ""}`.trim() } });
      setAdded(`Added to incident #${n}`);
    } catch (err) { setAdded((err as Error).message); }
  };
  return (
    <div className="space-y-3 text-sm">
      <Loading q={q} />
      <div className="flex flex-wrap gap-2">
        {e.src_ip && <button className="btn" onClick={() => nav(`/graph?kind=ip&value=${encodeURIComponent(e.src_ip)}`)}>Graph source</button>}
        {e.dst_ip && <button className="btn" onClick={() => nav(`/graph?kind=ip&value=${encodeURIComponent(e.dst_ip)}`)}>Graph destination</button>}
        {e.src_ip && <button className="btn" onClick={() => nav(`/search?q=${encodeURIComponent(`src:${e.src_ip} | stats count, dc(dst_ip) as dsts, dc(dst_port) as ports by category, action`)}`)}>Pivot on source</button>}
        <button className="btn" onClick={toIncident}>Add to incident…</button>
        {added && <span className="text-xs text-muted self-center">{added}</span>}
      </div>
      {c && <>
        <div className="grid gap-3 md:grid-cols-2">
          {(["source", "destination"] as const).map((role) => { const x = c.entities[role]; return x ? (
            <div key={role} className="border border-line rounded-lg p-3 space-y-1">
              <div className="text-2xs uppercase tracking-wide text-muted">{role}</div>
              <div><IpLink ip={x.ip} />{x.country && <span className="text-xs text-muted"> · {x.country}</span>}{x.as_org && <span className="text-xs text-muted"> · {x.as_org}</span>}</div>
              {x.asset ? <div className="text-xs">{x.asset.hostname || "unnamed host"} · <b>{x.asset.criticality}</b>{x.asset.owner && ` · ${x.asset.owner}`}{x.asset.last_user && ` · user ${x.asset.last_user}`}</div>
                : <div className="text-xs text-muted">not in the asset inventory</div>}
              {x.threat_intel.length > 0 && <div className="text-xs text-red-300">Threat intel: {x.threat_intel.map((t: any) => `${t.feed} (${t.category})`).join(", ")}</div>}
              {x.watchlists.length > 0 && <div className="text-xs">Watchlists: {x.watchlists.map((w: string) => <span key={w} className="pill bg-brand-500/10 text-brand-400 mr-1">{w}</span>)}</div>}
            </div>) : null; })}
        </div>
        {c.policy && <div className="border border-line rounded-lg p-3 text-xs">
          <div className="text-2xs uppercase tracking-wide text-muted mb-1">Matching firewall policy</div>
          <button className="link" onClick={() => nav(`/policies/${c.policy.firewall_id}/${c.policy.vdom}/${c.policy.policyid}`)}>#{c.policy.policyid} {c.policy.name || "(unnamed)"}</button>
          {" "}· {c.policy.action} · {c.policy.status} · logging {c.policy.logtraffic}{c.policy.usage && ` · usage ${c.policy.usage}`}{c.policy.shadow && <span className="text-amber-300"> · {c.policy.shadow}</span>}
        </div>}
        {c.session && Object.keys(c.session).length > 0 && <div className="text-xs text-muted">Same session: {Object.entries(c.session).map(([k, v]) => `${v} ${k}`).join(", ")} event(s)</div>}
        <div><div className="text-2xs uppercase tracking-wide text-muted mb-1">Alerts on these IPs (7 days)</div>
          {c.alerts.length ? <ul className="space-y-0.5">{c.alerts.map((a: any) => <li key={a.id}><Sev s={a.severity} /> <button className="link" onClick={() => nav(`/alerts?id=${a.id}`)}>{a.name}</button> <span className="text-xs text-muted">{a.status} · <Time v={a.last_seen} /></span></li>)}</ul>
            : <div className="text-xs text-muted">none</div>}</div>
        {c.incidents.length > 0 && <div><div className="text-2xs uppercase tracking-wide text-muted mb-1">Incidents</div>
          <ul className="space-y-0.5">{c.incidents.map((i: any) => <li key={i.id}><Sev s={i.severity} /> <button className="link" onClick={() => nav(`/incidents/${i.id}`)}>#{i.id} {i.title}</button> <span className="text-xs text-muted">{i.status}</span></li>)}</ul></div>}
      </>}
    </div>
  );
}

function QueryBar({ value, onRun }: { value: string; onRun: (q: string) => void }) {
  const [q, setQ] = useState(value);
  const [save, setSave] = useState(false);
  const g = useGlobal();
  useEffect(() => setQ(value), [value]);
  const dq = useDebounced(q, 350);
  const val = useQuery({ queryKey: ["ql-validate", dq], queryFn: () => api<any>("/ql/validate", { method: "POST", body: { query: dq } }), enabled: !!dq.trim() });
  const saved = useQuery({ queryKey: ["searches"], queryFn: () => api<any[]>("/searches") });
  const invalid = !!dq.trim() && val.data && !val.data.valid;
  return (
    <Card title="Query" right={<div className="flex flex-wrap gap-2">
      <select aria-label="Load saved search" className="input py-1 max-w-[14rem]" value="" onChange={(e) => { const s = saved.data?.find((x) => String(x.id) === e.target.value); if (s) { setQ(s.query); onRun(s.query); } }}>
        <option value="">Saved searches…</option>{(saved.data || []).map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select>
      <button className="btn" disabled={!q.trim() || invalid} onClick={() => setSave(true)}>Save</button></div>}>
      <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); if (!invalid) onRun(q.trim()); }}>
        <input aria-label="Query" aria-invalid={invalid} className={`input flex-1 font-mono ${invalid ? "border-red-500" : ""}`} value={q} onChange={(e) => setQ(e.target.value)}
          placeholder='src_ip:10.0.0.0/8 AND action:deny AND dst_port:445   ·   country:"Russia" OR ti:*   ·   -user:svc_* "login failed"' />
        <button className="btn btn-primary" disabled={invalid}>Search</button>
        {value && <button type="button" className="btn" onClick={() => { setQ(""); onRun(""); }}>Clear</button>}
      </form>
      {invalid ? <p role="alert" className="text-xs text-red-400 mt-1">{val.data.error}</p> : <p className="text-2xs text-muted mt-1" title={QL_HELP}>Fields, CIDR, ranges (port:1-1024), comparisons (bytes&gt;=1000000), AND/OR/NOT, wildcards. Hover for the full list.</p>}
      {save && <SaveSearch query={q} range={g.range === "custom" ? "24h" : g.range} onClose={() => setSave(false)} />}
    </Card>
  );
}

export function Explorer() {
  const [sp, setSp] = useSearchParams();
  const urlFilters = useMemo(() => paramsFromSearch(sp), [sp]);
  const [form, setForm] = useState<Record<string, string>>({});
  useEffect(() => {
    const f: Record<string, string> = {};
    sp.forEach((v, k) => { if (!MULTI.includes(k)) f[k] = v; });
    setForm(f);
  }, [sp]);
  const multi = (k: string) => (urlFilters[k] as string[]) || [];
  const toggle = (k: string, v: string) => {
    const cur = new Set(multi(k));
    cur.has(v) ? cur.delete(v) : cur.add(v);
    const n = new URLSearchParams(sp);
    n.delete(k);
    cur.forEach((x) => n.append(k, x));
    setSp(n);
  };
  const apply = () => {
    const n = new URLSearchParams();
    MULTI.forEach((k) => multi(k).forEach((v) => n.append(k, v)));
    Object.entries(form).forEach(([k, v]) => v && n.set(k, v));
    setSp(n);
  };
  // URL start/end (e.g. from an alert) override the global range
  const filters = { ...urlFilters };
  if (filters.start) filters.range = undefined;
  return (
    <div className="space-y-3">
      <QueryBar value={sp.get("ql") || ""} onRun={(q) => { const n = new URLSearchParams(sp); if (q) n.set("ql", q); else n.delete("ql"); setSp(n); }} />
      <Card title="Filters" right={<div className="flex flex-wrap gap-2"><button className="btn" onClick={() => setSp(new URLSearchParams())}>Clear</button><button className="btn btn-primary" onClick={apply}>Apply</button></div>}>
        <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-7 gap-2" onKeyDown={(e) => e.key === "Enter" && apply()}>
          {FIELDS.map(([k, l, ph]) => (
            <div key={k}><label className="label">{l}</label><input className="input w-full" placeholder={ph} value={form[k] || ""} onChange={(e) => setForm({ ...form, [k]: e.target.value })} /></div>
          ))}
          <div><label className="label">Verdict</label><select className="input w-full" value={form.verdict || ""} onChange={(e) => setForm({ ...form, verdict: e.target.value })}><option value="">any</option><option value="allowed">allowed</option><option value="denied">denied</option></select></div>
        </div>
        <div className="flex flex-wrap gap-4 mt-3 text-xs">
          {([["category", ["traffic", "dns", "web", "security", "system"]], ["action", ["accept", "close", "timeout", "reset", "deny", "block", "allow", "monitor"]],
            ["severity", ["critical", "high", "medium", "low", "informational"]]] as [string, string[]][]).map(([k, vals]) => (
            <div key={k} className="flex flex-wrap items-center gap-1"><span className="text-muted mr-1">{k}:</span>
              {vals.map((v) => <button key={v} onClick={() => toggle(k, v)} className={`pill border ${multi(k).includes(v) ? "border-brand-500 bg-brand-500/10 text-brand-400" : "border-line text-slate-400"}`}>{v}</button>)}
            </div>
          ))}
        </div>
        {urlFilters.start && <div className="text-xs text-amber-300 mt-2">Time window from link: {fmtTime(urlFilters.start)} → {urlFilters.end ? fmtTime(urlFilters.end) : "now"} (overrides global range)</div>}
      </Card>
      <Card><EventTable filters={filters} /></Card>
    </div>
  );
}
