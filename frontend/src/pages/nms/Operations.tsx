import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { useMe } from "../../lib/context";
import { useTheme } from "../../lib/theme";
import { fmtNum, fmtTime } from "../../lib/format";
import { Chart, SERIES_ROLE, axisStyle } from "../../components/Chart";
import { Card, Empty, Kpi, Loading, Modal, TableWrap, Time } from "../../components/ui";
import { SERVICE_STATE, TONE_TEXT, WEEKDAYS, availTone, describeScope, describeWindow, fmtAvail, serviceTarget } from "./nms";

/** Sentinel NMS operations: service checks (TCP / HTTP / DNS / TLS), maintenance windows and device dependencies.
 *  Everyone with NMS access can read; changes need the administrator role (enforced by the API). */

export function ServiceState({ s }: { s: string }) {
  const [c, l] = SERVICE_STATE[s] || SERVICE_STATE.unknown;
  return <span className="inline-flex items-center gap-1.5 whitespace-nowrap"><span className={`h-2.5 w-2.5 rounded-full ${c}`} aria-hidden />{l}</span>;
}

const useSwitches = () => useQuery({ queryKey: ["nms-deps"], queryFn: () => api<any>("/nms/dependencies"), staleTime: 60_000 });

// ------------------------------------------------------------------ service checks
const KIND_HELP: Record<string, string> = {
  tcp: "Connects to host:port; OK when the connection is accepted.",
  http: "One GET (redirects not followed); OK when the status is accepted and the body contains the expected text. HTTPS certificates are always verified.",
  dns: "Resolves the name with the NMS host's resolver; OK when it resolves (and to the expected address, if given).",
  tls: "TLS handshake with certificate verification; warns before the certificate expires.",
};

export function ServicesPage() {
  const me = useMe();
  const admin = me?.role === "admin";
  const [sp, setSp] = useSearchParams();
  const [state, setState] = useState("");
  const [edit, setEdit] = useState<any | null | undefined>(undefined);
  const q = useQuery({ queryKey: ["nms-services", state], queryFn: () => api<any>("/nms/services", { params: { state } }), refetchInterval: 30_000 });
  const sel = sp.get("id") ? Number(sp.get("id")) : null;
  const c = q.data?.counts || {};
  return <div className="space-y-4 min-w-0">
    <div className="flex flex-wrap items-center gap-2">
      <p className="text-xs text-muted flex-1 min-w-[16rem]">Synthetic checks of the services your network carries (Zabbix simple / web checks, LibreNMS services).
        A check alerts after its configured consecutive failures; latency the check could not measure is blank, never 0.</p>
      {admin && <button className="btn btn-primary" onClick={() => setEdit(null)}>+ Add service check</button>}
    </div>
    <div className="kpi-grid">
      {(["ok", "warning", "critical", "unknown", "paused"] as const).map((k) => <Kpi key={k} label={SERVICE_STATE[k][1]} value={fmtNum(c[k] || 0)}
        tone={k === "critical" && c[k] ? "bad" : k === "warning" && c[k] ? "warn" : undefined} onClick={() => setState(state === k ? "" : k)} />)}
    </div>
    <Card title={state ? `Service checks — ${SERVICE_STATE[state][1]}` : "Service checks"} bodyClass="p-0" right={state && <button className="link text-xs" onClick={() => setState("")}>Show all</button>}>
      <Loading q={q} />
      {q.data && (!q.data.items.length ? <Empty text={admin ? "No service checks yet. Add one to monitor a web app, DNS name, port or certificate." : "No service checks defined."} /> :
        <TableWrap maxH="max-h-[34rem]"><table className="tbl"><thead><tr><th>Check</th><th>Kind</th><th>Target</th><th>State</th><th className="num">Latency</th>
          <th>Last result</th><th>Certificate</th><th>Checked</th>{admin && <th />}</tr></thead>
          <tbody>{q.data.items.map((x: any) => <tr key={x.id} className={`cursor-pointer hover:bg-white/5 ${sel === x.id ? "bg-white/5" : ""}`} onClick={() => setSp({ id: String(x.id) })}>
            <td className="font-medium">{x.name}{(x.site || x.switch) && <div className="text-2xs text-muted">{[x.site, x.switch].filter(Boolean).join(" · ")}</div>}</td>
            <td className="text-xs uppercase">{x.kind}</td><td className="font-mono text-xs max-w-[18rem] truncate" title={serviceTarget(x)}>{serviceTarget(x)}</td>
            <td><ServiceState s={x.state} />{x.fail_streak > 1 && <span className="text-2xs text-muted"> ×{x.fail_streak}</span>}</td>
            <td className="num">{x.last_latency_ms == null ? "—" : `${x.last_latency_ms} ms`}</td>
            <td className="text-xs max-w-[22rem] truncate" title={x.last_message}>{x.last_message || "—"}</td>
            <td className="text-xs">{x.cert_days_left == null ? "—" : <span className={TONE_TEXT[x.cert_days_left < 7 ? "bad" : x.cert_days_left < x.cert_warn_days ? "warn" : "ok"]}>
              {x.cert_days_left < 0 ? "expired" : `${Math.floor(x.cert_days_left)} days`}</span>}</td>
            <td className="text-xs"><Time v={x.last_check_at} /></td>
            {admin && <td><button className="link text-xs" onClick={(e) => { e.stopPropagation(); setEdit(x); }}>Edit</button></td>}</tr>)}</tbody></table></TableWrap>)}
    </Card>
    {sel && <ServiceHistory id={sel} admin={admin} onClose={() => setSp({})} />}
    {edit !== undefined && <ServiceForm svc={edit} onClose={() => setEdit(undefined)} />}
  </div>;
}

function ServiceHistory({ id, admin, onClose }: { id: number; admin: boolean; onClose: () => void }) {
  const [range, setRange] = useState("24h");
  const qc = useQueryClient();
  const { theme } = useTheme();
  const q = useQuery({ queryKey: ["nms-svc-hist", id, range], queryFn: () => api<any>(`/nms/services/${id}/history`, { params: { range } }), refetchInterval: 60_000 });
  const run = useMutation({ mutationFn: () => api<any>(`/nms/services/${id}/run`, { method: "POST" }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["nms-services"] }); qc.invalidateQueries({ queryKey: ["nms-svc-hist", id] }); } });
  const d = q.data;
  const opt = useMemo(() => d && {
    tooltip: { trigger: "axis", confine: true }, legend: { top: 0 }, grid: { left: 8, right: 16, top: 32, bottom: 8, containLabel: true },
    xAxis: { type: "category", data: d.series.map((p: any) => fmtTime(p.t, false)), ...axisStyle },
    yAxis: [{ type: "value", name: "ms", ...axisStyle }, { type: "value", name: "failed", minInterval: 1, ...axisStyle, splitLine: { show: false } }],
    series: [{ name: "Latency avg", type: "line", showSymbol: false, connectNulls: false, itemStyle: { color: SERIES_ROLE[theme].primary }, data: d.series.map((p: any) => p.latency_ms) },
      { name: "Latency max", type: "line", showSymbol: false, connectNulls: false, lineStyle: { type: "dashed" }, itemStyle: { color: SERIES_ROLE[theme].muted },
        data: d.series.map((p: any) => p.latency_max_ms) },
      { name: "Failed checks", type: "bar", yAxisIndex: 1, barMaxWidth: 10, itemStyle: { color: SERIES_ROLE[theme].alert }, data: d.series.map((p: any) => p.critical) }],
  }, [d, theme]);
  return <Card title={d ? `${d.service.name} — history` : "History"} right={<div className="flex items-center gap-2">
    <select className="input py-1 text-xs" value={range} onChange={(e) => setRange(e.target.value)} aria-label="Range">{["24h", "7d", "30d", "90d"].map((r) => <option key={r}>{r}</option>)}</select>
    {admin && <button className="btn" disabled={run.isPending} onClick={() => run.mutate()}>{run.isPending ? "Running…" : "Run now"}</button>}
    <button className="link text-xs" onClick={onClose}>Close</button></div>}>
    <Loading q={q} />
    {run.error && <div role="alert" className="text-sm text-red-300 mb-2">{(run.error as Error).message}</div>}
    {d && <div className="space-y-3">
      <div className="kpi-grid">
        <Kpi label="Availability" value={fmtAvail(d.availability_pct)} tone={availTone(d.availability_pct, 99.9)} sub={`${fmtNum(d.checks)} checks`} />
        <Kpi label="State" value={<ServiceState s={d.service.state} />} sub={d.service.last_message} />
        <Kpi label="Target" value={<span className="text-sm font-mono">{serviceTarget(d.service)}</span>} sub={`every ${d.service.interval_seconds}s · timeout ${d.service.timeout_ms} ms`} />
      </div>
      {!d.series.length ? <Empty text="No results in this range yet." /> : <Chart option={opt} height={240} ariaLabel="Service latency and failures" />}
      <div className="text-sm font-medium">Recent failures and warnings</div>
      {!d.failures.length ? <Empty text="None in this range." /> : <TableWrap maxH="max-h-64"><table className="tbl"><thead><tr><th>When</th><th>State</th><th>Message</th></tr></thead>
        <tbody>{d.failures.map((f: any, i: number) => <tr key={i}><td className="text-xs"><Time v={f.ts} /></td><td><ServiceState s={f.state} /></td><td className="text-xs">{f.message}</td></tr>)}</tbody></table></TableWrap>}
    </div>}
  </Card>;
}

const SVC_BLANK = { name: "", kind: "http", target: "", port: "", expect: "200-399", match: "", record: "A", switch_id: "", site: "", interval_seconds: 60, timeout_ms: 5000,
  latency_warn_ms: "", cert_warn_days: 21, enabled: true };

function ServiceForm({ svc, onClose }: { svc: any | null; onClose: () => void }) {
  const qc = useQueryClient();
  const sws = useSwitches();
  const [f, setF] = useState<any>(() => ({ ...SVC_BLANK, ...(svc || {}), port: svc?.port ?? "", switch_id: svc?.switch_id ?? "", latency_warn_ms: svc?.latency_warn_ms ?? "" }));
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value });
  const inp = (k: string, l: string, p: any = {}) => <div><label className="label">{l}</label><input className="input w-full" value={f[k] ?? ""} onChange={set(k)} {...p} /></div>;
  const num = (v: any) => (v === "" || v == null ? null : Number(v));
  const body = () => ({ ...f, port: num(f.port), switch_id: num(f.switch_id), latency_warn_ms: num(f.latency_warn_ms), interval_seconds: Number(f.interval_seconds),
    timeout_ms: Number(f.timeout_ms), cert_warn_days: Number(f.cert_warn_days), expect: f.kind === "http" ? f.expect : "", match: ["http", "dns"].includes(f.kind) ? f.match : "" });
  const done = () => { qc.invalidateQueries({ queryKey: ["nms-services"] }); onClose(); };
  const save = useMutation({ mutationFn: () => api(svc ? `/nms/services/${svc.id}` : "/nms/services", { method: svc ? "PUT" : "POST", body: body() }), onSuccess: done });
  const del = useMutation({ mutationFn: () => api(`/nms/services/${svc.id}`, { method: "DELETE" }), onSuccess: done });
  const err = (save.error || del.error) as Error | null;
  return <Modal wide title={svc ? `Edit ${svc.name}` : "Add a service check"} onClose={onClose}>
    <div className="grid gap-2 sm:grid-cols-3">
      {inp("name", "Name", { placeholder: "Warehouse portal HTTPS" })}
      <div><label className="label">Kind</label><select className="input w-full" value={f.kind} onChange={set("kind")}>
        <option value="http">HTTP(S)</option><option value="tcp">TCP port</option><option value="dns">DNS lookup</option><option value="tls">TLS certificate</option></select></div>
      {inp("target", f.kind === "http" ? "URL" : "Host name or IP", { placeholder: f.kind === "http" ? "https://portal.example.com/health" : "10.20.0.5" })}
      {["tcp", "tls"].includes(f.kind) && inp("port", "Port", { type: "number", min: 1, max: 65535, placeholder: f.kind === "tls" ? "443" : "22" })}
      {f.kind === "http" && inp("expect", "Accepted status codes", { placeholder: "200-399" })}
      {f.kind === "http" && inp("match", "Body must contain (optional)", { placeholder: "ok" })}
      {f.kind === "dns" && <div><label className="label">Record</label><select className="input w-full" value={f.record} onChange={set("record")}><option>A</option><option>AAAA</option></select></div>}
      {f.kind === "dns" && inp("match", "Expected address (optional)", { placeholder: "10.20.0.5" })}
      {f.kind === "tls" && inp("cert_warn_days", "Warn days before expiry", { type: "number", min: 1, max: 365 })}
      {inp("interval_seconds", "Check every (seconds)", { type: "number", min: 30, max: 86400 })}{inp("timeout_ms", "Timeout (ms)", { type: "number", min: 500, max: 60000 })}
      {inp("latency_warn_ms", "Warn above latency (ms, optional)", { type: "number", min: 1 })}
      {inp("site", "Site (for correlation and maintenance)")}
      <div><label className="label">Related device (optional)</label><select className="input w-full" value={f.switch_id} onChange={set("switch_id")}>
        <option value="">—</option>{(sws.data?.items || []).map((s: any) => <option key={s.id} value={s.id}>{s.name}</option>)}</select></div>
      <label className="flex items-center gap-2 text-sm mt-5"><input type="checkbox" checked={!!f.enabled} onChange={set("enabled")} /> Enabled</label>
    </div>
    <p className="text-xs text-muted mt-2">{KIND_HELP[f.kind]}</p>
    {err && <div role="alert" className="text-sm text-red-300 mt-2">{err.message}</div>}
    <div className="flex gap-2 justify-end mt-3">
      {svc && <button className="btn mr-auto text-red-300" disabled={del.isPending} onClick={() => confirm(`Delete ${svc.name} and its history link?`) && del.mutate()}>Delete</button>}
      <button className="btn" onClick={onClose}>Cancel</button>
      <button className="btn btn-primary" disabled={save.isPending || !f.name || !f.target} onClick={() => save.mutate()}>{save.isPending ? "Saving…" : "Save"}</button>
    </div>
  </Modal>;
}

// ------------------------------------------------------------------ maintenance
export function MaintenancePage() {
  const me = useMe();
  const admin = me?.role === "admin";
  const [edit, setEdit] = useState<any | null | undefined>(undefined);
  const q = useQuery({ queryKey: ["nms-mw"], queryFn: () => api<any>("/nms/maintenance"), refetchInterval: 60_000 });
  const sws = useSwitches();
  const svcs = useQuery({ queryKey: ["nms-services", ""], queryFn: () => api<any>("/nms/services") });
  const names = Object.fromEntries((sws.data?.items || []).map((s: any) => [s.id, s.name]));
  const svcNames = Object.fromEntries((svcs.data?.items || []).map((s: any) => [s.id, s.name]));
  return <div className="space-y-4 min-w-0">
    <div className="flex flex-wrap items-center gap-2">
      <p className="text-xs text-muted flex-1 min-w-[16rem]">While a window is active, new network alerts of the devices, sites and service checks it covers are held back (no alert, no
        notification). Polling continues, so graphs and availability keep their data. A condition still present when the window ends alerts normally.</p>
      {admin && <button className="btn btn-primary" onClick={() => setEdit(null)}>+ Schedule maintenance</button>}
    </div>
    <div className="kpi-grid"><Kpi label="Active now" value={fmtNum(q.data?.active || 0)} tone={q.data?.active ? "warn" : undefined} />
      <Kpi label="Windows" value={fmtNum(q.data?.items?.length || 0)} /></div>
    <Card title="Maintenance windows" bodyClass="p-0"><Loading q={q} />
      {q.data && (!q.data.items.length ? <Empty text="No maintenance windows." /> :
        <TableWrap><table className="tbl"><thead><tr><th>Name</th><th>Status</th><th>Schedule</th><th>Covers</th><th>Reason</th><th>By</th>{admin && <th />}</tr></thead>
          <tbody>{q.data.items.map((m: any) => <tr key={m.id}><td className="font-medium">{m.name}</td>
            <td>{!m.enabled ? <span className="text-muted">disabled</span> : m.active ? <span className="text-amber-300">active until {fmtTime(m.active_until, false)}</span> :
              m.expired ? <span className="text-muted">finished</span> : <span className="text-emerald-300">scheduled</span>}</td>
            <td className="text-xs">{describeWindow(m, (v) => fmtTime(v, false))}</td><td className="text-xs">{describeScope(m, names, svcNames)}</td>
            <td className="text-xs max-w-[18rem] truncate" title={m.reason}>{m.reason || "—"}</td><td className="text-xs">{m.created_by}</td>
            {admin && <td><button className="link text-xs" onClick={() => setEdit(m)}>Edit</button></td>}</tr>)}</tbody></table></TableWrap>)}</Card>
    {edit !== undefined && <MaintenanceForm m={edit} switches={sws.data?.items || []} services={svcs.data?.items || []} onClose={() => setEdit(undefined)} />}
  </div>;
}

const toLocalInput = (iso?: string | null) => {
  if (!iso) return "";
  const d = new Date(iso);
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
};

function MaintenanceForm({ m, switches, services, onClose }: { m: any | null; switches: any[]; services: any[]; onClose: () => void }) {
  const qc = useQueryClient();
  const now = new Date();
  const [f, setF] = useState<any>(() => ({
    name: "", reason: "", kind: "once", weekdays: [] as number[], start_time: "22:00", duration_minutes: 120, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC",
    all_devices: false, switch_ids: [] as number[], sites: [] as string[], service_ids: [] as number[], enabled: true, ...(m || {}),
    starts: toLocalInput(m?.starts_at || now.toISOString()), ends: toLocalInput(m?.ends_at || new Date(now.getTime() + 2 * 3600e3).toISOString()),
    sitesText: (m?.sites || []).join(", "),
  }));
  const sites = useMemo(() => Array.from(new Set(switches.map((s) => s.site).filter(Boolean))).sort() as string[], [switches]);
  const toggle = (k: string, v: any) => setF({ ...f, [k]: f[k].includes(v) ? f[k].filter((x: any) => x !== v) : [...f[k], v] });
  const body = () => ({ name: f.name, reason: f.reason, kind: f.kind, enabled: f.enabled, all_devices: f.all_devices, switch_ids: f.switch_ids, service_ids: f.service_ids,
    sites: String(f.sitesText).split(",").map((x) => x.trim()).filter(Boolean), weekdays: f.weekdays, start_time: f.start_time, duration_minutes: Number(f.duration_minutes),
    timezone: f.timezone, starts_at: f.kind === "once" && f.starts ? new Date(f.starts).toISOString() : null, ends_at: f.kind === "once" && f.ends ? new Date(f.ends).toISOString() : null });
  const done = () => { qc.invalidateQueries({ queryKey: ["nms-mw"] }); onClose(); };
  const save = useMutation({ mutationFn: () => api(m ? `/nms/maintenance/${m.id}` : "/nms/maintenance", { method: m ? "PUT" : "POST", body: body() }), onSuccess: done });
  const del = useMutation({ mutationFn: () => api(`/nms/maintenance/${m.id}`, { method: "DELETE" }), onSuccess: done });
  const err = (save.error || del.error) as Error | null;
  return <Modal wide title={m ? `Edit ${m.name}` : "Schedule maintenance"} onClose={onClose}>
    <div className="grid gap-2 sm:grid-cols-3">
      <div><label className="label">Name</label><input className="input w-full" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="Core switch upgrade" /></div>
      <div><label className="label">Type</label><select className="input w-full" value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })}>
        <option value="once">One-off</option><option value="weekly">Weekly</option></select></div>
      <div><label className="label">Time zone</label><input className="input w-full" value={f.timezone} onChange={(e) => setF({ ...f, timezone: e.target.value })} /></div>
      {f.kind === "once" ? <>
        <div><label className="label">Starts (your local time)</label><input type="datetime-local" className="input w-full" value={f.starts} onChange={(e) => setF({ ...f, starts: e.target.value })} /></div>
        <div><label className="label">Ends</label><input type="datetime-local" className="input w-full" value={f.ends} onChange={(e) => setF({ ...f, ends: e.target.value })} /></div>
      </> : <>
        <div className="sm:col-span-3"><label className="label">Days</label><div className="flex flex-wrap gap-2">{WEEKDAYS.map((d, i) =>
          <label key={d} className="flex items-center gap-1 text-sm"><input type="checkbox" checked={f.weekdays.includes(i)} onChange={() => toggle("weekdays", i)} />{d}</label>)}</div></div>
        <div><label className="label">Start time (HH:MM, in the time zone)</label><input className="input w-full" value={f.start_time} onChange={(e) => setF({ ...f, start_time: e.target.value })} /></div>
        <div><label className="label">Duration (minutes)</label><input type="number" min={1} max={10080} className="input w-full" value={f.duration_minutes}
          onChange={(e) => setF({ ...f, duration_minutes: e.target.value })} /></div>
      </>}
      <div className="sm:col-span-3"><label className="label">Reason</label><input className="input w-full" value={f.reason} onChange={(e) => setF({ ...f, reason: e.target.value })}
        placeholder="Change ticket, vendor, what is expected to go down" /></div>
      <label className="sm:col-span-3 flex items-center gap-2 text-sm"><input type="checkbox" checked={f.all_devices} onChange={(e) => setF({ ...f, all_devices: e.target.checked })} />
        Hold back all network alerts (every device, circuit and check)</label>
      {!f.all_devices && <>
        <div className="sm:col-span-3"><label className="label">Sites (comma separated{sites.length ? `; known: ${sites.join(", ")}` : ""})</label>
          <input className="input w-full" value={f.sitesText} onChange={(e) => setF({ ...f, sitesText: e.target.value })} /></div>
        <div className="sm:col-span-2"><label className="label">Devices</label><div className="max-h-40 overflow-auto border border-line rounded p-2 grid sm:grid-cols-2 gap-1">
          {switches.map((s) => <label key={s.id} className="flex items-center gap-1 text-xs"><input type="checkbox" checked={f.switch_ids.includes(s.id)} onChange={() => toggle("switch_ids", s.id)} />
            {s.name}{s.site && <span className="text-muted"> · {s.site}</span>}</label>)}</div></div>
        <div><label className="label">Service checks</label><div className="max-h-40 overflow-auto border border-line rounded p-2 space-y-1">
          {!services.length && <div className="text-xs text-muted">None defined.</div>}
          {services.map((s) => <label key={s.id} className="flex items-center gap-1 text-xs"><input type="checkbox" checked={f.service_ids.includes(s.id)} onChange={() => toggle("service_ids", s.id)} />{s.name}</label>)}</div></div>
      </>}
      <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked })} /> Enabled</label>
    </div>
    {err && <div role="alert" className="text-sm text-red-300 mt-2">{err.message}</div>}
    <div className="flex gap-2 justify-end mt-3">
      {m && <button className="btn mr-auto text-red-300" disabled={del.isPending} onClick={() => confirm(`Delete ${m.name}?`) && del.mutate()}>Delete</button>}
      <button className="btn" onClick={onClose}>Cancel</button>
      <button className="btn btn-primary" disabled={save.isPending || !f.name} onClick={() => save.mutate()}>{save.isPending ? "Saving…" : "Save"}</button>
    </div>
  </Modal>;
}

// ------------------------------------------------------------------ dependencies
export function DependenciesPage() {
  const me = useMe();
  const admin = me?.role === "admin";
  const qc = useQueryClient();
  const q = useSwitches();
  const [err, setErr] = useState("");
  const set = useMutation({ mutationFn: ({ id, parent_id }: { id: number; parent_id: number | null }) => api(`/nms/dependencies/${id}`, { method: "PUT", body: { parent_id } }),
    onSuccess: () => { setErr(""); qc.invalidateQueries({ queryKey: ["nms-deps"] }); }, onError: (e: Error) => setErr(e.message) });
  const items: any[] = q.data?.items || [];
  const roots = items.filter((x) => !x.parent_id);
  return <div className="space-y-4 min-w-0">
    <p className="text-xs text-muted">Tell the NMS which device each device is reached through (its upstream / parent). When a parent is unreachable, the devices behind it are not
      alerted separately: the parent's alert lists them as the root cause (LibreNMS dependencies, Zabbix trigger dependencies). Loops are refused.</p>
    <div className="kpi-grid"><Kpi label="Devices" value={fmtNum(items.length)} /><Kpi label="With a parent" value={fmtNum(items.length - roots.length)} />
      <Kpi label="Top-level" value={fmtNum(roots.length)} /></div>
    {err && <div role="alert" className="text-sm text-red-300">{err}</div>}
    <Card title="Device dependencies" bodyClass="p-0"><Loading q={q} />
      {q.data && (!items.length ? <Empty text="No devices yet." /> :
        <TableWrap maxH="max-h-[40rem]"><table className="tbl"><thead><tr><th>Device</th><th>Site</th><th>Role</th><th>State</th><th>Depends on (parent)</th><th className="num">Children</th></tr></thead>
          <tbody>{items.map((x) => <tr key={x.id}><td><Link className="link" to={`/switches/${x.id}`}>{x.name}</Link></td><td>{x.site || "—"}</td><td>{x.role || "—"}</td>
            <td className={x.state === "down" ? "text-red-300" : x.state === "up" ? "text-emerald-300" : "text-muted"}>{x.state}</td>
            <td>{admin ? <select className="input py-1 text-xs" value={x.parent_id ?? ""} aria-label={`Parent of ${x.name}`}
              onChange={(e) => set.mutate({ id: x.id, parent_id: e.target.value ? Number(e.target.value) : null })}>
              <option value="">— none (top-level) —</option>{items.filter((p) => p.id !== x.id).map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}</select>
              : x.parent || <span className="text-muted">—</span>}</td>
            <td className="num">{x.children || "—"}</td></tr>)}</tbody></table></TableWrap>)}</Card>
  </div>;
}
