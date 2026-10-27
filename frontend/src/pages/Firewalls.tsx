import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useMe } from "../lib/context";
import { fmtAgo, fmtBytes, fmtDuration, fmtTime } from "../lib/format";
import { Card, Drawer, Empty, Loading, Modal, rowProps } from "../components/ui";
import { Chart, axisStyle } from "../components/Chart";

const VENDOR: Record<string, [string, string]> = { fortinet: ["FortiGate", "bg-red-500/10 text-red-300"], paloalto: ["Palo Alto", "bg-orange-500/15 text-orange-300"] };
const ZONES = ["UTC", "Asia/Kolkata", "Asia/Dubai", "Asia/Singapore", "Europe/London", "Europe/Berlin", "America/New_York", "America/Los_Angeles"];
const linkUp = (v: any) => v === true || v === "up";

const API_TONE: Record<string, string> = { ok: "bg-emerald-700/30 text-emerald-200", auth_error: "bg-red-700/40 text-red-200",
  unreachable: "bg-red-700/40 text-red-200", error: "bg-amber-700/40 text-amber-200", unknown: "bg-slate-700 text-slate-300", demo: "bg-amber-600/30 text-amber-200" };

function ingestTone(lag?: number | null) {
  if (lag == null) return "text-slate-500";
  return lag < 300 ? "text-emerald-400" : lag < 3600 ? "text-amber-300" : "text-red-400";
}

export function Firewalls() {
  const me = useMe();
  const q = useQuery({ queryKey: ["firewalls"], queryFn: () => api<any[]>("/firewalls"), refetchInterval: 30_000 });
  const [edit, setEdit] = useState<any | null>(null);
  const [detail, setDetail] = useState<any | null>(null);
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-xs text-muted flex-1 min-w-[14rem]">API connectivity and log ingestion are tracked separately: a healthy API connection does not mean traffic/DNS logs are arriving.</p>
        {me.role === "admin" && <>
          <button className="btn" onClick={() => setEdit({ vendor: "paloalto" })}>+ Palo Alto firewall</button>
          <button className="btn btn-primary" onClick={() => setEdit({ vendor: "fortinet" })}>+ FortiGate</button></>}
      </div>
      <Card>
        <Loading q={q} />
        {q.data && !q.data.length && <Empty text="No firewalls registered yet." />}
        {!!q.data?.length && <div className="tbl-wrap"><table className="tbl">
          <thead><tr><th>Name</th><th>Management</th><th>OS version</th><th>Site</th><th>API</th><th>Last poll</th><th>Log ingestion</th><th className="num">Lag</th><th className="num">CPU</th><th className="num">Mem</th><th className="num">Sessions</th><th></th></tr></thead>
          <tbody>{q.data.map((f) => {
            const res = f.health?.resources || {};
            const ing = (f.ingest || []).sort((a: any, b: any) => String(b.last_ingest_time).localeCompare(String(a.last_ingest_time)))[0];
            return (
              <tr key={f.id} {...rowProps(() => setDetail(f))}>
                <td><div className="font-medium">{f.name}</div><div className="text-xs text-muted"><span className={`pill ${VENDOR[f.vendor]?.[1] || ""} mr-1`}>{VENDOR[f.vendor]?.[0] || f.vendor}</span>{f.serial || "serial unknown"} {f.is_demo && <span className="pill bg-amber-600/30 text-amber-200">DEMO</span>}</div></td>
                <td className="font-mono text-xs">{f.host}:{f.https_port}</td>
                <td className="text-xs">{f.fortios_version_detected || <span className="text-muted">{f.fortios_version_declared || "?"} (declared)</span>}<div className="text-muted">{f.version_support}</div></td>
                <td className="text-xs">{f.site}</td>
                <td><span className={`pill ${API_TONE[f.api_status] || API_TONE.unknown}`}>{f.api_status}</span></td>
                <td className="text-xs">{fmtAgo(f.api_last_success)}</td>
                <td className="text-xs">{ing ? <><span className={ingestTone(ing.lag_seconds)}>●</span> {ing.source} · {fmtAgo(ing.last_ingest_time)}</> : <span className="text-red-400">no logs received</span>}</td>
                <td className={`text-xs ${ingestTone(ing?.lag_seconds)}`}>{ing?.lag_seconds != null ? fmtDuration(ing.lag_seconds) : "—"}</td>
                <td className="text-xs">{res.cpu != null ? `${res.cpu}%` : "—"}</td><td className="text-xs">{res.mem != null ? `${res.mem}%` : "—"}</td>
                <td className="text-xs">{res.sessions ?? "—"}</td>
                <td>{me.role === "admin" && !f.is_demo && <button className="btn" onClick={(e) => { e.stopPropagation(); setEdit(f); }}>Edit</button>}</td>
              </tr>);
          })}</tbody></table></div>}
      </Card>
      {edit && <FirewallForm fw={edit} onClose={() => setEdit(null)} />}
      {detail && <FirewallDetail fw={detail} onClose={() => setDetail(null)} />}
    </div>
  );
}

function TestReport({ r }: { r: any }) {
  return (
    <div className="space-y-2 text-sm">
      <div>Result: {r.ok ? <span className="text-emerald-400 font-medium">connected</span> : <span className="text-red-400 font-medium">failed</span>} · auth: {r.auth}</div>
      {r.error && <div className="text-red-400 text-xs">{r.error}</div>}
      {r.identity && <div className="text-xs grid grid-cols-2 gap-1">
        <div>Hostname: {r.identity.hostname}</div><div>Serial: {r.identity.serial}</div>
        <div>OS: {r.identity.version}{r.identity.build ? ` build ${r.identity.build}` : ""}</div><div>Model: {r.identity.model} {r.identity.model_number}</div>
        <div>Version support: {r.version_support}</div></div>}
      {r.endpoints && Object.keys(r.endpoints).length > 0 && <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Endpoint</th><th>Result</th></tr></thead>
        <tbody>{Object.entries(r.endpoints).map(([k, v]) => <tr key={k}><td className="font-mono text-xs">{k}</td>
          <td className={`text-xs ${v === "supported" ? "text-emerald-400" : v === "forbidden" ? "text-amber-300" : "text-slate-400"}`}>{String(v)}</td></tr>)}</tbody></table></div>}
      {(r.warnings || []).map((w: string, i: number) => <div key={i} className="text-xs text-amber-300">⚠ {w}</div>)}
    </div>
  );
}

function FirewallForm({ fw, onClose }: { fw: any; onClose: () => void }) {
  const qc = useQueryClient();
  const [isNew] = useState(!fw.id);
  const [f, setF] = useState<any>({
    name: fw.name || "", vendor: fw.vendor || "fortinet", log_tz: fw.log_tz || "UTC", host: fw.host || "", https_port: fw.https_port || 443,
    fortios_version: fw.fortios_version_declared || "", api_token: "", vdom: fw.vdom || (fw.vendor === "paloalto" ? "vsys1" : "root"), site: fw.site || "", tags: (fw.tags || []).join(", "),
    poll_interval_seconds: fw.poll_interval_seconds || 60, ca_bundle_path: fw.ca_bundle_path || "",
    syslog_source_ips: (fw.syslog_source_ips || []).join(", "), api_log_pull: !!fw.api_log_pull, api_log_device: fw.api_log_device || "disk",
    enabled: fw.enabled ?? true,
  });
  const [report, setReport] = useState<any>(null);
  const [err, setErr] = useState("");
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value });
  const body = () => {
    const b: any = { ...f, https_port: Number(f.https_port), poll_interval_seconds: Number(f.poll_interval_seconds),
      tags: f.tags.split(",").map((s: string) => s.trim()).filter(Boolean),
      syslog_source_ips: f.syslog_source_ips.split(",").map((s: string) => s.trim()).filter(Boolean),
      fortios_version: f.fortios_version || null, ca_bundle_path: f.ca_bundle_path || null };
    if (!b.api_token) delete b.api_token;
    return b;
  };
  const save = useMutation({
    mutationFn: () => !fw.id ? api("/firewalls", { method: "POST", body: body() }) : api(`/firewalls/${fw.id}`, { method: "PUT", body: body() }),
    onSuccess: (r: any) => { qc.invalidateQueries({ queryKey: ["firewalls"] }); qc.invalidateQueries({ queryKey: ["firewalls-lite"] }); if (!fw.id) fw.id = r.id; setErr(""); },
    onError: (e) => setErr((e as Error).message),
  });
  const test = useMutation({
    mutationFn: async () => { if (isNew && !fw.id) await save.mutateAsync(); return api(`/firewalls/${fw.id}/test`, { method: "POST", body: f.api_token ? { api_token: f.api_token } : {} }); },
    onSuccess: (r) => { setReport(r); qc.invalidateQueries({ queryKey: ["firewalls"] }); },
    onError: (e) => setErr((e as Error).message),
  });
  const del = useMutation({ mutationFn: () => api(`/firewalls/${fw.id}`, { method: "DELETE" }), onSuccess: () => { qc.invalidateQueries({ queryKey: ["firewalls"] }); onClose(); } });
  const pan = f.vendor === "paloalto";
  const inp = (k: string, l: string, p: any = {}) => <div><label className="label">{l}</label><input className="input w-full" value={f[k]} onChange={set(k)} {...p} /></div>;
  return (
    <Modal title={isNew && !fw.id ? `Register ${pan ? "Palo Alto firewall" : "FortiGate"}` : `Edit ${f.name}`} onClose={onClose} wide>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="space-y-2">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {inp("name", "Firewall name")}{inp("site", "Site / warehouse / branch")}
            {inp("host", "Management IP or hostname")}{inp("https_port", "HTTPS port", { type: "number" })}
            {pan ? <div><label className="label">Log time zone (PAN-OS logs local time)</label>
                <input className="input w-full" list="tz-list" value={f.log_tz} onChange={set("log_tz")} /><datalist id="tz-list">{ZONES.map((z) => <option key={z} value={z} />)}</datalist></div>
              : inp("fortios_version", "FortiOS version (declared)", { placeholder: "7.4.4" })}
            {inp("vdom", pan ? "Virtual system (vsys)" : "VDOM")}
            <div><label className="label">API access method</label><select className="input w-full" value="token" disabled><option value="token">{pan ? "XML API key (X-PAN-KEY header)" : "REST API token (Bearer header)"}</option></select></div>
            {inp("api_token", isNew ? (pan ? "API key" : "API token") : `${pan ? "API key" : "API token"} (leave blank to keep; required when host or port changes)`, { type: "password", autoComplete: "new-password" })}
            {inp("poll_interval_seconds", "Polling interval (s)", { type: "number", min: 15 })}{inp("tags", "Tags (comma-separated)")}
            {inp("ca_bundle_path", "CA bundle path (server-side, optional)", { placeholder: "/certs/fortigate-ca.pem" })}
            {inp("syslog_source_ips", "Syslog source IPs (comma-separated)")}
          </div>
          <div className="flex flex-wrap gap-4 text-sm">
            <label className="flex items-center gap-1"><input type="checkbox" checked={f.enabled} onChange={set("enabled")} /> Enabled</label>
            {!pan && <><label className="flex items-center gap-1"><input type="checkbox" checked={f.api_log_pull} onChange={set("api_log_pull")} /> Best-effort API log pull</label>
            <select className="input py-0.5" value={f.api_log_device} onChange={set("api_log_device")}><option value="disk">disk</option><option value="memory">memory</option><option value="fortianalyzer">fortianalyzer</option></select></>}
          </div>
          {pan ? <div className="text-xs text-muted space-y-1">
            <p>TLS is always verified. Create an admin role with <b>XML API → Operational Requests</b> and <b>Configuration</b> (read) only, generate its API key, and enter it here. The SIEM only sends <code>show</code> commands and <code>config get</code>; it never commits or changes anything.</p>
            <p>Logs: <b>Device → Server Profiles → Syslog</b> → this SIEM, port 514, UDP or TCP, format BSD or IETF, default (CSV) log format. Attach the profile to the Log Forwarding profile on security rules (traffic, threat, URL) and under Device → Log Settings (System, Config, GlobalProtect). Policy analytics, drift and hardening are FortiGate-only.</p></div>
            : <p className="text-xs text-muted">TLS certificates are always verified. Use a read-only API administrator restricted by trusted hosts. Syslog is the recommended source for traffic, DNS and URL logs.</p>}
          {err && <div className="text-red-400 text-sm">{err}</div>}
          <div className="flex flex-wrap gap-2">
            <button className="btn btn-primary" onClick={() => save.mutate()} disabled={save.isPending}>Save</button>
            <button className="btn" onClick={() => test.mutate()} disabled={test.isPending}>{test.isPending ? "Testing…" : "Test connection"}</button>
            {!isNew && <button className="btn btn-danger ml-auto" onClick={() => confirm(`Remove ${fw.name}? Stored events are retained.`) && del.mutate()}>Remove</button>}
          </div>
          {save.isSuccess && <div className="text-emerald-400 text-xs">Saved.</div>}
        </div>
        <div>{report ? <TestReport r={report} /> : <div className="text-sm text-muted">Run "Test connection" to verify authentication, identity, {pan ? "PAN-OS" : "FortiOS"} version, endpoint availability and permissions.</div>}</div>
      </div>
    </Modal>
  );
}

function FirewallDetail({ fw, onClose }: { fw: any; onClose: () => void }) {
  const m = useQuery({ queryKey: ["fw-metrics", fw.id], queryFn: () => api<any[]>(`/firewalls/${fw.id}/metrics`, { params: { hours: 24 } }), enabled: !fw.is_demo });
  const h = fw.health || {};
  const ifs = Array.isArray(h.interfaces) ? h.interfaces : null;
  return (
    <Drawer title={fw.name} onClose={onClose}>
      <div className="space-y-4 text-sm">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs [&>*]:min-w-0 [&>*]:break-words">
          <div>Host: <span className="font-mono">{fw.host}:{fw.https_port}</span></div><div>Serial: {fw.serial || "—"}</div>
          <div>Model: {fw.model || "—"}</div><div>{VENDOR[fw.vendor]?.[0] || "OS"}: {fw.fortios_version_detected || "—"} ({fw.version_support || "untested"})</div>
          {fw.health?.ha && !fw.health.ha.unsupported && <div>HA: {fw.health.ha.enabled ? `${fw.health.ha.local_state} (peer ${fw.health.ha.peer_state || "—"})` : "disabled"}</div>}
          {fw.vendor === "paloalto" && <div>Log time zone: {fw.log_tz}</div>}
          <div>API status: {fw.api_status}</div><div>Last successful poll: {fmtTime(fw.api_last_success)}</div>
          <div className="col-span-2">Last API error: {fw.api_last_error ? <span className="text-red-400">{fw.api_last_error} ({fmtTime(fw.api_last_error_at)})</span> : "none"}</div>
        </div>
        <Card title="Log ingestion (independent of API status)">
          {fw.ingest?.length ? <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Source</th><th>Last event time</th><th>Last ingested</th><th className="num">Lag</th><th className="num">Total</th><th className="num">Parse errors</th></tr></thead>
            <tbody>{fw.ingest.map((s: any) => <tr key={s.source}><td>{s.source}</td><td className="text-xs">{fmtTime(s.last_event_time)}</td><td className="text-xs">{fmtTime(s.last_ingest_time)}</td>
              <td className={ingestTone(s.lag_seconds)}>{s.lag_seconds != null ? fmtDuration(s.lag_seconds) : "—"}</td><td className="num">{Number(s.events_total).toLocaleString()}</td><td className="num">{s.parse_errors}</td></tr>)}</tbody></table></div>
            : <div className="text-red-400 text-xs">No logs received from this firewall. Configure syslog forwarding to the SIEM (see README) and add the sending IP under "Syslog source IPs" if devid matching is not possible.</div>}
        </Card>
        {!fw.is_demo && <Card title="CPU / memory (24 h, from REST API)">
          {m.data?.length ? <Chart height={200} option={{ legend: { top: 0 }, xAxis: { type: "category", data: m.data.map((r) => fmtTime(r.ts, false)), ...axisStyle },
            yAxis: { type: "value", max: 100, ...axisStyle }, series: [{ name: "CPU %", type: "line", showSymbol: false, data: m.data.map((r) => r.cpu) }, { name: "Mem %", type: "line", showSymbol: false, data: m.data.map((r) => r.mem) }] }} />
            : <Empty text={h.resources?.unsupported ? `Resource endpoint ${h.resources.unsupported}` : "No metrics yet."} />}
        </Card>}
        <Card title="Interfaces">
          {ifs?.length ? <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Name</th><th>Link</th><th>Speed</th><th>IP</th><th>TX</th><th>RX</th><th>Errors</th></tr></thead>
            <tbody>{ifs.map((i: any) => <tr key={i.name}><td>{i.name}{i.alias ? ` (${i.alias})` : ""}</td><td className={linkUp(i.link) ? "text-emerald-400" : "text-red-400"}>{linkUp(i.link) ? "up" : "down"}</td>
              <td>{i.speed ?? "—"}</td><td className="font-mono text-xs">{i.ip || "—"}</td><td className="num">{fmtBytes(i.tx_bytes)}</td><td className="num">{fmtBytes(i.rx_bytes)}</td><td>{(i.tx_errors || 0) + (i.rx_errors || 0)}</td></tr>)}</tbody></table></div>
            : <Empty text={h.interfaces?.unsupported ? `Interface endpoint ${h.interfaces.unsupported}` : fw.is_demo ? "Demo device: no API polling." : "Not polled yet."} />}
        </Card>
        {fw.capabilities?.endpoints && <Card title={`Endpoint capabilities (tested ${fmtTime(fw.capabilities.tested_at)})`}><TestReport r={{ ok: true, auth: "ok", endpoints: fw.capabilities.endpoints }} /></Card>}
      </div>
    </Drawer>
  );
}
