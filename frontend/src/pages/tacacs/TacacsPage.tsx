import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { fmtNum } from "../../lib/format";
import { Card, Empty, Kpi, Loading, Sev, TableWrap, Tabs, Time, Trunc } from "../../components/ui";
import { RangeSelect, Status, useTacMeta } from "./common";
import { Clients, Servers } from "./Inventory";
import { Identity } from "./Identity";
import { AuthPolicies, Authorization } from "./Policies";
import { Accounting, Sessions } from "./Accounting";
import { Studio } from "./Studio";
import { Testing } from "./Testing";
import { AlertsTab, Audit, Health, SettingsTab } from "./Admin";

export const TABS: [string, string][] = [["overview", "Overview"], ["servers", "Servers"], ["clients", "Device clients"], ["identity", "Users & identity sources"],
  ["authn", "Authentication policies"], ["authz", "Authorization & commands"], ["accounting", "Accounting explorer"], ["sessions", "Session audit"],
  ["studio", "Configuration studio"], ["testing", "Testing center"], ["health", "Health & failover"], ["alerts", "Security alerts"], ["audit", "Audit & changes"],
  ["settings", "Settings"]];

export function Tacacs() {
  const [sp, setSp] = useSearchParams();
  const tab = sp.get("tab") || "overview";
  const meta = useTacMeta();
  return <div className="space-y-4 min-w-0">
    <p className="text-xs text-muted">Centralised AAA for network-device administrators (tac_plus-ng): devices authenticate administrators against the TACACS+ server,
      receive role-based authorization, and send accounting the SIEM ingests. This does not change how you sign in to the SIEM, and the SIEM never pushes
      configuration to network devices.{meta.data && <> Your TACACS+ roles: <b>{meta.data.my_roles.join(", ") || "none (read-only overview)"}</b>.</>}</p>
    <Tabs value={tab} onChange={(t) => setSp({ tab: t })} tabs={TABS.map(([key, label]) => ({ key, label }))} />
    {!meta.data ? <Loading q={meta} /> : <>
    {tab === "overview" && <Overview go={(t) => setSp({ tab: t })} />}
    {tab === "servers" && <Servers />}
    {tab === "clients" && <Clients />}
    {tab === "identity" && <Identity />}
    {tab === "authn" && <AuthPolicies />}
    {tab === "authz" && <Authorization />}
    {tab === "accounting" && <Accounting />}
    {tab === "sessions" && <Sessions />}
    {tab === "studio" && <Studio />}
    {tab === "testing" && <Testing />}
    {tab === "health" && <Health />}
    {tab === "alerts" && <AlertsTab />}
    {tab === "audit" && <Audit />}
    {tab === "settings" && <SettingsTab />}
    </>}
  </div>;
}

function Overview({ go }: { go: (tab: string) => void }) {
  const [range, setRange] = useState("24h");
  const [user, setUser] = useState("");
  const [device, setDevice] = useState("");
  const [site, setSite] = useState("");
  const [result, setResult] = useState("");
  const [eventType, setEventType] = useState("");
  const [severity, setSeverity] = useState("");
  const meta = useTacMeta();
  const q = useQuery({ queryKey: ["tac-overview", range, user, device, site, result, eventType, severity], refetchInterval: 30_000, placeholderData: (p) => p,
    queryFn: () => api<any>("/tacacs/overview", { params: { range, user: user || undefined, device: device || undefined, site: site || undefined,
      result: result || undefined, event_type: eventType || undefined, severity: severity || undefined } }) });
  const d = q.data;
  const t = d?.totals || {};
  return <div className="space-y-4">
    <div className="flex flex-wrap gap-2 items-center">
      <RangeSelect value={range} onChange={setRange} />
      <input aria-label="User" className="input py-1 w-32" placeholder="User" value={user} onChange={(e) => setUser(e.target.value)} />
      <input aria-label="Device IP" className="input py-1 w-36" placeholder="Device IP" value={device} onChange={(e) => setDevice(e.target.value)} />
      <input aria-label="Site" className="input py-1 w-28" placeholder="Site" value={site} onChange={(e) => setSite(e.target.value)} />
      <select aria-label="Event type" className="input py-1" value={eventType} onChange={(e) => setEventType(e.target.value)}><option value="">All event types</option>
        {(meta.data?.event_types || []).map((x: string) => <option key={x}>{x}</option>)}</select>
      <select aria-label="Result" className="input py-1" value={result} onChange={(e) => setResult(e.target.value)}><option value="">Any result</option>
        {["success", "failure", "backend_unavailable", "policy_deny", "permit", "deny", "recorded"].map((x) => <option key={x}>{x}</option>)}</select>
      <select aria-label="Severity" className="input py-1" value={severity} onChange={(e) => setSeverity(e.target.value)}><option value="">Any severity</option>
        {["informational", "low", "medium", "high"].map((x) => <option key={x}>{x}</option>)}</select>
    </div>
    <Loading q={q} />
    {d && <>
      {!d.servers.length && <Card><Empty text={<>No TACACS+ server registered yet. Start the tacacs service (COMPOSE_PROFILES=tacacs), then add it under <b>Servers</b>.
        See docs/TACACS.md for the installation steps.</>} /></Card>}
      <div className="kpi-grid">
        {d.servers.map((x: any) => <Kpi key={x.id} label={`${x.name} (${x.role})`} value={<Status s={x.status} />} sub={<>ok <Time v={x.last_ok_at} /></>}
          tone={x.status === "up" ? "ok" : x.status === "down" ? "bad" : "warn"} onClick={() => go("health")} />)}
        <Kpi label="Authentication successes" value={fmtNum(t.auth_success)} tone="ok" onClick={() => go("accounting")} />
        <Kpi label="Authentication failures" value={fmtNum(t.auth_failure)} sub="wrong credentials" tone={t.auth_failure ? "warn" : "ok"} onClick={() => go("accounting")} />
        <Kpi label="Backend unavailable" value={fmtNum(t.auth_backend_error)} sub="not counted as wrong passwords" tone={t.auth_backend_error ? "bad" : "ok"} />
        <Kpi label="Policy denials at login" value={fmtNum(t.auth_policy_deny)} tone={t.auth_policy_deny ? "warn" : "ok"} />
        <Kpi label="Authorization permits / denials" value={`${fmtNum(t.authz_permit)} / ${fmtNum(t.authz_deny)}`} tone={t.authz_deny ? "warn" : "ok"} />
        <Kpi label="Accounting records" value={fmtNum(t.accounting)} onClick={() => go("sessions")} />
        <Kpi label="Active sessions" value={t.active_sessions == null ? "unavailable" : fmtNum(t.active_sessions)} sub={t.active_sessions_note || "open exec accounting"} />
        <Kpi label="Unique administrators" value={fmtNum(t.unique_admins)} />
        <Kpi label="Devices using TACACS+" value={`${fmtNum(t.devices_seen)} / ${fmtNum(t.clients_enabled)}`} sub="seen in events / registered" onClick={() => go("clients")} />
        <Kpi label="Unknown devices" value={fmtNum(t.unknown_devices + t.conn_reject)} tone={t.unknown_devices + t.conn_reject ? "bad" : "ok"} />
        <Kpi label="Clients failing AAA tests" value={fmtNum(t.clients_failed_tests)} tone={t.clients_failed_tests ? "bad" : "ok"} onClick={() => go("testing")} />
        <Kpi label="Clients not yet deployed" value={fmtNum(t.clients_out_of_sync)} tone={t.clients_out_of_sync ? "warn" : "ok"} onClick={() => go("studio")} />
        <Kpi label="Pending operations" value={fmtNum(t.pending_operations)} tone={t.pending_operations ? "warn" : "ok"} onClick={() => go("studio")} />
        <Kpi label="Open security alerts" value={fmtNum(t.open_alerts)} tone={t.open_alerts ? "bad" : "ok"} onClick={() => go("alerts")} />
        <Kpi label="Ingestion problems" value={fmtNum(t.ingestion_issues)} tone={t.ingestion_issues ? "bad" : "ok"} onClick={() => go("health")} />
      </div>
      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="Recent command authorization denials" bodyClass="p-0">{!d.recent_denials.length ? <Empty text="No denials in this range." /> :
          <TableWrap maxH="max-h-80"><table className="tbl"><thead><tr><th>Time</th><th>User</th><th>Device</th><th>Command</th><th>Category</th></tr></thead>
            <tbody>{d.recent_denials.map((r: any, i: number) => <tr key={i}><td><Time v={r.ts} /></td><td>{r.username}</td><td>{r.device_name || r.device_address}</td>
              <td className="font-mono text-xs"><Trunc text={r.cmd} /></td><td className="text-xs">{r.cmd_category}</td></tr>)}</tbody></table></TableWrap>}</Card>
        <Card title="Suspicious activity (open alerts)" bodyClass="p-0">{!d.alerts.length ? <Empty text="No open TACACS+ alerts." /> :
          <TableWrap maxH="max-h-80"><table className="tbl"><thead><tr><th>Severity</th><th>Alert</th><th>Last seen</th><th className="w-full">Detail</th></tr></thead>
            <tbody>{d.alerts.map((a: any) => <tr key={a.id}><td><Sev s={a.severity} /></td><td><Link className="link" to={`/alerts?id=${a.id}`}>{a.name}</Link></td>
              <td><Time v={a.last_seen} /></td><td className="text-xs">{a.explanation}</td></tr>)}</tbody></table></TableWrap>}</Card>
        <Card title="Configuration changes" bodyClass="p-0">{!d.config_changes.length ? <Empty text="No versions or deployments in this range." /> :
          <TableWrap maxH="max-h-80"><table className="tbl"><thead><tr><th>Time</th><th>Change</th><th>By</th><th>Detail</th></tr></thead>
            <tbody>{d.config_changes.map((c: any) => <tr key={`${c.type}${c.id}`}><td><Time v={c.at} /></td>
              <td>{c.type === "version" ? `version v${c.number}` : <>deployment #{c.id} <Status s={c.status} /></>}</td><td>{c.by}{c.approved_by && ` → ${c.approved_by}`}</td>
              <td className="text-xs">{c.message || ""}</td></tr>)}</tbody></table></TableWrap>}</Card>
        <Card title="Ingestion and accounting sources" bodyClass="p-0">{!d.ingestion_issues.length ? <Empty text="All log files of managed servers are being read without errors." /> :
          <TableWrap><table className="tbl"><thead><tr><th>Server</th><th>Log</th><th className="w-full">Issue</th></tr></thead>
            <tbody>{d.ingestion_issues.map((x: any, i: number) => <tr key={i}><td>{x.server}</td><td>{x.log}</td><td className="text-xs text-red-300">{x.issue}
              {x.last && <div className="text-muted font-mono">{x.last.line}</div>}</td></tr>)}</tbody></table></TableWrap>}</Card>
      </div>
      {!!d.active_sessions.length && <Card title={`Open administrative sessions (${d.active_sessions.length})`} bodyClass="p-0">
        <TableWrap maxH="max-h-72"><table className="tbl"><thead><tr><th>Started</th><th>User</th><th>Device</th><th>Port</th><th>Task</th></tr></thead>
          <tbody>{d.active_sessions.map((x: any, i: number) => <tr key={i}><td><Time v={x.started} /></td><td>{x.username}</td><td>{x.device_name || x.device_address}</td>
            <td>{x.port}</td><td className="font-mono text-xs">{x.task_id}</td></tr>)}</tbody></table></TableWrap></Card>}
    </>}
  </div>;
}
