import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useMe } from "../lib/context";
import { fmtBytes, fmtNum, fmtTime } from "../lib/format";
import { Card, Empty, Tabs } from "../components/ui";
import { Mitre } from "./Incidents";

export function Settings({ onMeChange }: { onMeChange: () => void }) {
  const me = useMe();
  const [tab, setTab] = useState("prefs");
  const tabs = [{ key: "prefs", label: "Preferences" }, { key: "rules", label: "Detection rules" }, { key: "retention", label: "Retention" },
    { key: "storage", label: "Storage" }, ...(me.role === "admin" ? [{ key: "users", label: "Users" }, { key: "audit", label: "Audit log" }] : [])];
  return (
    <div>
      <Tabs tabs={tabs} value={tab} onChange={setTab} />
      {tab === "prefs" && <Prefs onMeChange={onMeChange} />}
      {tab === "rules" && <Rules />}
      {tab === "retention" && <Retention />}
      {tab === "storage" && <Storage />}
      {tab === "users" && <Users />}
      {tab === "audit" && <Audit />}
    </div>
  );
}

function Prefs({ onMeChange }: { onMeChange: () => void }) {
  const me = useMe();
  const [tz, setTz] = useState(me.timezone);
  const [cur, setCur] = useState("");
  const [nw, setNw] = useState("");
  const [msg, setMsg] = useState("");
  const zones: string[] = (Intl as any).supportedValuesOf ? (Intl as any).supportedValuesOf("timeZone") : ["UTC"];
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <Card title="Display timezone"><div className="flex gap-2"><select className="input" value={tz} onChange={(e) => setTz(e.target.value)}>{["UTC", ...zones].map((z) => <option key={z}>{z}</option>)}</select>
        <button className="btn btn-primary" onClick={async () => { await api("/auth/me/preferences", { method: "PUT", body: { timezone: tz } }); onMeChange(); setMsg("Timezone saved."); }}>Save</button></div>
        <p className="text-xs text-muted mt-2">All timestamps are stored in UTC and displayed in this timezone.</p></Card>
      <Card title="Change password"><div className="space-y-2">
        <input className="input w-full" type="password" placeholder="Current password" value={cur} onChange={(e) => setCur(e.target.value)} />
        <input className="input w-full" type="password" placeholder="New password (min 12 chars)" value={nw} onChange={(e) => setNw(e.target.value)} />
        <button className="btn btn-primary" onClick={() => api("/auth/me/password", { method: "PUT", body: { current_password: cur, new_password: nw } }).then(() => setMsg("Password changed.")).catch((e) => setMsg(e.message))}>Change</button></div></Card>
      {msg && <div className="text-sm text-sky-300">{msg}</div>}
    </div>
  );
}

function Rules() {
  const me = useMe();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["rules"], queryFn: () => api<any[]>("/alert-rules") });
  const stats = useQuery({ queryKey: ["rule-stats"], queryFn: () => api<any[]>("/alert-rules/stats", { params: { days: 90 } }) });
  const byKey = Object.fromEntries((stats.data || []).map((x) => [x.rule_key, x]));
  return (
    <div className="space-y-3">
      <p className="text-xs text-muted">False-positive rate = alerts in incidents closed as <i>false positive</i> ÷ alerts with a verdict (last 90 days). Use it to tune thresholds.</p>
      {(q.data || []).map((r) => <RuleCard key={r.key} r={r} stat={byKey[r.key]} admin={me.role === "admin"} onSaved={() => qc.invalidateQueries({ queryKey: ["rules"] })} />)}
    </div>
  );
}

function RuleCard({ r, stat, admin, onSaved }: { r: any; stat?: any; admin: boolean; onSaved: () => void }) {
  const [params, setParams] = useState(JSON.stringify(r.params, null, 1));
  const [sev, setSev] = useState(r.severity);
  const [enabled, setEnabled] = useState(r.enabled);
  const [err, setErr] = useState("");
  const save = useMutation({
    mutationFn: () => api(`/alert-rules/${r.key}`, { method: "PUT", body: { enabled, severity: sev, params: JSON.parse(params) } }),
    onSuccess: () => { setErr("saved"); onSaved(); }, onError: (e) => setErr((e as Error).message),
  });
  return (
    <Card title={<span>{r.name} <span className="text-xs text-muted font-mono ml-2">{r.key}</span></span>} right={
      <div className="flex gap-2 items-center text-xs">
        <label className="flex items-center gap-1"><input type="checkbox" disabled={!admin} checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />enabled</label>
        <select className="input py-0.5" disabled={!admin} value={sev} onChange={(e) => setSev(e.target.value)}>{["critical", "high", "medium", "low", "informational"].map((s) => <option key={s}>{s}</option>)}</select>
        {admin && <button className="btn" onClick={() => { try { JSON.parse(params); save.mutate(); } catch { setErr("invalid JSON"); } }}>Save</button>}
      </div>}>
      <p className="text-xs text-muted mb-1">{r.description}</p>
      <div className="flex flex-wrap items-center gap-3 mb-2 text-xs"><Mitre m={r.mitre} />
        {stat ? <span className="text-muted">{stat.alerts} alerts (90 d) · FP rate {stat.false_positive_rate == null ? "n/a" : <b className={stat.false_positive_rate > 0.5 ? "text-red-400" : stat.false_positive_rate > 0.2 ? "text-amber-300" : "text-emerald-400"}>{Math.round(stat.false_positive_rate * 100)}%</b>}
          {" "}({stat.true_positive} TP · {stat.false_positive} FP · {stat.benign} benign · {stat.undetermined} open)</span> : <span className="text-muted">no alerts in 90 days</span>}</div>
      <textarea className="input w-full font-mono text-xs h-24" readOnly={!admin} value={params} onChange={(e) => setParams(e.target.value)} />
      {err && <div className={`text-xs ${err === "saved" ? "text-emerald-400" : "text-red-400"}`}>{err}</div>}
    </Card>
  );
}

function Retention() {
  const me = useMe();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["retention"], queryFn: () => api<any>("/admin/retention") });
  const save = useMutation({ mutationFn: (p: any) => api(`/admin/retention/${p.category}`, { method: "PUT", body: { days: Number(p.days), enabled: p.enabled } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["retention"] }) });
  return (
    <div className="space-y-4">
      <Card title="Retention policies (per event category)">
        <p className="text-xs text-muted mb-2">Expired data is removed by dropping whole daily partitions; every run is logged below. Defaults: traffic 30 d, DNS 30 d, web 90 d, security 365 d, system 365 d.</p>
        <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Category</th><th className="num">Days</th><th>Enabled</th><th></th></tr></thead>
          <tbody>{(q.data?.policies || []).map((p: any) => <RetRow key={p.category} p={p} admin={me.role === "admin"} onSave={(x: any) => save.mutate(x)} />)}</tbody></table></div>
      </Card>
      <Card title="Retention runs">{q.data?.runs?.length ? <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Started</th><th>Category</th><th>Cutoff</th><th>Partitions dropped</th><th className="num">Rows</th><th>Status</th></tr></thead>
        <tbody>{q.data.runs.map((r: any, i: number) => <tr key={i}><td className="text-xs">{fmtTime(r.started_at)}</td><td>{r.category}</td><td className="text-xs">{fmtTime(r.cutoff)}</td>
          <td className="text-xs">{r.partitions_dropped.join(", ")}</td><td className="num">{fmtNum(r.rows_dropped)}</td><td className={r.status === "ok" ? "text-emerald-400" : "text-red-400"}>{r.status} {r.error}</td></tr>)}</tbody></table></div> : <Empty text="No data has been removed by retention yet." />}</Card>
    </div>
  );
}

function RetRow({ p, admin, onSave }: any) {
  const [days, setDays] = useState(p.days);
  const [en, setEn] = useState(p.enabled);
  return <tr><td>{p.category}</td><td><input className="input w-24" type="number" min={1} disabled={!admin} value={days} onChange={(e) => setDays(e.target.value)} /></td>
    <td><input type="checkbox" disabled={!admin} checked={en} onChange={(e) => setEn(e.target.checked)} /></td>
    <td>{admin && <button className="btn" onClick={() => onSave({ category: p.category, days, enabled: en })}>Save</button>}</td></tr>;
}

function Storage() {
  const q = useQuery({ queryKey: ["storage"], queryFn: () => api<any>("/admin/storage"), refetchInterval: 60_000 });
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <Card title="Events by category">{q.data?.categories?.length ? <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Category</th><th className="num">Rows</th><th className="num">On disk</th><th className="num">Days</th><th>Oldest</th><th>Newest</th></tr></thead>
        <tbody>{q.data.categories.map((c: any) => <tr key={c.category}><td>{c.category}</td><td className="num">{fmtNum(c.rows)}</td><td className="num">{fmtBytes(c.bytes)}</td><td>{c.partitions}</td><td>{c.oldest_day}</td><td>{c.newest_day}</td></tr>)}</tbody></table></div> : <Empty text="No events stored." />}</Card>
      <Card title="ClickHouse tables">{q.data?.tables?.length ? <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Table</th><th className="num">Rows</th><th className="num">On disk</th></tr></thead>
        <tbody>{q.data.tables.map((t: any) => <tr key={t.table}><td className="font-mono text-xs">{t.table}</td><td className="num">{fmtNum(t.rows)}</td><td className="num">{fmtBytes(t.bytes)}</td></tr>)}</tbody></table></div> : <Empty />}</Card>
    </div>
  );
}

function Users() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["users"], queryFn: () => api<any[]>("/users") });
  const [n, setN] = useState({ username: "", password: "", role: "analyst" });
  const [err, setErr] = useState("");
  const create = useMutation({ mutationFn: () => api("/users", { method: "POST", body: n }), onSuccess: () => { setN({ username: "", password: "", role: "analyst" }); setErr(""); qc.invalidateQueries({ queryKey: ["users"] }); }, onError: (e) => setErr((e as Error).message) });
  const patch = useMutation({ mutationFn: ({ id, body }: any) => api(`/users/${id}`, { method: "PATCH", body }), onSuccess: () => qc.invalidateQueries({ queryKey: ["users"] }), onError: (e) => setErr((e as Error).message) });
  return (
    <div className="space-y-4">
      <Card title="Users"><div className="tbl-wrap"><table className="tbl"><thead><tr><th>User</th><th>Role</th><th>Active</th><th>Last login</th><th></th></tr></thead>
        <tbody>{(q.data || []).map((u) => <tr key={u.id}><td>{u.username}</td><td>{u.role}</td><td>{u.is_active ? "yes" : "no"}</td><td className="text-xs">{fmtTime(u.last_login)}</td>
          <td className="flex gap-1"><button className="btn" onClick={() => patch.mutate({ id: u.id, body: { role: u.role === "admin" ? "analyst" : "admin" } })}>Make {u.role === "admin" ? "analyst" : "admin"}</button>
            <button className="btn" onClick={() => patch.mutate({ id: u.id, body: { is_active: !u.is_active } })}>{u.is_active ? "Disable" : "Enable"}</button></td></tr>)}</tbody></table></div></Card>
      <Card title="Create user"><div className="flex gap-2 flex-wrap">
        <input className="input" placeholder="username" value={n.username} onChange={(e) => setN({ ...n, username: e.target.value })} />
        <input className="input" type="password" placeholder="password (min 12)" value={n.password} onChange={(e) => setN({ ...n, password: e.target.value })} />
        <select className="input" value={n.role} onChange={(e) => setN({ ...n, role: e.target.value })}><option value="analyst">analyst (read-only)</option><option value="admin">admin</option></select>
        <button className="btn btn-primary" onClick={() => create.mutate()}>Create</button></div>{err && <div className="text-red-400 text-xs mt-1">{err}</div>}</Card>
    </div>
  );
}

function Audit() {
  const q = useQuery({ queryKey: ["audit"], queryFn: () => api<any[]>("/admin/audit", { params: { size: 200 } }) });
  return <Card title="Audit log">{q.data?.length ? <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Time</th><th>User</th><th>Action</th><th>Target</th><th>Client IP</th><th>OK</th><th>Detail</th></tr></thead>
    <tbody>{q.data.map((r, i) => <tr key={i}><td className="text-xs">{fmtTime(r.ts)}</td><td>{r.username}</td><td>{r.action}</td><td>{r.target}</td><td className="font-mono text-xs">{r.client_ip}</td>
      <td className={r.success ? "text-emerald-400" : "text-red-400"}>{r.success ? "✓" : "✗"}</td><td className="text-xs font-mono max-w-md truncate">{JSON.stringify(r.detail)}</td></tr>)}</tbody></table></div> : <Empty />}</Card>;
}
