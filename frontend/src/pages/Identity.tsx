import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useGlobal } from "../lib/context";
import { useTheme } from "../lib/theme";
import { fmtBytes, fmtDuration, fmtNum } from "../lib/format";
import { Chart, PALETTES, axisStyle } from "../components/Chart";
import { Card, Drawer, Empty, IpLink, Kpi, Loading, TableWrap, Tabs, Time, Trunc, rowProps } from "../components/ui";

const RANGES = [["24h", "Last 24 h"], ["7d", "Last 7 days"], ["30d", "Last 30 days"]];
const KIND: Record<string, string> = { vpn: "VPN", admin: "Firewall admin", windows: "Windows", fw_auth: "Firewall auth" };
const RES: Record<string, string> = { success: "text-emerald-300", failure: "text-red-300", logout: "text-slate-400", info: "text-slate-500" };
const REASON: Record<string, string> = { new_country: "New country", new_device: "New device", new_network: "New network", unusual_hour: "Unusual hour",
  off_hours: "Off hours", new_admin_source: "New admin source" };
const dur = (s?: number | null) => (s == null ? "—" : s ? fmtDuration(s) : "0");

function Risk({ v }: { v: number }) {
  const c = v >= 60 ? "bg-red-500/80" : v >= 30 ? "bg-amber-500/80" : v > 0 ? "bg-sky-600/70" : "bg-slate-600/50";
  return <span className={`inline-block min-w-[2.2rem] text-center rounded px-1.5 text-xs font-semibold text-white ${c}`}>{v}</span>;
}

function Chips({ items, max = 3, mono }: { items: string[]; max?: number; mono?: boolean }) {
  if (!items?.length) return <span className="text-muted">—</span>;
  return <span className={`text-xs ${mono ? "font-mono" : ""}`} title={items.join(", ")}>{items.slice(0, max).join(", ")}{items.length > max && <span className="text-muted"> +{items.length - max}</span>}</span>;
}

function HourBars({ hours, base }: { hours: number[]; base?: number[] }) {
  const { theme } = useTheme();
  return <Chart height={170} option={{
    legend: base ? { top: 0 } : undefined, tooltip: { trigger: "axis", confine: true }, grid: { left: 32, right: 8, top: base ? 28 : 10, bottom: 24 },
    xAxis: { type: "category", data: hours.map((_, i) => `${String(i).padStart(2, "0")}`), ...axisStyle },
    yAxis: { type: "value", minInterval: 1, ...axisStyle },
    series: [{ name: "this period", type: "bar", data: hours, itemStyle: { color: PALETTES[theme][0] } },
      ...(base ? [{ name: "30-day baseline", type: "bar", data: base, itemStyle: { color: PALETTES[theme][2], opacity: 0.6 } }] : [])],
  }} />;
}

export function Identity() {
  const g = useGlobal();
  const [range, setRange] = useState("7d");
  const [tab, setTab] = useState("users");
  const [sel, setSel] = useState<string | null>(null);
  const fw = Array.isArray(g.params.firewall_id) ? g.params.firewall_id : [];
  const q = useQuery({ queryKey: ["identity", range, fw], queryFn: () => api<any>("/identity/overview", { params: { range, firewall_id: fw } }), refetchInterval: 120_000, placeholderData: (p) => p });
  const d = q.data;
  const t = d?.totals || {};
  return (
    <div className="space-y-4 min-w-0">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-xs text-muted flex-1 min-w-[16rem]">Who authenticated, from where and on which device: VPN users (FortiClient XAUTH, SSL VPN, GlobalProtect), firewall administrators,
          Windows logons and firewall user authentication. A VPN session's assigned IP ties the person to their traffic. Local times use each firewall's time zone.</p>
        <WhoBox onUser={setSel} />
        <select aria-label="Range" className="input py-1" value={range} onChange={(e) => setRange(e.target.value)}>
          {RANGES.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
      </div>
      <Loading q={q} />
      {d && <>
        <div className="kpi-grid">
          <Kpi label="Users" value={fmtNum(t.users)} sub={`${fmtNum(t.vpn_users)} VPN · ${fmtNum(t.admins)} admin`} />
          <Kpi label="Active VPN sessions" value={fmtNum(t.active_sessions)} onClick={() => setTab("sessions")} />
          <Kpi label="Logins / failures" value={`${fmtNum(t.logins)} / ${fmtNum(t.failures)}`} tone={t.failures > t.logins ? "warn" : undefined} onClick={() => setTab("failures")} />
          <Kpi label="Success after failures" value={fmtNum(t.success_after_failures)} tone={t.success_after_failures ? "bad" : "ok"} onClick={() => setTab("failures")} />
          <Kpi label="Unusual logins" value={fmtNum(t.anomalies)} tone={t.anomalies ? "warn" : "ok"} onClick={() => setTab("anomalies")} />
          <Kpi label="Admin account changes" value={fmtNum(t.account_changes)} sub={`${fmtNum(t.privilege_changes)} privilege-related`} tone={t.privilege_changes ? "bad" : undefined} onClick={() => setTab("accounts")} />
        </div>
        <Tabs value={tab} onChange={setTab} tabs={[{ key: "users", label: "Users" }, { key: "sessions", label: "VPN sessions" }, { key: "map", label: "User ↔ IP ↔ device" },
          { key: "failures", label: "Auth failures" }, { key: "anomalies", label: "Unusual logins" }, { key: "admins", label: "Administrators" }, { key: "accounts", label: "Account & privilege changes" }]} />
        {tab === "users" && <Users d={d} onSel={setSel} />}
        {tab === "sessions" && <Sessions rows={d.sessions} onSel={setSel} />}
        {tab === "map" && <IpMap d={d} onSel={setSel} />}
        {tab === "failures" && <Failures f={d.failures} onSel={setSel} />}
        {tab === "anomalies" && <Anomalies rows={d.anomalies} onSel={setSel} />}
        {tab === "admins" && <Admins a={d.admin} onSel={setSel} />}
        {tab === "accounts" && <Accounts rows={d.admin.account_changes} />}
      </>}
      {sel && <UserDrawer user={sel} range={range} onClose={() => setSel(null)} />}
    </div>
  );
}

function WhoBox({ onUser }: { onUser: (u: string) => void }) {
  const [ip, setIp] = useState("");
  const [go, setGo] = useState("");
  const q = useQuery({ queryKey: ["who", go], queryFn: () => api<any>("/identity/who", { params: { ip: go } }), enabled: !!go });
  return <div className="relative">
    <form onSubmit={(e) => { e.preventDefault(); setGo(ip.trim()); }}>
      <input aria-label="Who had this IP" className="input py-1 w-52 text-sm" placeholder="Who had IP… (VPN / public)" value={ip} onChange={(e) => setIp(e.target.value)} />
    </form>
    {go && q.data && <div className="absolute right-0 z-20 mt-1 w-80 rounded border border-line bg-[var(--surface,#0f172a)] shadow-lg p-2 text-xs">
      <div className="flex mb-1"><b className="flex-1">{go}</b><button className="text-muted" onClick={() => setGo("")}>✕</button></div>
      {q.data.sessions.length ? q.data.sessions.slice(0, 8).map((s: any, i: number) => <button key={i} className="block w-full text-left hover:bg-white/5 rounded px-1 py-0.5" onClick={() => { onUser(s.user); setGo(""); }}>
        <b>{s.user}</b> · <Time v={s.start} />{s.end ? <> – <Time v={s.end} /></> : <span className="text-emerald-300"> active</span>}</button>) : <span className="text-muted">No VPN session used this IP in the last 7 days.</span>}
    </div>}
  </div>;
}

function Users({ d, onSel }: { d: any; onSel: (u: string) => void }) {
  const [f, setF] = useState("");
  const rows = useMemo(() => d.users.filter((u: any) => !f || u.user.toLowerCase().includes(f.toLowerCase()) || u.sources.some((s: string) => s.includes(f)) || u.assigned_ips.some((s: string) => s.includes(f))), [d, f]);
  return <>
    <Card title={`Users (${fmtNum(rows.length)})`} bodyClass="p-0" right={<input aria-label="Filter users" className="input py-0.5 text-xs w-56" placeholder="filter user / IP" value={f} onChange={(e) => setF(e.target.value)} />}>
      {rows.length ? <TableWrap maxH="max-h-[34rem]"><table className="tbl"><thead><tr><th className="num">Risk</th><th>User</th><th>Type</th><th className="num">Logins</th><th className="num">Failures</th>
        <th>Last login</th><th>Last from</th><th>Countries</th><th>Devices</th><th>VPN IPs</th><th>Group / profile</th><th>Status</th></tr></thead>
        <tbody>{rows.map((u: any) => <tr key={u.user} {...rowProps(() => onSel(u.user))}>
          <td className="num"><Risk v={u.risk} /></td><td className="font-semibold text-sm nowrap">{u.user}</td><td className="text-xs nowrap">{u.kinds.map((k: string) => KIND[k] || k).join(", ")}</td>
          <td className="num">{fmtNum(u.logins)}</td><td className={`num ${u.failures ? "text-red-300" : ""}`}>{fmtNum(u.failures)}</td><td><Time v={u.last_login} /></td>
          <td>{u.last_src ? <IpLink ip={u.last_src} /> : "—"}{u.last_country && <div className="text-2xs text-muted">{u.last_country}</div>}</td>
          <td><Chips items={u.countries} /></td><td><Chips items={u.devices.map((x: string) => x.slice(0, 12))} max={2} mono /></td><td><Chips items={u.assigned_ips} max={2} mono /></td>
          <td><Chips items={[...u.groups, ...u.profiles]} max={2} /></td>
          <td className="text-xs nowrap">{u.active ? <span className="text-emerald-300">● connected</span> : ""}{u.anomalies ? <span className="text-amber-300 ml-1">{u.anomalies} unusual</span> : ""}</td>
        </tr>)}</tbody></table></TableWrap> : <Empty text="No authenticated users in this range." />}
    </Card>
    <Card title="Successful logins by local hour"><HourBars hours={d.login_hours} /></Card>
  </>;
}

function Sessions({ rows, onSel }: { rows: any[]; onSel: (u: string) => void }) {
  const [only, setOnly] = useState(false);
  const r = only ? rows.filter((s) => s.active) : rows;
  return <Card title={`VPN sessions (${fmtNum(r.length)})`} bodyClass="p-0" right={<label className="text-xs flex items-center gap-1"><input type="checkbox" checked={only} onChange={(e) => setOnly(e.target.checked)} />active only</label>}>
    {r.length ? <TableWrap maxH="max-h-[36rem]"><table className="tbl"><thead><tr><th>User</th><th>Firewall</th><th>Start</th><th>End</th><th className="num">Duration</th><th>Public IP</th>
      <th>Country</th><th>Assigned IP</th><th>Client IP</th><th>Device</th><th>Group</th><th className="num">In / out</th></tr></thead>
      <tbody>{r.map((s: any, i: number) => <tr key={i} {...rowProps(() => onSel(s.user))}><td className="font-semibold text-sm nowrap">{s.user}</td><td className="text-xs nowrap">{s.firewall_name}</td>
        <td><Time v={s.start} /></td><td>{s.active ? <span className="text-emerald-300 text-xs">active</span> : <Time v={s.end} />}</td><td className="num text-xs">{dur(s.duration_s)}</td>
        <td><IpLink ip={s.src_ip} /></td><td className="text-xs">{s.country || "—"}</td><td className="font-mono text-xs">{s.assigned_ip || "—"}</td><td className="font-mono text-xs">{s.client_ip || "—"}</td>
        <td className="font-mono text-2xs">{s.device ? s.device.slice(0, 14) : "—"}</td><td className="text-xs">{s.group || "—"}</td>
        <td className="num text-xs">{s.rcvd || s.sent ? `${fmtBytes(s.rcvd)} / ${fmtBytes(s.sent)}` : "—"}</td></tr>)}</tbody></table></TableWrap>
      : <Empty text="No VPN sessions in this range." />}
  </Card>;
}

function IpMap({ d, onSel }: { d: any; onSel: (u: string) => void }) {
  const [f, setF] = useState("");
  const rows = d.ip_map.filter((m: any) => !f || m.ip.includes(f) || m.user.toLowerCase().includes(f.toLowerCase()) || (m.device || "").toLowerCase().includes(f.toLowerCase()));
  return <div className="grid gap-4 xl:grid-cols-[3fr_1fr] min-w-0">
    <Card title={`User ↔ IP ↔ device (${fmtNum(rows.length)})`} bodyClass="p-0" right={<input aria-label="Filter map" className="input py-0.5 text-xs w-56" placeholder="filter IP / user / device" value={f} onChange={(e) => setF(e.target.value)} />}>
      {rows.length ? <TableWrap maxH="max-h-[36rem]"><table className="tbl"><thead><tr><th>User</th><th>IP</th><th>IP role</th><th>Device</th><th>Country</th><th>First</th><th>Last</th><th className="num">Events</th></tr></thead>
        <tbody>{rows.slice(0, 1000).map((m: any, i: number) => <tr key={i} {...rowProps(() => onSel(m.user))}><td className="text-sm nowrap">{m.user}</td><td><IpLink ip={m.ip} /></td>
          <td className="text-xs">{m.type}</td><td className="font-mono text-2xs">{m.device ? m.device.slice(0, 16) : "—"}</td><td className="text-xs">{m.country || "—"}</td>
          <td><Time v={m.first} /></td><td><Time v={m.last} /></td><td className="num">{fmtNum(m.events)}</td></tr>)}</tbody></table></TableWrap> : <Empty />}
    </Card>
    <Card title="IPs shared by several users">
      <ul className="text-xs space-y-1.5">{d.shared_ips.map((s: any) => <li key={s.ip}><span className="font-mono">{s.ip}</span> · {s.users.join(", ")}</li>)}
        {!d.shared_ips.length && <li className="text-muted">none</li>}</ul>
      <p className="text-2xs text-muted mt-3">Office NAT and home routers are shared legitimately; one public IP used by many unrelated users can also be a proxy or a credential-stuffing source.</p>
    </Card>
  </div>;
}

function Failures({ f, onSel }: { f: any; onSel: (u: string) => void }) {
  return <>
    {f.success_after_failures.length > 0 && <Card title={`Successful login after failures (${f.success_after_failures.length})`} bodyClass="p-0">
      <TableWrap><table className="tbl"><thead><tr><th>Time</th><th>User</th><th>Type</th><th className="num">Failures before</th><th>Logged in from</th><th className="w-full">Failures came from</th></tr></thead>
        <tbody>{f.success_after_failures.map((s: any, i: number) => <tr key={i} {...rowProps(() => onSel(s.user))}><td><Time v={s.t} /></td><td className="font-semibold">{s.user}</td>
          <td className="text-xs">{KIND[s.kind]}</td><td className="num text-red-300">{s.failures}</td><td><IpLink ip={s.src_ip} /></td>
          <td className="text-xs">{s.same_source ? "same source (likely the user mistyping)" : s.failed_from.join(", ")}</td></tr>)}</tbody></table></TableWrap>
    </Card>}
    <div className="grid gap-4 xl:grid-cols-2 min-w-0">
      <Card title="Failures by user" bodyClass="p-0">{f.by_user.length ? <TableWrap maxH="max-h-[30rem]"><table className="tbl"><thead><tr><th>User</th><th className="num">Failures</th><th className="num">Sources</th>
        <th>Type</th><th>Last</th><th className="w-full">Last reason</th></tr></thead>
        <tbody>{f.by_user.map((u: any) => <tr key={u.user} {...rowProps(() => onSel(u.user))}><td className="text-sm">{u.user}</td><td className="num text-red-300">{fmtNum(u.failures)}</td>
          <td className="num">{u.sources.length}</td><td className="text-xs">{u.kinds.map((k: string) => KIND[k]).join(", ")}</td><td><Time v={u.last} /></td><td className="text-xs"><Trunc text={u.detail} /></td></tr>)}</tbody></table></TableWrap>
        : <Empty text="No authentication failures." />}</Card>
      <Card title="Failures by source (password spraying = many users)" bodyClass="p-0">{f.by_source.length ? <TableWrap maxH="max-h-[30rem]"><table className="tbl"><thead><tr><th>Source</th><th>Country</th>
        <th className="num">Failures</th><th className="num">Users</th><th className="w-full">User names tried</th><th>Last</th></tr></thead>
        <tbody>{f.by_source.map((s: any, i: number) => <tr key={i}><td><IpLink ip={s.src_ip} /></td><td className="text-xs">{s.country || "—"}</td><td className="num text-red-300">{fmtNum(s.failures)}</td>
          <td className={`num ${s.users.length >= 5 ? "text-red-300 font-semibold" : ""}`}>{s.users.length}</td><td><Chips items={s.users} max={4} /></td><td><Time v={s.last} /></td></tr>)}</tbody></table></TableWrap>
        : <Empty text="No authentication failures." />}</Card>
    </div>
  </>;
}

function Anomalies({ rows, onSel }: { rows: any[]; onSel: (u: string) => void }) {
  return <Card title={`Unusual logins (${rows.length})`} bodyClass="p-0">
    {rows.length ? <TableWrap maxH="max-h-[36rem]"><table className="tbl"><thead><tr><th className="num">Score</th><th>Time</th><th>User</th><th>Type</th><th>From</th><th>Country</th><th className="w-full">Why</th></tr></thead>
      <tbody>{rows.map((a: any, i: number) => <tr key={i} {...rowProps(() => onSel(a.user))}><td className="num"><Risk v={a.score} /></td><td><Time v={a.t} /></td><td className="font-semibold text-sm">{a.user}</td>
        <td className="text-xs">{KIND[a.kind]}</td><td><IpLink ip={a.src_ip} /></td><td className="text-xs">{a.country || "—"}</td>
        <td className="text-xs">{a.reasons.map((r: any) => <span key={r.type} className="mr-2"><b>{REASON[r.type] || r.type}</b>: {r.detail}</span>)}</td></tr>)}</tbody></table></TableWrap>
      : <Empty text="No unusual logins. Users need about 5 logins in the previous 30 days before location / device / hour checks apply." />}
  </Card>;
}

function Admins({ a, onSel }: { a: any; onSel: (u: string) => void }) {
  return <>
    <Card title="Administrator activity" bodyClass="p-0">
      {a.admins.length ? <TableWrap><table className="tbl"><thead><tr><th>Administrator</th><th className="num">Config changes</th><th className="num">CLI commands</th><th>Most changed</th>
        <th>Sources</th><th>Methods</th><th>Firewalls</th><th>Last</th></tr></thead>
        <tbody>{a.admins.map((x: any) => <tr key={x.admin} {...rowProps(() => onSel(x.admin))}><td className="font-semibold text-sm">{x.admin}</td><td className="num">{fmtNum(x.changes)}</td>
          <td className="num">{fmtNum(x.commands)}</td><td className="text-xs">{x.paths.slice(0, 3).map((p: any) => `${p.path} (${p.n})`).join(", ") || "—"}</td>
          <td><Chips items={x.sources} max={2} mono /></td><td className="text-xs">{x.methods.join(", ")}</td><td className="text-xs">{x.firewalls.join(", ")}</td><td><Time v={x.last} /></td></tr>)}</tbody></table></TableWrap>
        : <Empty text="No administrator configuration changes or CLI commands in this range." />}
    </Card>
    <Card title={`Configuration changes (${a.changes.length})`} bodyClass="p-0">
      {a.changes.length ? <TableWrap maxH="max-h-[30rem]"><table className="tbl"><thead><tr><th>Time</th><th>Admin</th><th>Firewall</th><th>Action</th><th>Path</th><th>Object</th><th className="w-full">Attributes</th><th>From</th></tr></thead>
        <tbody>{a.changes.map((c: any, i: number) => <tr key={i}><td><Time v={c.t} /></td><td className="text-sm">{c.admin}</td><td className="text-xs nowrap">{c.firewall_name}</td>
          <td className="text-xs">{c.action}</td><td className="font-mono text-xs nowrap">{c.path}</td><td className="font-mono text-xs"><Trunc text={c.object} /></td>
          <td className="text-xs"><Trunc text={c.attr || c.detail} max="max-w-[28rem]" /></td><td className="font-mono text-xs nowrap">{c.method}{c.src_ip ? ` · ${c.src_ip}` : ""}</td></tr>)}</tbody></table></TableWrap> : <Empty />}
    </Card>
    <Card title={`CLI commands (${a.commands.length})`} bodyClass="p-0">
      {a.commands.length ? <TableWrap maxH="max-h-80"><table className="tbl"><thead><tr><th>Time</th><th>Admin</th><th>Firewall</th><th className="w-full">Command</th><th>From</th></tr></thead>
        <tbody>{a.commands.map((c: any, i: number) => <tr key={i}><td><Time v={c.t} /></td><td className="text-sm">{c.admin}</td><td className="text-xs nowrap">{c.firewall_name}</td>
          <td className="font-mono text-xs"><Trunc text={c.command} max="max-w-[36rem]" /></td><td className="font-mono text-xs nowrap">{c.method}{c.src_ip ? ` · ${c.src_ip}` : ""}</td></tr>)}</tbody></table></TableWrap> : <Empty />}
    </Card>
  </>;
}

function Accounts({ rows }: { rows: any[] }) {
  return <Card title={`Administrator / account / privilege changes (${rows.length})`} bodyClass="p-0">
    {rows.length ? <TableWrap maxH="max-h-[40rem]"><table className="tbl"><thead><tr><th>Time</th><th>Changed by</th><th>Firewall</th><th>Action</th><th>Account object</th><th>Path</th>
      <th className="w-full">What changed</th><th>Privilege</th></tr></thead>
      <tbody>{rows.map((c: any, i: number) => <tr key={i}><td><Time v={c.t} /></td><td className="text-sm">{c.admin}<div className="text-2xs text-muted font-mono">{c.method}{c.src_ip ? ` · ${c.src_ip}` : ""}</div></td>
        <td className="text-xs nowrap">{c.firewall_name}</td><td className={`text-xs ${c.action.toLowerCase() === "delete" ? "text-red-300" : c.action.toLowerCase() === "add" ? "text-amber-300" : ""}`}>{c.action}</td>
        <td className="font-mono text-xs font-semibold">{c.object || "—"}</td><td className="font-mono text-xs nowrap">{c.path}</td><td className="text-xs"><Trunc text={c.attr || c.detail} max="max-w-[30rem]" /></td>
        <td>{c.privilege ? <span className="text-red-300 text-xs font-semibold">yes</span> : <span className="text-muted text-xs">no</span>}</td></tr>)}</tbody></table></TableWrap>
      : <Empty text="No changes to administrator accounts, access profiles, local users or user groups in this range." />}
  </Card>;
}

function UserDrawer({ user, range, onClose }: { user: string; range: string; onClose: () => void }) {
  const q = useQuery({ queryKey: ["identity-user", user, range], queryFn: () => api<any>(`/identity/users/${encodeURIComponent(user)}`, { params: { range } }) });
  const d = q.data;
  return <Drawer title={`User ${user}`} onClose={onClose}>
    <Loading q={q} />
    {d && <div className="space-y-4">
      <div className="kpi-grid">
        <Kpi label="Logins" value={fmtNum(d.events.filter((e: any) => e.result === "success").length)} />
        <Kpi label="Failures" value={fmtNum(d.events.filter((e: any) => e.result === "failure").length)} tone={d.events.some((e: any) => e.result === "failure") ? "warn" : undefined} />
        <Kpi label="VPN sessions" value={fmtNum(d.sessions.length)} sub={d.sessions.some((s: any) => s.active) ? "connected now" : undefined} />
        <Kpi label="Traffic in VPN sessions" value={fmtBytes(d.traffic.bytes_rcvd + d.traffic.bytes_sent)} sub={`${fmtNum(d.traffic.events)} sessions logged`} />
      </div>
      {d.anomalies.length > 0 && <Card title={`Unusual logins (${d.anomalies.length})`}><ul className="text-xs space-y-1">{d.anomalies.map((a: any, i: number) =>
        <li key={i}><Time v={a.t} /> · {a.src_ip} {a.country && `(${a.country})`} — {a.reasons.map((r: any) => r.detail).join("; ")}</li>)}</ul></Card>}
      {d.baseline && <Card title="Baseline (previous 30 days)"><div className="text-xs space-y-1">
        <div>{fmtNum(d.baseline.logins)} logins · countries: <b>{d.baseline.countries.join(", ") || "—"}</b></div>
        <div>devices: <span className="font-mono">{d.baseline.devices.map((x: string) => x.slice(0, 12)).join(", ") || "—"}</span></div></div>
        <HourBars hours={d.login_hours} base={d.baseline.hours} /></Card>}
      {d.sessions.length > 0 && <Card title="VPN sessions" bodyClass="p-0"><TableWrap maxH="max-h-72"><table className="tbl"><thead><tr><th>Start</th><th className="num">Duration</th><th>Public IP</th><th>Assigned</th><th>Device</th></tr></thead>
        <tbody>{d.sessions.map((s: any, i: number) => <tr key={i}><td><Time v={s.start} />{s.active && <span className="text-emerald-300 text-2xs ml-1">active</span>}</td><td className="num text-xs">{dur(s.duration_s)}</td>
          <td><IpLink ip={s.src_ip} />{s.country && <span className="text-2xs text-muted ml-1">{s.country}</span>}</td><td className="font-mono text-xs">{s.assigned_ip || "—"}</td>
          <td className="font-mono text-2xs">{s.device ? s.device.slice(0, 14) : "—"}</td></tr>)}</tbody></table></TableWrap></Card>}
      {d.traffic.destinations.length > 0 && <Card title="What the user accessed over VPN (traffic from the assigned IP during sessions)" bodyClass="p-0">
        <TableWrap maxH="max-h-72"><table className="tbl"><thead><tr><th>Destination</th><th>Country</th><th>App</th><th className="num">Sessions</th><th className="num">Bytes</th></tr></thead>
          <tbody>{d.traffic.destinations.map((x: any, i: number) => <tr key={i}><td><IpLink ip={x.dst_ip} /></td><td className="text-xs">{x.country || "—"}</td><td className="text-xs">{x.app || "—"}</td>
            <td className="num">{fmtNum(x.n)}</td><td className="num">{fmtBytes(x.bytes)}</td></tr>)}</tbody></table></TableWrap></Card>}
      {(d.admin.changes.length > 0 || d.admin.account_changes.length > 0) && <Card title="Administrator activity" bodyClass="p-0">
        <TableWrap maxH="max-h-72"><table className="tbl"><thead><tr><th>Time</th><th>Action</th><th>Path</th><th>Object</th><th className="w-full">Detail</th></tr></thead>
          <tbody>{[...d.admin.account_changes.map((c: any) => ({ ...c, acct: true })), ...d.admin.changes].slice(0, 300).map((c: any, i: number) => <tr key={i}><td><Time v={c.t} /></td>
            <td className={`text-xs ${c.acct ? "text-amber-300" : ""}`}>{c.action}</td><td className="font-mono text-xs">{c.path}</td><td className="font-mono text-xs">{c.object}</td>
            <td className="text-xs"><Trunc text={c.attr || c.detail} /></td></tr>)}</tbody></table></TableWrap></Card>}
      <Card title={`Authentication events (${fmtNum(d.events.length)})`} bodyClass="p-0">
        <TableWrap maxH="max-h-96"><table className="tbl"><thead><tr><th>Time</th><th>Type</th><th>Result</th><th>From</th><th>Country</th><th>Firewall</th><th className="w-full">Detail</th></tr></thead>
          <tbody>{d.events.map((e: any, i: number) => <tr key={i}><td><Time v={e.t} /></td><td className="text-xs">{KIND[e.kind]}</td><td className={`text-xs ${RES[e.result]}`}>{e.result}</td>
            <td>{e.src_ip ? <IpLink ip={e.src_ip} /> : "—"}</td><td className="text-xs">{e.country || "—"}</td><td className="text-xs nowrap">{e.firewall_name}</td>
            <td className="text-xs"><Trunc text={e.detail || e.action} /></td></tr>)}</tbody></table></TableWrap>
      </Card>
    </div>}
  </Drawer>;
}
