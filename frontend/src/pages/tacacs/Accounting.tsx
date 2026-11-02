import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, downloadUrl } from "../../lib/api";
import { useTheme } from "../../lib/theme";
import { getTimezone } from "../../lib/format";
import { Chart, PALETTES, axisStyle } from "../../components/Chart";
import { Card, Empty, Loading, Sev, TableWrap, Time, Trunc } from "../../components/ui";
import { Denied, Pager, RangeSelect, Status, useCan, useTacMeta } from "./common";

const SHOW = ["auth_success", "auth_failure", "auth_backend_error", "authz_permit", "authz_deny", "acct_start", "acct_stop"];

export function Accounting() {
  const can = useCan();
  const meta = useTacMeta();
  const { theme } = useTheme();
  const [f, setF] = useState<any>({ range: "24h", user: "", device: "", vendor: "", site: "", q: "", category: "", result: "", event_type: "", task_id: "", priv_lvl: "",
    severity: "", log: "" });
  const [offset, setOffset] = useState(0);
  const [raw, setRaw] = useState(false);
  const params = Object.fromEntries(Object.entries(f).filter(([, v]) => v !== "")) as any;
  const ev = useQuery({ queryKey: ["tac-events", params, offset, raw], enabled: can("auditor"), placeholderData: (p) => p,
    queryFn: () => api<any>("/tacacs/events", { params: { ...params, raw, limit: 100, offset } }) });
  const tl = useQuery({ queryKey: ["tac-timeline", f.range, f.user, f.device], queryFn: () => api<any>("/tacacs/timeline", { params: { range: f.range, user: f.user || undefined,
    device: f.device || undefined } }) });
  const option = useMemo(() => {
    const pts = tl.data?.points || [];
    return { legend: { top: 0 }, xAxis: { type: "time", ...axisStyle, axisLabel: { ...axisStyle.axisLabel, formatter: (v: number) => new Date(v).toLocaleString(undefined,
      { hour: "2-digit", minute: "2-digit", hour12: false, timeZone: getTimezone() }) } }, yAxis: { type: "value", ...axisStyle },
      series: SHOW.map((k, i) => ({ name: k.replace(/_/g, " "), type: "bar", stack: "a", barMaxWidth: 14, itemStyle: { color: PALETTES[theme][i % 8] },
        data: pts.map((p: any) => [Date.parse(p.t), p[k] ?? 0]) })) };
  }, [tl.data, theme]);
  const set = (k: string) => (e: any) => { setF({ ...f, [k]: e.target.value }); setOffset(0); };
  if (!can("auditor")) return <div className="space-y-4"><Denied role="auditor" what="see command history and accounting records" />
    <Card title="Activity (counts only)"><Chart option={option} height={220} /></Card></div>;
  return <div className="space-y-4">
    <div className="flex flex-wrap gap-2 items-center">
      <RangeSelect value={f.range} onChange={(v) => setF({ ...f, range: v })} />
      {[["user", "User"], ["device", "Device IP"], ["site", "Site"], ["q", "Command contains"], ["task_id", "Session / task id"]].map(([k, l]) =>
        <input key={k} aria-label={l} className="input py-1 w-36" placeholder={l} value={f[k]} onChange={set(k)} />)}
      <select aria-label="Vendor" className="input py-1" value={f.vendor} onChange={set("vendor")}><option value="">Any vendor</option>{["fortinet", "cisco", "ruckus", "other"].map((v) => <option key={v}>{v}</option>)}</select>
      <select aria-label="Log" className="input py-1" value={f.log} onChange={set("log")}><option value="">All logs</option><option value="authc">authentication</option>
        <option value="authz">authorization</option><option value="acct">accounting</option><option value="conn">connections</option></select>
      <select aria-label="Event type" className="input py-1" value={f.event_type} onChange={set("event_type")}><option value="">Any event</option>{(meta.data?.event_types || []).map((x: string) => <option key={x}>{x}</option>)}</select>
      <select aria-label="Category" className="input py-1" value={f.category} onChange={set("category")}><option value="">Any category</option>{Object.keys(meta.data?.categories || {}).map((x) => <option key={x}>{x}</option>)}</select>
      <select aria-label="Result" className="input py-1" value={f.result} onChange={set("result")}><option value="">Any result</option>{["success", "failure", "backend_unavailable", "policy_deny", "permit", "deny", "recorded"].map((x) => <option key={x}>{x}</option>)}</select>
      <select aria-label="Severity" className="input py-1" value={f.severity} onChange={set("severity")}><option value="">Any severity</option>{["informational", "low", "medium", "high"].map((x) => <option key={x}>{x}</option>)}</select>
      <input aria-label="Privilege level" className="input py-1 w-20" placeholder="priv" value={f.priv_lvl} onChange={set("priv_lvl")} />
      <label className="text-xs flex items-center gap-1"><input type="checkbox" checked={raw} onChange={(e) => setRaw(e.target.checked)} /> raw (redacted) record</label>
      <a className="btn" href={downloadUrl("/tacacs/events/export.csv", params)}>Export CSV</a>
    </div>
    <Card title="Timeline"><Chart option={option} height={220} /></Card>
    <Card title={`Events${ev.data ? ` (${ev.data.total})` : ""}`} bodyClass="p-0">
      <Loading q={ev} />
      {ev.data && (!ev.data.items.length ? <Empty text="No TACACS+ events match. Events appear once a managed server is ingesting its logs." /> :
        <TableWrap><table className="tbl"><thead><tr><th>Time</th><th>Severity</th><th>Event</th><th>User</th><th>Device</th><th>Port / client</th><th>Priv</th><th>Command</th>
          <th>Category</th><th>Rule / profile</th><th>Session</th>{raw && <th>Raw</th>}</tr></thead>
          <tbody>{ev.data.items.map((r: any, i: number) => <tr key={i}><td><Time v={r.ts} /></td><td><Sev s={r.severity} /></td>
            <td className="whitespace-nowrap">{r.event_type.replace(/_/g, " ")}<div className="text-2xs text-muted">{r.msgid}</div></td>
            <td><button className="link" onClick={() => setF({ ...f, user: r.username })}>{r.username}</button></td>
            <td className="text-xs">{r.device_name || r.device_address}<div className="text-muted">{r.vendor} {r.site}</div></td>
            <td className="text-xs">{r.port}<div className="text-muted">{r.remote_addr}</div></td><td className="num">{r.priv_lvl ?? "—"}</td>
            <td className="font-mono text-xs"><Trunc text={r.cmd} max="max-w-[20rem]" /></td><td className="text-xs">{r.cmd_category}</td>
            <td className="text-xs">{r.rule}{r.profile && <div className="text-muted">{r.profile}</div>}</td>
            <td className="font-mono text-xs">{r.task_id ? <button className="link" onClick={() => setF({ ...f, task_id: r.task_id })}>{r.task_id}</button> : "—"}</td>
            {raw && <td className="font-mono text-2xs"><Trunc text={r.raw} max="max-w-[24rem]" /></td>}</tr>)}</tbody></table></TableWrap>)}
      {ev.data && <Pager total={ev.data.total} limit={100} offset={offset} onChange={setOffset} />}
      <p className="text-2xs text-muted p-2">Secrets in commands are redacted before storage (Settings → redaction rules). Command records exist only where the device sends command accounting
        or command authorization. Related SIEM incidents: <Link className="link" to="/incidents">Incidents</Link> correlate TACACS+ alerts by user.</p>
    </Card>
  </div>;
}

export function Sessions() {
  const can = useCan();
  const [range, setRange] = useState("24h");
  const [user, setUser] = useState("");
  const [device, setDevice] = useState("");
  const [offset, setOffset] = useState(0);
  const [open, setOpen] = useState<number | null>(null);
  const q = useQuery({ queryKey: ["tac-sessions", range, user, device, offset], enabled: can("auditor"), placeholderData: (p) => p,
    queryFn: () => api<any>("/tacacs/sessions", { params: { range, user: user || undefined, device: device || undefined, limit: 50, offset } }) });
  if (!can("auditor")) return <Denied role="auditor" what="audit administrative sessions" />;
  return <Card title="Session audit" bodyClass="p-0" right={<><RangeSelect value={range} onChange={setRange} />
    <input aria-label="User" className="input py-1 w-32" placeholder="User" value={user} onChange={(e) => setUser(e.target.value)} />
    <input aria-label="Device IP" className="input py-1 w-36" placeholder="Device IP" value={device} onChange={(e) => setDevice(e.target.value)} /></>}>
    <Loading q={q} />
    {q.data && <p className="text-2xs text-muted p-2">{q.data.note}</p>}
    {q.data && (!q.data.items.length ? <Empty text="No exec sessions recorded in this range." /> :
      <TableWrap><table className="tbl"><thead><tr><th>Started</th><th>Stopped</th><th>State</th><th>User</th><th>Device</th><th>Port / from</th><th className="num">Priv</th>
        <th className="num">Duration</th><th className="num">Commands</th></tr></thead>
        <tbody>{q.data.items.map((x: any, i: number) => <>
          <tr key={i} className="cursor-pointer" onClick={() => setOpen(open === i ? null : i)}><td><Time v={x.started} /></td><td><Time v={x.stopped} /></td><td><Status s={x.state === "closed" ? "succeeded" : x.state} /></td>
            <td>{x.username}</td><td className="text-xs">{x.device_name || x.device_address}<div className="text-muted">{x.vendor} {x.site}</div></td>
            <td className="text-xs">{x.port}<div className="text-muted">{x.remote}</div></td><td className="num">{x.priv_lvl ?? "—"}</td>
            <td className="num">{x.elapsed_s != null ? `${Math.round(x.elapsed_s / 60)} min` : "—"}</td><td className="num">{x.commands.length}</td></tr>
          {open === i && <tr key={`${i}c`}><td colSpan={9} className="bg-slate-900/30">{!x.commands.length ? <span className="text-xs text-muted">No command accounting for this session.</span> :
            <table className="tbl"><tbody>{x.commands.map((c: any, j: number) => <tr key={j}><td><Time v={c.ts} /></td><td className="font-mono text-xs">{c.cmd}</td><td className="text-xs">{c.cmd_category}</td></tr>)}</tbody></table>}</td></tr>}
        </>)}</tbody></table></TableWrap>)}
    {q.data && <Pager total={q.data.items.length < 50 ? offset + q.data.items.length : offset + 51} limit={50} offset={offset} onChange={setOffset} />}
  </Card>;
}
