/** Sentinel NMS → Device Access: inventory access status, browser SSH terminals, diagnostics, bulk diagnostics,
 *  configuration change requests, credential vault, access audit and NMS roles. Everything here goes through the
 *  Device Access Gateway (/api/nms/access); the browser never connects to a device. */
import { lazy, Suspense, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, downloadUrl } from "../../lib/api";
import { useMe } from "../../lib/context";
import { Card, Empty, Field, Kpi, Loading, Modal, Pager, TableWrap, Tabs, Time, useDebounced } from "../../components/ui";

const DeviceTerminal = lazy(() => import("./Terminal"));

export const RISK_TONE: Record<string, string> = {
  READ_ONLY: "text-emerald-300", LOW_RISK: "text-sky-300", MODERATE_RISK: "text-amber-300",
  HIGH_RISK: "text-orange-300", DESTRUCTIVE: "text-red-300",
};
export const Risk = ({ r }: { r?: string }) => r ? <span className={`pill ${RISK_TONE[r] || "bg-slate-800 text-slate-300"}`}>{r.replace("_", " ").toLowerCase()}</span> : null;
const STATUS_TONE: Record<string, string> = {
  ok: "text-emerald-300", completed: "text-emerald-300", done: "text-emerald-300", active: "text-emerald-300", approved: "text-sky-300",
  failed: "text-red-300", verify_failed: "text-red-300", rejected: "text-red-300", terminated: "text-amber-300", cancelled: "text-slate-400",
  pending_approval: "text-amber-300", running: "text-sky-300", executing: "text-sky-300", skipped: "text-slate-400", rolled_back: "text-violet-300",
};
const St = ({ s }: { s?: string }) => <span className={`text-xs font-medium ${STATUS_TONE[s || ""] || "text-slate-300"}`}>{(s || "").replace(/_/g, " ")}</span>;

type AccessMe = { permissions: string[]; roles: string[]; terminal_enabled: boolean; changes_enabled: boolean; recording: string };
export function useAccess() {
  const q = useQuery({ queryKey: ["access-me"], queryFn: () => api<AccessMe>("/nms/access/me"), retry: false, staleTime: 60_000 });
  const can = (p: string) => !!q.data?.permissions.includes(p);
  return { q, me: q.data, can };
}

const TABS = [
  { key: "devices", label: "Devices", perm: "nms.device.access.view" }, { key: "sessions", label: "Sessions", perm: "nms.device.access.view" },
  { key: "bulk", label: "Bulk diagnostics", perm: "nms.automation.execute" }, { key: "automation", label: "Automation (Ansible)", perm: "nms.device.access.view" },
  { key: "changes", label: "Change requests", perm: "nms.device.access.view" }, { key: "consoles", label: "Console servers", perm: "nms.device.access.view" },
  { key: "vault", label: "Credential vault", perm: "nms.device.access.credential.manage" }, { key: "audit", label: "Access audit", perm: "nms.device.access.audit.view" },
  { key: "roles", label: "NMS roles", perm: "admin" },
];

export function AccessPage() {
  const [sp, setSp] = useSearchParams();
  const user = useMe();
  const { q, me, can } = useAccess();
  if (q.error) return <Card><p className="text-sm text-amber-300">{(q.error as Error).message}. Device access needs an NMS role (Administration → NMS roles).</p></Card>;
  if (!me) return <Loading q={q} />;
  const tabs = TABS.filter((t) => t.perm === "admin" ? user.role === "admin" : can(t.perm));
  const tab = tabs.some((t) => t.key === sp.get("tab")) ? sp.get("tab")! : "devices";
  return <div className="space-y-4 min-w-0">
    <p className="text-xs text-muted">Every connection starts in the Device Access Gateway: only inventory devices inside an authorised management network, on fixed
      service ports, with credentials from the vault that never reach the browser. Terminals are read-only unless opened for an approved change request.
      {!me.changes_enabled && " Configuration changes are disabled on this installation."}</p>
    <Tabs value={tab} onChange={(t) => setSp({ tab: t })} tabs={tabs} />
    {tab === "devices" && <Devices can={can} />}
    {tab === "sessions" && <Sessions can={can} />}
    {tab === "bulk" && <Bulk />}
    {tab === "changes" && <Changes can={can} enabled={me.changes_enabled} />}
    {tab === "vault" && <Vault />}
    {tab === "audit" && <Audit />}
    {tab === "roles" && <Roles />}
    {tab === "consoles" && <ConsoleServers can={can} />}
    {tab === "automation" && <Automation can={can} enabled={me.changes_enabled} />}
  </div>;
}

// ------------------------------------------------------------------ devices + terminals
type OpenTerm = { key: number; sid: number; name: string; mode?: "read_only" | "change"; changeId?: number; protocol?: "ssh" | "telnet" | "console"; consolePortId?: number };

export function TerminalWorkspace({ terms, setTerms }: { terms: OpenTerm[]; setTerms: (f: (t: OpenTerm[]) => OpenTerm[]) => void }) {
  const [active, setActive] = useState<number | null>(null);
  if (!terms.length) return null;
  const cur = terms.find((t) => t.key === active) || terms[terms.length - 1];
  return <Card title="Terminals" right={<span className="text-xs text-muted">{terms.length} open</span>}>
    <div className="flex flex-wrap gap-1 mb-2" role="tablist" aria-label="Open terminals">
      {terms.map((t) => <span key={t.key} className={`inline-flex items-center rounded-md border ${t.key === cur.key ? "border-line-strong bg-hover" : "border-line"}`}>
        <button role="tab" aria-selected={t.key === cur.key} className="px-2 py-1 text-xs" onClick={() => setActive(t.key)}>{t.name}{t.mode === "change" ? " (change)" : ""}</button>
        <button aria-label={`Close terminal ${t.name}`} className="px-1.5 text-muted hover:text-slate-100" onClick={() => setTerms((x) => x.filter((y) => y.key !== t.key))}>✕</button>
      </span>)}
    </div>
    <Suspense fallback={<div className="text-sm text-muted">Loading terminal…</div>}>
      {/* inactive terminals stay laid out (xterm cannot measure or render inside display: none) but are invisible and take no space */}
      {terms.map((t) => <div key={t.key} aria-hidden={t.key !== cur.key} className={t.key !== cur.key ? "invisible h-0 overflow-hidden" : ""}><DeviceTerminal sid={t.sid} mode={t.mode} changeId={t.changeId} protocol={t.protocol} consolePortId={t.consolePortId} /></div>)}
    </Suspense>
  </Card>;
}

let termSeq = 1;
export const newTerm = (sid: number, name: string, mode?: "read_only" | "change", changeId?: number, protocol?: "ssh" | "telnet" | "console",
  consolePortId?: number): OpenTerm => ({ key: termSeq++, sid, name, mode, changeId, protocol, consolePortId });

function Devices({ can }: { can: (p: string) => boolean }) {
  const [text, setText] = useState("");
  const [page, setPage] = useState(0);
  const [sel, setSel] = useState<Set<number>>(new Set());
  const [terms, setTerms] = useState<OpenTerm[]>([]);
  const [diag, setDiag] = useState<{ id: number; name: string } | null>(null);
  const q2 = useDebounced(text, 300);
  const size = 100;
  const q = useQuery({ queryKey: ["access-devices", q2, page], queryFn: () => api<any>("/nms/access/devices", { params: { q: q2, limit: size, offset: page * size } }),
    refetchInterval: 30_000 });
  const items: any[] = q.data?.items || [];
  const toggle = (id: number) => setSel((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });
  return <>
    <div className="kpi-grid"><Kpi label="Devices" value={q.data?.total ?? "—"} />
      <Kpi label="With SSH credential" value={items.filter((x) => x.ssh_credential).length} sub="this page" />
      <Kpi label="Command library" value={items.filter((x) => x.platform).length} sub="this page" />
      <Kpi label="Open sessions" value={items.reduce((a, x) => a + x.active_sessions, 0)} sub="this page" /></div>
    <TerminalWorkspace terms={terms} setTerms={setTerms} />
    <Card bodyClass="p-0" title="Devices" right={<div className="flex gap-2 items-center">
      <input aria-label="Search devices" className="input py-1" placeholder="Name, address, model" value={text} onChange={(e) => { setText(e.target.value); setPage(0); }} />
      {can("nms.automation.execute") && sel.size > 0 && <Link className="btn btn-primary py-1" to={`/nms/access?tab=bulk&devices=${[...sel].join(",")}`}>Bulk diagnostics ({sel.size})</Link>}
    </div>}>
      <Loading q={q} />
      {q.data && (!items.length ? <Empty text="No devices match. Devices come from Switch & Device Monitoring." /> :
        <TableWrap maxH="max-h-[40rem]"><table className="tbl"><thead><tr><th><span className="sr-only">Select</span></th><th>Device</th><th>Address</th><th>Platform</th>
          <th>Site</th><th>SNMP</th><th>SSH credential</th><th className="num">Sessions</th><th>Last access</th><th /></tr></thead>
          <tbody>{items.map((x) => <tr key={x.id}>
            <td><input type="checkbox" aria-label={`Select ${x.name}`} checked={sel.has(x.id)} onChange={() => toggle(x.id)} /></td>
            <td className="font-medium"><Link className="link" to={`/switches/${x.id}?tab=access`}>{x.name}</Link><div className="text-2xs text-muted">{x.vendor} {x.model || x.family}</div></td>
            <td className="font-mono text-xs">{x.address}</td>
            <td className="text-xs">{x.platform_label || <span className="text-muted">none</span>}</td><td className="text-xs">{x.site || "—"}</td>
            <td><St s={x.state === "up" ? "ok" : x.state} /></td>
            <td className="text-xs">{x.ssh_credential ? "assigned" : <span className="text-muted">none</span>}</td>
            <td className="num">{x.active_sessions || ""}</td><td className="text-xs whitespace-nowrap"><Time v={x.last_access} /></td>
            <td className="whitespace-nowrap space-x-1">
              {can("nms.device.access.ssh") && <button className="btn py-0.5 text-xs" disabled={!x.ssh_credential} title={x.ssh_credential ? "" : "no SSH credential"}
                onClick={() => setTerms((t) => [...t, newTerm(x.id, x.name)])}>SSH</button>}
              {can("nms.device.access.diagnostics") && <button className="btn py-0.5 text-xs" disabled={!x.platform || !x.ssh_credential}
                onClick={() => setDiag({ id: x.id, name: x.name })}>Diagnose</button>}
            </td></tr>)}</tbody></table></TableWrap>)}
      {q.data && <Pager page={page + 1} size={size} total={q.data.total} onPage={(p) => setPage(p - 1)} />}
    </Card>
    {diag && <Modal title={`Diagnostics — ${diag.name}`} onClose={() => setDiag(null)} wide><DiagnosticsPanel sid={diag.id} /></Modal>}
  </>;
}

/** The device page's Access tab. */
export function DeviceAccessTab({ sid }: { sid: number }) {
  const qc = useQueryClient();
  const { can, me } = useAccess();
  const [terms, setTerms] = useState<OpenTerm[]>([]);
  const [show, setShow] = useState<"" | "diag" | "change" | "protocol">("");
  const user = useMe();
  const telnet = useMutation({ mutationFn: (enabled: boolean) => api(`/nms/access/devices/${sid}/telnet`, { method: "PUT", body: { enabled } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["access-device", sid] }) });
  const q = useQuery({ queryKey: ["access-device", sid], queryFn: () => api<any>(`/nms/access/devices/${sid}`), refetchInterval: 15_000, retry: false });
  const test = useMutation({ mutationFn: () => api<any>(`/nms/access/devices/${sid}/test`, { method: "POST" }) });
  const web = useMutation({ mutationFn: () => api<any>(`/nms/access/devices/${sid}/web`, { method: "POST" }),
    onSuccess: (r) => window.open(r.url, "_blank", "noopener,noreferrer") });
  const term = useMutation({ mutationFn: (id: string) => api(`/nms/access/sessions/${id}/terminate`, { method: "POST" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["access-device", sid] }) });
  if (q.error) return <Card><p className="text-sm text-amber-300">{(q.error as Error).message}</p></Card>;
  const d = q.data;
  if (!d) return <Loading q={q} />;
  const a = d.actions;
  return <div className="space-y-4">
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title="Access">
        <dl className="grid grid-cols-[9rem_1fr] gap-y-1 text-sm">
          <dt className="text-muted">Management IP</dt><dd className="font-mono">{d.address}</dd>
          <dt className="text-muted">Platform</dt><dd>{d.platform_label || <span className="text-amber-300">no command library (set the access platform)</span>}</dd>
          <dt className="text-muted">Protocols</dt><dd className="text-xs">{Object.entries(d.protocols).filter(([, v]) => v).map(([k]) => k.toUpperCase()).join(" · ")}</dd>
          <dt className="text-muted">SSH credential</dt><dd>{d.credential.ssh ? <>{d.credential.ssh.name} <span className="text-xs text-muted">({d.credential.ssh.username}, {d.credential.ssh.via})</span></> : <span className="text-amber-300">none</span>}</dd>
          <dt className="text-muted">SSH host key</dt><dd className="text-xs">{d.host_key_pinned ? "pinned (trust on first use)" : "not seen yet"}</dd>
          <dt className="text-muted">SNMP</dt><dd className="text-xs"><St s={d.snmp.state === "up" ? "ok" : d.snmp.state} /> <Time v={d.snmp.last_success_at} /></dd>
          <dt className="text-muted">Last access</dt><dd className="text-xs"><Time v={d.last_access} />{d.last_latency_ms != null && ` · login ${d.last_latency_ms} ms`}</dd>
          <dt className="text-muted">Active sessions</dt><dd>{d.active_sessions}</dd>
        </dl>
        <div className="flex flex-wrap gap-2 mt-3">
          {a.ssh && <button className="btn btn-primary" onClick={() => setTerms((t) => [...t, newTerm(sid, d.name)])}>Open SSH terminal</button>}
          {a.https && <button className="btn" disabled={web.isPending} onClick={() => web.mutate()}>Open web management</button>}
          {a.diagnostics && <button className="btn" onClick={() => setShow("diag")}>Run diagnostics</button>}
          {a.test && <button className="btn" disabled={test.isPending} onClick={() => test.mutate()}>{test.isPending ? "Testing…" : "Test connectivity"}</button>}
          {a.change && <button className="btn" onClick={() => setShow("change")}>Request change</button>}
          {(a.netconf || a.restconf) && <button className="btn" onClick={() => setShow("protocol")}>NETCONF / RESTCONF</button>}
          {a.telnet && <button className="btn" title="clear text" onClick={() => confirm("Telnet sends the login and everything you type unencrypted. Continue?") &&
            setTerms((t) => [...t, newTerm(sid, `${d.name} (telnet)`, undefined, undefined, "telnet")])}>Telnet (clear text)</button>}
          {(d.consoles || []).filter((c: any) => c.usable).map((c: any) => <button key={c.id} className="btn"
            onClick={() => setTerms((t) => [...t, newTerm(sid, `${d.name} (console)`, undefined, undefined, "console", c.id)])}>Console: {c.server} port {c.port}</button>)}
          {a.credentials && <Link className="btn" to="/nms/access?tab=vault">Credential profile</Link>}
          {user.role === "admin" && <label className="text-xs flex items-center gap-1 ml-1" title="also needs ACCESS_TELNET_ENABLED on the installation">
            <input type="checkbox" checked={!!d.telnet_enabled_device} disabled={telnet.isPending} onChange={(e) => telnet.mutate(e.target.checked)} />allow Telnet for this device</label>}
        </div>
        {!a.ssh && can("nms.device.access.ssh") && <p className="text-xs text-muted mt-2">{me?.terminal_enabled === false ? "The browser terminal is disabled on this installation." : "Assign an SSH credential to open a terminal."}</p>}
        {test.error && <p role="alert" className="text-xs text-red-300 mt-2">{(test.error as Error).message}</p>}
        {web.error && <p role="alert" className="text-xs text-red-300 mt-2">{(web.error as Error).message}</p>}
        {test.data && <table className="tbl mt-3"><thead><tr><th>Service</th><th>Result</th><th className="num">Latency</th></tr></thead><tbody>
          {Object.entries(test.data).map(([k, v]: [string, any]) => <tr key={k}><td>{k.toUpperCase()}</td><td>{v.ok ? <St s="ok" /> : <span className="text-xs text-red-300">{v.error || v.state}</span>}</td>
            <td className="num text-xs">{v.latency_ms != null ? `${v.latency_ms} ms` : ""}</td></tr>)}</tbody></table>}
      </Card>
      <Card title="Access history" bodyClass="p-0">
        {!d.history.length ? <Empty text="Nobody has opened a session on this device yet." /> :
          <TableWrap maxH="max-h-80"><table className="tbl"><thead><tr><th>Started</th><th>User</th><th>State</th><th>Reason</th><th className="num">Cmds</th><th /></tr></thead>
            <tbody>{d.history.map((x: any) => <tr key={x.id}><td className="text-xs whitespace-nowrap"><Time v={x.started_at} /></td><td>{x.username}</td><td><St s={x.state} /></td>
              <td className="text-xs">{x.termination_reason || x.result}</td><td className="num">{x.commands}{x.blocked ? ` (${x.blocked} blocked)` : ""}</td>
              <td>{["pending", "active"].includes(x.state) && <button className="btn py-0.5 text-xs" onClick={() => term.mutate(x.id)}>Terminate</button>}</td></tr>)}</tbody></table></TableWrap>}
      </Card>
    </div>
    <TerminalWorkspace terms={terms} setTerms={setTerms} />
    {show === "diag" && <Modal title={`Diagnostics — ${d.name}`} onClose={() => setShow("")} wide><DiagnosticsPanel sid={sid} /></Modal>}
    {show === "protocol" && <Modal title={`NETCONF / RESTCONF — ${d.name}`} onClose={() => setShow("")} wide><ProtocolPanel sid={sid} platform={d.platform} /></Modal>}
    {show === "change" && <Modal title={`Change request — ${d.name}`} onClose={() => setShow("")} wide><ChangeForm sid={sid} onDone={() => setShow("")} /></Modal>}
  </div>;
}

function DiagnosticsPanel({ sid }: { sid: number }) {
  const q = useQuery({ queryKey: ["access-device", sid], queryFn: () => api<any>(`/nms/access/devices/${sid}`) });
  const [pick, setPick] = useState<Set<string>>(new Set());
  const run = useMutation({ mutationFn: () => api<any>(`/nms/access/devices/${sid}/diagnostics`, { method: "POST", body: { templates: [...pick] } }) });
  const tpls: any[] = q.data?.templates || [];
  const cats = [...new Set(tpls.map((t) => t.category))];
  return <div className="space-y-3">
    <Loading q={q} />
    {!!tpls.length && <div className="grid gap-2 sm:grid-cols-2">{cats.map((c) => <fieldset key={c} className="border border-line rounded-md p-2">
      <legend className="text-2xs uppercase text-muted px-1">{c}</legend>
      {tpls.filter((t) => t.category === c).map((t) => <label key={t.id} className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={pick.has(t.id)} onChange={() => setPick((s) => { const n = new Set(s); n.has(t.id) ? n.delete(t.id) : n.add(t.id); return n; })} />{t.title}</label>)}
    </fieldset>)}</div>}
    <button className="btn btn-primary" disabled={!pick.size || run.isPending} onClick={() => run.mutate()}>{run.isPending ? "Running…" : `Run ${pick.size || ""} read-only template${pick.size === 1 ? "" : "s"}`}</button>
    {run.error && <p role="alert" className="text-sm text-red-300">{(run.error as Error).message}</p>}
    {run.data && <ResultView r={run.data.result} jobId={run.data.job.id} />}
  </div>;
}

function ResultView({ r, jobId }: { r: any; jobId: number }) {
  return <div className="space-y-2">
    <div className="flex items-center gap-2 text-sm"><St s={r.status} /><span className="text-muted text-xs">{r.duration_ms} ms</span>{r.error && <span className="text-xs text-red-300">{r.error}</span>}
      <a className="btn py-0.5 text-xs ml-auto" href={downloadUrl(`/nms/access/jobs/${jobId}/export`)}>Download</a></div>
    {(r.outputs || []).map((o: any, i: number) => <details key={i} open={i === 0} className="border border-line rounded-md">
      <summary className="px-2 py-1 text-sm cursor-pointer"><span className="font-mono">{o.command}</span> <St s={o.status} /> <span className="text-xs text-muted">{o.ms} ms</span></summary>
      <pre className="text-xs font-mono whitespace-pre overflow-auto max-h-96 p-2 bg-slate-950">{o.output}{o.truncated ? "\n… (truncated)" : ""}</pre>
    </details>)}
  </div>;
}

// ------------------------------------------------------------------ sessions
function Sessions({ can }: { can: (p: string) => boolean }) {
  const qc = useQueryClient();
  const [state, setState] = useState("active");
  const [open, setOpen] = useState<string | null>(null);
  const q = useQuery({ queryKey: ["access-sessions", state], queryFn: () => api<any>("/nms/access/sessions", { params: { state: state || undefined, limit: 300 } }), refetchInterval: 10_000 });
  const kill = useMutation({ mutationFn: (id: string) => api(`/nms/access/sessions/${id}/terminate`, { method: "POST" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["access-sessions"] }) });
  const items: any[] = q.data?.items || [];
  return <Card bodyClass="p-0" title="Sessions" right={<select aria-label="Session state" className="input py-1" value={state} onChange={(e) => setState(e.target.value)}>
    <option value="active">Active</option><option value="ended">Ended</option><option value="">All</option></select>}>
    <Loading q={q} />
    {q.data && (!items.length ? <Empty text={state === "active" ? "No open sessions." : "No sessions."} /> :
      <TableWrap maxH="max-h-[40rem]"><table className="tbl"><thead><tr><th>Started</th><th>User</th><th>Device</th><th>Mode</th><th>Source</th><th>State</th><th>End reason</th>
        <th className="num">Commands</th><th className="num">Blocked</th><th /></tr></thead>
        <tbody>{items.map((x) => <tr key={x.id}><td className="text-xs whitespace-nowrap"><Time v={x.started_at} /></td><td>{x.username}</td>
          <td>{x.switch_id ? <Link className="link" to={`/switches/${x.switch_id}?tab=access`}>{x.device}</Link> : x.device}</td><td className="text-xs">{x.mode}{x.change_id ? ` #${x.change_id}` : ""}</td>
          <td className="font-mono text-xs">{x.client_ip}</td><td><St s={x.state} /></td><td className="text-xs">{x.termination_reason}</td>
          <td className="num">{x.commands}</td><td className="num">{x.blocked || ""}</td>
          <td className="whitespace-nowrap space-x-1"><button className="btn py-0.5 text-xs" onClick={() => setOpen(x.id)}>Details</button>
            {["pending", "active"].includes(x.state) && can("nms.device.access.session.terminate") && <button className="btn btn-danger py-0.5 text-xs" onClick={() => kill.mutate(x.id)}>Terminate</button>}</td>
        </tr>)}</tbody></table></TableWrap>)}
    {open && <SessionDetail id={open} onClose={() => setOpen(null)} canRec={can("nms.device.access.audit.view")} />}
  </Card>;
}

function SessionDetail({ id, onClose, canRec }: { id: string; onClose: () => void; canRec: boolean }) {
  const q = useQuery({ queryKey: ["access-session", id], queryFn: () => api<any>(`/nms/access/sessions/${id}`) });
  const d = q.data;
  return <Modal title={d ? `${d.username} on ${d.device}` : "Session"} onClose={onClose} wide>
    <Loading q={q} />
    {d && <div className="space-y-3">
      <div className="text-xs text-muted"><Time v={d.started_at} /> → <Time v={d.ended_at} /> · {d.client_ip} · {d.state} {d.termination_reason && `(${d.termination_reason})`} ·
        in {d.bytes_in} B / out {d.bytes_out} B {d.has_recording && canRec && <a className="link ml-2" href={downloadUrl(`/nms/access/sessions/${id}/recording`)}>Download recording</a>}</div>
      {!d.command_log.length ? <Empty text={d.recording === "off" ? "Command recording is off on this installation." : "No commands."} /> :
        <TableWrap maxH="max-h-96"><table className="tbl"><thead><tr><th>Time</th><th>Command</th><th>Risk</th><th>Result</th></tr></thead>
          <tbody>{d.command_log.map((c: any, i: number) => <tr key={i}><td className="text-xs whitespace-nowrap"><Time v={c.ts} /></td><td className="font-mono text-xs">{c.command}</td>
            <td><Risk r={c.risk} /></td><td className="text-xs">{c.allowed ? "sent" : <span className="text-red-300">blocked: {c.reason}</span>}</td></tr>)}</tbody></table></TableWrap>}
    </div>}
  </Modal>;
}

// ------------------------------------------------------------------ bulk diagnostics
function Bulk() {
  const [sp] = useSearchParams();
  const preset = useMemo(() => (sp.get("devices") || "").split(",").map(Number).filter(Boolean), [sp]);
  const [devs, setDevs] = useState<Set<number>>(new Set(preset));
  const [tpls, setTpls] = useState<Set<string>>(new Set());
  const [cats, setCats] = useState<Set<string>>(new Set());
  const [conc, setConc] = useState(10);
  const [job, setJob] = useState<number | null>(null);
  const [filter, setFilter] = useState("");
  const lib = useQuery({ queryKey: ["access-library"], queryFn: () => api<any>("/nms/access/library") });
  const devq = useQuery({ queryKey: ["access-devices-all"], queryFn: () => api<any>("/nms/access/devices", { params: { limit: 2000 } }) });
  const jobs = useQuery({ queryKey: ["access-jobs"], queryFn: () => api<any>("/nms/access/jobs", { params: { kind: "bulk" } }), refetchInterval: 10_000 });
  const start = useMutation({ mutationFn: () => api<any>("/nms/access/bulk", { method: "POST", body: { device_ids: [...devs], templates: [...tpls], categories: [...cats], concurrency: conc } }),
    onSuccess: (r) => setJob(r.job_id) });
  const all: any[] = (devq.data?.items || []).filter((x: any) => x.platform && x.ssh_credential);
  const shown = all.filter((x) => !filter || `${x.name} ${x.address} ${x.platform} ${x.site}`.toLowerCase().includes(filter.toLowerCase()));
  const plats = new Set(all.filter((x) => devs.has(x.id)).map((x) => x.platform));
  const templates: any[] = (lib.data?.templates || []).filter((t: any) => plats.has(t.platform));
  const categories = [...new Set((lib.data?.templates || []).map((t: any) => t.category))] as string[];
  const flip = <T,>(set: Set<T>, v: T) => { const n = new Set(set); n.has(v) ? n.delete(v) : n.add(v); return n; };
  return <div className="space-y-4">
    <div className="grid gap-4 xl:grid-cols-2">
      <Card title={`1. Devices (${devs.size})`} right={<div className="flex gap-2"><input aria-label="Filter devices" className="input py-1" placeholder="Filter" value={filter} onChange={(e) => setFilter(e.target.value)} />
        <button className="btn py-1" onClick={() => setDevs(new Set(shown.map((x) => x.id)))}>Select shown</button><button className="btn py-1" onClick={() => setDevs(new Set())}>Clear</button></div>} bodyClass="p-0">
        <Loading q={devq} />
        <TableWrap maxH="max-h-80"><table className="tbl"><tbody>{shown.map((x) => <tr key={x.id}><td><input type="checkbox" aria-label={`Select ${x.name}`} checked={devs.has(x.id)} onChange={() => setDevs((s) => flip(s, x.id))} /></td>
          <td className="font-medium">{x.name}</td><td className="text-xs">{x.platform_label}</td><td className="text-xs">{x.site}</td></tr>)}</tbody></table></TableWrap>
        {devq.data && !all.length && <Empty text="No device has both a command-library platform and an SSH credential." />}
      </Card>
      <Card title="2. What to run">
        <Field label="Whole categories (each device runs its own platform's templates)"><div className="flex flex-wrap gap-2">{categories.map((c) =>
          <label key={c} className="text-sm flex items-center gap-1"><input type="checkbox" checked={cats.has(c)} onChange={() => setCats((s) => flip(s, c))} />{c}</label>)}</div></Field>
        <Field label="Or individual templates" className="mt-3"><div className="max-h-56 overflow-auto space-y-0.5">{!templates.length ? <span className="text-xs text-muted">Select devices first.</span> :
          templates.map((t) => <label key={t.id} className="text-sm flex items-center gap-2"><input type="checkbox" checked={tpls.has(t.id)} onChange={() => setTpls((s) => flip(s, t.id))} />
            <span className="text-xs text-muted w-32 shrink-0 truncate">{t.platform}</span>{t.title} <span className="font-mono text-2xs text-muted truncate">{t.commands.join("; ")}</span></label>)}</div></Field>
        <div className="flex items-end gap-3 mt-3"><Field label="Devices at once"><input type="number" min={1} max={50} className="input w-24" value={conc} onChange={(e) => setConc(Number(e.target.value) || 1)} /></Field>
          <button className="btn btn-primary" disabled={!devs.size || (!tpls.size && !cats.size) || start.isPending} onClick={() => start.mutate()}>Run on {devs.size} device{devs.size === 1 ? "" : "s"}</button></div>
        {start.error && <p role="alert" className="text-sm text-red-300 mt-2">{(start.error as Error).message}</p>}
      </Card>
    </div>
    {job != null && <JobView id={job} />}
    <Card title="Recent bulk jobs" bodyClass="p-0">
      {!(jobs.data?.items || []).length ? <Empty text="No bulk jobs yet." /> :
        <TableWrap><table className="tbl"><thead><tr><th>#</th><th>Started</th><th>By</th><th>Status</th><th className="num">Devices</th><th className="num">Failed</th><th /></tr></thead>
          <tbody>{jobs.data.items.map((j: any) => <tr key={j.id}><td>{j.id}</td><td className="text-xs"><Time v={j.created_at} /></td><td>{j.username}</td><td><St s={j.status} /></td>
            <td className="num">{j.completed}/{j.total}</td><td className="num">{j.failed || ""}</td><td><button className="btn py-0.5 text-xs" onClick={() => setJob(j.id)}>Open</button></td></tr>)}</tbody></table></TableWrap>}
    </Card>
  </div>;
}

function JobView({ id }: { id: number }) {
  const qc = useQueryClient();
  const [open, setOpen] = useState<number | null>(null);
  const q = useQuery({ queryKey: ["access-job", id], queryFn: () => api<any>(`/nms/access/jobs/${id}`),
    refetchInterval: (qq) => ["queued", "running"].includes(qq.state.data?.job?.status) ? 2000 : false });
  const cancel = useMutation({ mutationFn: () => api(`/nms/access/jobs/${id}/cancel`, { method: "POST" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["access-job", id] }) });
  const one = useQuery({ queryKey: ["access-job-result", id, open], enabled: open != null, queryFn: () => api<any>(`/nms/access/jobs/${id}/results/${open}`) });
  const j = q.data?.job;
  const pct = j?.total ? Math.round((100 * j.completed) / j.total) : 0;
  return <Card title={`Job #${id}`} right={<div className="flex gap-2">{j && ["queued", "running"].includes(j.status) && <button className="btn btn-danger py-1" onClick={() => cancel.mutate()}>Cancel</button>}
    <a className="btn py-1" href={downloadUrl(`/nms/access/jobs/${id}/export`)}>Download all output</a></div>}>
    <Loading q={q} />
    {j && <>
      <div className="flex items-center gap-3 text-sm"><St s={j.status} /><span>{j.completed} / {j.total} devices</span>{j.failed > 0 && <span className="text-red-300">{j.failed} failed</span>}</div>
      <div className="h-2 rounded bg-slate-800 mt-2" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}><div className="h-2 rounded bg-slate-400" style={{ width: `${pct}%` }} /></div>
      <TableWrap maxH="max-h-96"><table className="tbl mt-3"><thead><tr><th>Device</th><th>Status</th><th>Commands</th><th className="num">Time</th><th>Error</th><th /></tr></thead>
        <tbody>{q.data.results.map((r: any) => <tr key={r.switch_id}><td className="font-medium">{r.device}</td><td><St s={r.status} /></td>
          <td className="text-xs">{(r.outputs || []).map((o: any) => `${o.command} (${o.status})`).join(", ")}</td><td className="num text-xs">{r.duration_ms != null ? `${r.duration_ms} ms` : ""}</td>
          <td className="text-xs text-red-300">{r.error}</td><td>{!!r.outputs?.length && <button className="btn py-0.5 text-xs" onClick={() => setOpen(r.switch_id)}>Output</button>}</td></tr>)}</tbody></table></TableWrap>
    </>}
    {open != null && <Modal title={one.data ? `${one.data.device} — job #${id}` : "Output"} onClose={() => setOpen(null)} wide><Loading q={one} />{one.data && <ResultView r={one.data} jobId={id} />}</Modal>}
  </Card>;
}

// ------------------------------------------------------------------ change requests
function ChangeForm({ sid, onDone }: { sid: number; onDone: () => void }) {
  const qc = useQueryClient();
  const [f, setF] = useState({ title: "", reason: "", lines: "", rollback: "", save: false, start: "", end: "" });
  const [risk, setRisk] = useState<any>(null);
  const create = useMutation({
    mutationFn: () => api<any>(`/nms/access/devices/${sid}/changes`, { method: "POST", body: {
      title: f.title, reason: f.reason, lines: f.lines.split("\n"), rollback_lines: f.rollback.split("\n"), save_config: f.save,
      window_start: f.start ? new Date(f.start).toISOString() : null, window_end: f.end ? new Date(f.end).toISOString() : null } }),
    onSuccess: (r) => { setRisk(r); qc.invalidateQueries({ queryKey: ["access-changes"] }); },
  });
  if (risk) return <div className="space-y-2 text-sm"><p>Change request #{risk.id} created with risk <Risk r={risk.risk} />. It needs approval by another person with the approver permission.</p>
    <pre className="text-xs font-mono bg-slate-950 p-2 rounded overflow-auto">{risk.preview}</pre><button className="btn" onClick={onDone}>Close</button></div>;
  return <div className="space-y-3">
    <Field label="Title"><input className="input w-full" value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} /></Field>
    <Field label="Reason / ticket"><input className="input w-full" value={f.reason} onChange={(e) => setF({ ...f, reason: e.target.value })} /></Field>
    <div className="grid gap-3 sm:grid-cols-2">
      <Field label="Configuration lines (in order)" hint="Configuration mode is entered and left for you."><textarea className="input w-full h-40 font-mono text-xs" value={f.lines} onChange={(e) => setF({ ...f, lines: e.target.value })} /></Field>
      <Field label="Rollback lines" hint="Required for high-risk changes (Junos uses rollback 1)."><textarea className="input w-full h-40 font-mono text-xs" value={f.rollback} onChange={(e) => setF({ ...f, rollback: e.target.value })} /></Field>
    </div>
    <div className="flex flex-wrap gap-3 items-end">
      <Field label="Window start"><input type="datetime-local" className="input" value={f.start} onChange={(e) => setF({ ...f, start: e.target.value })} /></Field>
      <Field label="Window end"><input type="datetime-local" className="input" value={f.end} onChange={(e) => setF({ ...f, end: e.target.value })} /></Field>
      <label className="text-sm flex items-center gap-2"><input type="checkbox" checked={f.save} onChange={(e) => setF({ ...f, save: e.target.checked })} />Save to startup configuration after verification</label>
    </div>
    {create.error && <p role="alert" className="text-sm text-red-300">{(create.error as Error).message}</p>}
    <button className="btn btn-primary" disabled={create.isPending || f.title.length < 3 || !f.lines.trim()} onClick={() => create.mutate()}>Submit for approval</button>
  </div>;
}

function Changes({ can, enabled }: { can: (p: string) => boolean; enabled: boolean }) {
  const [status, setStatus] = useState("");
  const [open, setOpen] = useState<number | null>(null);
  const q = useQuery({ queryKey: ["access-changes", status], queryFn: () => api<any>("/nms/access/changes", { params: { status: status || undefined } }), refetchInterval: 15_000 });
  const items: any[] = q.data?.items || [];
  return <>
    {!enabled && <p className="text-xs text-amber-300">Configuration changes are disabled (NMS_CONFIG_CHANGES_ENABLED). Requests can be made and approved; nothing is sent to a device.</p>}
    <Card bodyClass="p-0" title="Change requests" right={<select aria-label="Status" className="input py-1" value={status} onChange={(e) => setStatus(e.target.value)}>
      {["", "pending_approval", "approved", "completed", "failed", "verify_failed", "rolled_back", "rejected", "cancelled"].map((s) => <option key={s} value={s}>{s ? s.replace(/_/g, " ") : "All"}</option>)}</select>}>
      <Loading q={q} />
      {q.data && (!items.length ? <Empty text="No change requests. Request one from a device's Access tab." /> :
        <TableWrap><table className="tbl"><thead><tr><th>#</th><th>Created</th><th>Device</th><th>Title</th><th>Risk</th><th>Status</th><th>Requested by</th><th>Approved by</th><th /></tr></thead>
          <tbody>{items.map((c) => <tr key={c.id}><td>{c.id}</td><td className="text-xs whitespace-nowrap"><Time v={c.created_at} /></td><td>{c.device}</td><td>{c.title}</td>
            <td><Risk r={c.risk} /></td><td><St s={c.status} /></td><td>{c.requested_by}</td><td>{c.approved_by}</td>
            <td><button className="btn py-0.5 text-xs" onClick={() => setOpen(c.id)}>Open</button></td></tr>)}</tbody></table></TableWrap>)}
    </Card>
    {open != null && <ChangeDetail id={open} can={can} enabled={enabled} onClose={() => setOpen(null)} />}
  </>;
}

function ChangeDetail({ id, can, enabled, onClose }: { id: number; can: (p: string) => boolean; enabled: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const me = useMe();
  const [comment, setComment] = useState("");
  const q = useQuery({ queryKey: ["access-change", id], queryFn: () => api<any>(`/nms/access/changes/${id}`) });
  const act = useMutation({ mutationFn: (a: string) => api<any>(`/nms/access/changes/${id}/${a}`, { method: "POST", body: { comment } }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["access-change", id] }); qc.invalidateQueries({ queryKey: ["access-changes"] }); } });
  const c = q.data;
  const mine = c?.requested_by === me.username;
  return <Modal title={c ? `#${c.id} ${c.title}` : "Change request"} onClose={onClose} wide>
    <Loading q={q} />
    {c && <div className="space-y-3 text-sm">
      <div className="flex flex-wrap gap-3 items-center"><St s={c.status} /><Risk r={c.risk} /><span className="text-muted text-xs">{c.device} · requested by {c.requested_by}
        {c.approved_by && ` · ${c.status === "rejected" ? "rejected" : "approved"} by ${c.approved_by}`}{c.window_start && <> · window <Time v={c.window_start} /> – <Time v={c.window_end} /></>}</span></div>
      {c.reason && <p className="text-xs">{c.reason}</p>}
      <div className="grid gap-3 lg:grid-cols-2">
        <div><h3 className="text-xs uppercase text-muted mb-1">What will be sent</h3><pre className="text-xs font-mono bg-slate-950 p-2 rounded overflow-auto max-h-64">{c.preview}</pre></div>
        <div><h3 className="text-xs uppercase text-muted mb-1">Line risk</h3><TableWrap maxH="max-h-64"><table className="tbl"><tbody>{(c.result?.line_risks || []).map((l: any, i: number) =>
          <tr key={i}><td className="font-mono text-xs">{l.line}</td><td><Risk r={l.risk} /></td></tr>)}</tbody></table></TableWrap></div>
      </div>
      {c.result?.error && <p className="text-red-300 text-xs">{c.result.error}</p>}
      {c.result?.diff && <div><h3 className="text-xs uppercase text-muted mb-1">Configuration before → after (+{c.result.added} / -{c.result.removed})</h3>
        <pre className="text-xs font-mono bg-slate-950 p-2 rounded overflow-auto max-h-64">{c.result.diff}</pre></div>}
      {c.output && <details><summary className="cursor-pointer text-xs">Device transcript</summary><pre className="text-xs font-mono bg-slate-950 p-2 rounded overflow-auto max-h-64">{c.output}</pre></details>}
      <details><summary className="cursor-pointer text-xs">History ({c.log.length})</summary><ul className="text-xs space-y-0.5 mt-1">{c.log.map((e: any, i: number) => <li key={i}><Time v={e.at} /> {e.who}: {e.event} {e.detail}</li>)}</ul></details>
      <div className="flex flex-wrap gap-2 items-end border-t border-line pt-3">
        <Field label="Comment" className="flex-1"><input className="input w-full" value={comment} onChange={(e) => setComment(e.target.value)} /></Field>
        {c.status === "pending_approval" && can("nms.configuration.approve") && !mine && <>
          <button className="btn btn-primary" onClick={() => act.mutate("approve")}>Approve</button><button className="btn btn-danger" onClick={() => act.mutate("reject")}>Reject</button></>}
        {c.status === "approved" && can("nms.device.access.configuration") && <button className="btn btn-primary" disabled={!enabled || act.isPending} title={enabled ? "" : "changes are disabled"}
          onClick={() => act.mutate("execute")}>{act.isPending ? "Executing…" : "Execute change"}</button>}
        {["completed", "failed", "verify_failed"].includes(c.status) && can("nms.configuration.approve") && <button className="btn" disabled={!enabled} onClick={() => act.mutate("rollback")}>Roll back</button>}
        {["pending_approval", "approved"].includes(c.status) && (mine || can("nms.configuration.approve")) && <button className="btn" onClick={() => act.mutate("cancel")}>Cancel request</button>}
      </div>
      {c.status === "pending_approval" && mine && <p className="text-xs text-muted">Waiting for another person to approve (you cannot approve your own change).</p>}
      {act.error && <p role="alert" className="text-sm text-red-300">{(act.error as Error).message}</p>}
    </div>}
  </Modal>;
}

// ------------------------------------------------------------------ credential vault
function Vault() {
  const qc = useQueryClient();
  const [edit, setEdit] = useState<any | null>(null);
  const [assign, setAssign] = useState<any | null>(null);
  const q = useQuery({ queryKey: ["access-vault"], queryFn: () => api<any>("/nms/access/vault") });
  const del = useMutation({ mutationFn: (id: number) => api(`/nms/access/vault/${id}`, { method: "DELETE" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["access-vault"] }) });
  const unassign = useMutation({ mutationFn: (id: number) => api(`/nms/access/vault/assignments/${id}`, { method: "DELETE" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["access-vault"] }) });
  const items: any[] = q.data?.items || [];
  const names = Object.fromEntries(items.map((c) => [c.id, c.name]));
  return <>
    <p className="text-xs text-muted">Secrets are encrypted at rest (TOKEN_ENCRYPTION_KEY, rotated with app.rotate_keys) and are never shown again or returned by any API. A device's own
      credential wins over a group assignment; among groups the most specific match wins. SNMP credentials are managed in Switch Monitoring → Settings.</p>
    <Card title="Credentials" bodyClass="p-0" right={<button className="btn btn-primary py-1" onClick={() => setEdit({ kind: "ssh" })}>Add credential</button>}>
      <Loading q={q} />
      {q.data && (!items.length ? <Empty text="No credentials yet." /> :
        <TableWrap><table className="tbl"><thead><tr><th>Name</th><th>Kind</th><th>Username</th><th>Holds</th><th>Owner</th><th>Rotated</th><th className="num">Devices</th><th className="num">Groups</th><th /></tr></thead>
          <tbody>{items.map((c) => <tr key={c.id}><td className="font-medium">{c.name}</td><td className="text-xs">{c.kind}</td><td>{c.username}</td>
            <td className="text-xs">{c.secret_fields.join(", ") || "—"}</td><td className="text-xs">{c.owner}</td><td className="text-xs"><Time v={c.rotated_at} /></td>
            <td className="num">{c.devices}</td><td className="num">{c.groups}</td>
            <td className="whitespace-nowrap space-x-1"><button className="btn py-0.5 text-xs" onClick={() => setEdit(c)}>Edit / rotate</button>
              <button className="btn py-0.5 text-xs" onClick={() => setAssign(c)}>Assign</button>
              <button className="btn btn-danger py-0.5 text-xs" disabled={c.devices > 0} onClick={() => confirm(`Delete credential ${c.name}?`) && del.mutate(c.id)}>Delete</button></td></tr>)}</tbody></table></TableWrap>)}
      {del.error && <p role="alert" className="text-sm text-red-300 p-2">{(del.error as Error).message}</p>}
    </Card>
    <Card title="Group assignments" bodyClass="p-0">
      {!(q.data?.assignments || []).length ? <Empty text="No group assignments. Devices use only their own credential." /> :
        <TableWrap><table className="tbl"><thead><tr><th>Credential</th><th>Kind</th><th>Site</th><th>Role</th><th>Vendor</th><th>By</th><th /></tr></thead>
          <tbody>{q.data.assignments.map((a: any) => <tr key={a.id}><td>{names[a.credential_id]}</td><td className="text-xs">{a.kind}</td><td>{a.site || "any"}</td><td>{a.role || "any"}</td>
            <td>{a.vendor || "any"}</td><td className="text-xs">{a.created_by}</td><td><button className="btn py-0.5 text-xs" onClick={() => unassign.mutate(a.id)}>Remove</button></td></tr>)}</tbody></table></TableWrap>}
    </Card>
    {edit && <VaultForm c={edit} onClose={() => setEdit(null)} />}
    {assign && <AssignForm c={assign} onClose={() => setAssign(null)} />}
  </>;
}

function VaultForm({ c, onClose }: { c: any; onClose: () => void }) {
  const qc = useQueryClient();
  const [f, setF] = useState({ name: c.name || "", kind: c.kind || "ssh", username: c.username || "", password: "", private_key: "", token: "", description: c.description || "", owner: c.owner || "" });
  const save = useMutation({ mutationFn: () => api(c.id ? `/nms/access/vault/${c.id}` : "/nms/access/vault", { method: c.id ? "PUT" : "POST", body: f }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["access-vault"] }); onClose(); } });
  return <Modal title={c.id ? `Credential ${c.name}` : "New credential"} onClose={onClose}>
    <div className="space-y-3">
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Name"><input className="input w-full" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
        <Field label="Kind"><select className="input w-full" disabled={!!c.id} value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })}>
          {["ssh", "https", "api_token", "netconf"].map((k) => <option key={k}>{k}</option>)}</select></Field>
        {f.kind !== "api_token" && <Field label="Username"><input className="input w-full" autoComplete="off" value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} /></Field>}
        <Field label="Owner"><input className="input w-full" value={f.owner} onChange={(e) => setF({ ...f, owner: e.target.value })} /></Field>
      </div>
      {f.kind !== "api_token" && <Field label={c.id ? "New password (empty keeps the stored one)" : "Password"}><input type="password" autoComplete="new-password" className="input w-full" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} /></Field>}
      {["ssh", "netconf"].includes(f.kind) && <Field label="Private key (OpenSSH / PEM, no passphrase)"><textarea className="input w-full h-24 font-mono text-xs" value={f.private_key} onChange={(e) => setF({ ...f, private_key: e.target.value })} /></Field>}
      {f.kind === "api_token" && <Field label={c.id ? "New token (empty keeps the stored one)" : "Token"}><input type="password" autoComplete="off" className="input w-full" value={f.token} onChange={(e) => setF({ ...f, token: e.target.value })} /></Field>}
      <Field label="Description"><input className="input w-full" value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></Field>
      {save.error && <p role="alert" className="text-sm text-red-300">{(save.error as Error).message}</p>}
      <button className="btn btn-primary" disabled={save.isPending || !f.name} onClick={() => save.mutate()}>Save</button>
    </div>
  </Modal>;
}

function AssignForm({ c, onClose }: { c: any; onClose: () => void }) {
  const qc = useQueryClient();
  const [f, setF] = useState({ site: "", role: "", vendor: "" });
  const save = useMutation({ mutationFn: () => api(`/nms/access/vault/${c.id}/assignments`, { method: "POST", body: { kind: c.kind, ...f } }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["access-vault"] }); onClose(); } });
  return <Modal title={`Assign ${c.name} to a device group`} onClose={onClose}>
    <div className="space-y-3">
      <p className="text-xs text-muted">Empty fields match every device. Devices with their own {c.kind} credential keep it.</p>
      <div className="grid gap-3 sm:grid-cols-3">
        <Field label="Site"><input className="input w-full" value={f.site} onChange={(e) => setF({ ...f, site: e.target.value })} /></Field>
        <Field label="Role"><input className="input w-full" placeholder="core, access, wlc…" value={f.role} onChange={(e) => setF({ ...f, role: e.target.value })} /></Field>
        <Field label="Vendor"><input className="input w-full" placeholder="cisco, juniper…" value={f.vendor} onChange={(e) => setF({ ...f, vendor: e.target.value })} /></Field>
      </div>
      {save.error && <p role="alert" className="text-sm text-red-300">{(save.error as Error).message}</p>}
      <button className="btn btn-primary" onClick={() => save.mutate()}>Assign</button>
    </div>
  </Modal>;
}

// ------------------------------------------------------------------ audit
function Audit() {
  const [action, setAction] = useState("");
  const [user, setUser] = useState("");
  const [page, setPage] = useState(0);
  const u = useDebounced(user, 300);
  const size = 100;
  const q = useQuery({ queryKey: ["access-audit", action, u, page], queryFn: () => api<any>("/nms/access/audit", { params: { action: action || undefined, username: u || undefined, limit: size, offset: page * size } }) });
  const v = useQuery({ queryKey: ["access-audit-verify"], queryFn: () => api<any>("/nms/access/audit/verify") });
  const items: any[] = q.data?.items || [];
  return <>
    <div className="kpi-grid"><Kpi label="Audit records" value={q.data?.total ?? "—"} />
      <Kpi label="Integrity" value={v.data ? (v.data.ok ? "intact" : `broken at #${v.data.broken_at}`) : "…"} tone={v.data ? (v.data.ok ? "ok" : "bad") : undefined} sub={v.data && `${v.data.checked} records checked`} /></div>
    <Card bodyClass="p-0" title="Access audit" right={<div className="flex gap-2">
      <select aria-label="Action" className="input py-1" value={action} onChange={(e) => { setAction(e.target.value); setPage(0); }}>
        {["", "terminal_open", "terminal_connect", "terminal_end", "terminal_refused", "terminal_terminate", "diagnostics_run", "bulk_diagnostics", "connectivity_test", "web_open",
          "change_request", "change_approve", "change_reject", "change_execute", "change_rollback", "vault_create", "vault_rotate", "vault_assign", "roles_update"].map((a) => <option key={a} value={a}>{a || "All actions"}</option>)}</select>
      <input aria-label="User" className="input py-1 w-32" placeholder="User" value={user} onChange={(e) => { setUser(e.target.value); setPage(0); }} />
      <a className="btn py-1" href={downloadUrl("/nms/access/audit/export.csv")}>Export CSV</a></div>}>
      <Loading q={q} />
      {q.data && (!items.length ? <Empty text="No audit records match." /> :
        <TableWrap maxH="max-h-[40rem]"><table className="tbl"><thead><tr><th>Time</th><th>User</th><th>Action</th><th>Target</th><th>Result</th><th>Source</th><th>Detail</th></tr></thead>
          <tbody>{items.map((r) => <tr key={r.id}><td className="text-xs whitespace-nowrap"><Time v={r.ts} /></td><td>{r.username}</td><td className="text-xs font-mono">{r.action}</td>
            <td className="text-xs">{r.target}</td><td>{r.success ? <St s="ok" /> : <St s="failed" />}</td><td className="font-mono text-xs">{r.client_ip}</td>
            <td className="text-xs font-mono cell-wrap max-w-[28rem] break-all">{JSON.stringify(r.detail)}</td></tr>)}</tbody></table></TableWrap>)}
      {q.data && <Pager page={page + 1} size={size} total={q.data.total} onPage={(p) => setPage(p - 1)} />}
    </Card>
  </>;
}

// ------------------------------------------------------------------ roles
function Roles() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["access-roles"], queryFn: () => api<any>("/nms/access/roles") });
  const set = useMutation({ mutationFn: ({ id, roles }: { id: number; roles: string[] }) => api(`/nms/access/roles/${id}`, { method: "PUT", body: { roles } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["access-roles"] }) });
  const d = q.data;
  return <>
    <p className="text-xs text-muted">Administrators are Super Administrators. Changing a user's roles signs them out everywhere, including open terminals. A user's site list
      (Settings → Users) limits every permission to those sites.</p>
    <Card bodyClass="p-0" title="Users"><Loading q={q} />
      {d && <TableWrap><table className="tbl"><thead><tr><th>User</th><th>Products</th><th>Sites</th>{d.roles.filter((r: any) => r.id !== "super_admin").map((r: any) => <th key={r.id} className="text-center">{r.label}</th>)}</tr></thead>
        <tbody>{d.users.map((u: any) => <tr key={u.id}><td className="font-medium">{u.username}{u.role === "admin" && <span className="pill bg-slate-800 text-slate-300 ml-1">admin</span>}</td>
          <td className="text-xs">{u.role === "admin" ? "all" : u.products.join(", ") || "none"}</td><td className="text-xs">{u.sites.join(", ") || "all"}</td>
          {d.roles.filter((r: any) => r.id !== "super_admin").map((r: any) => <td key={r.id} className="text-center">
            <input type="checkbox" aria-label={`${u.username}: ${r.label}`} disabled={u.role === "admin" || set.isPending} checked={u.role === "admin" || u.nms_roles.includes(r.id)}
              onChange={(e) => set.mutate({ id: u.id, roles: e.target.checked ? [...u.nms_roles, r.id] : u.nms_roles.filter((x: string) => x !== r.id) })} /></td>)}
        </tr>)}</tbody></table></TableWrap>}
      {set.error && <p role="alert" className="text-sm text-red-300 p-2">{(set.error as Error).message}</p>}
    </Card>
    {d && <Card title="Permissions by role"><TableWrap><table className="tbl"><thead><tr><th>Permission</th>{d.roles.map((r: any) => <th key={r.id} className="text-center">{r.label}</th>)}</tr></thead>
      <tbody>{d.permissions.map((p: string) => <tr key={p}><td className="font-mono text-xs">{p}</td>{d.roles.map((r: any) => <td key={r.id} className="text-center">{r.permissions.includes(p) ? "✓" : ""}</td>)}</tr>)}</tbody></table></TableWrap></Card>}
  </>;
}


function ProtocolPanel({ sid, platform }: { sid: number; platform: string | null }) {
  const ops = useQuery({ queryKey: ["access-protocol-ops"], queryFn: () => api<any>("/nms/access/protocol-ops") });
  const [sel, setSel] = useState<{ proto: "netconf" | "restconf"; op: string }>({ proto: "netconf", op: "capabilities" });
  const run = useMutation({ mutationFn: () => api<any>(`/nms/access/devices/${sid}/${sel.proto}`, { method: "POST", body: { operation: sel.op } }) });
  const list = (ops.data?.[sel.proto] || []).filter((o: any) => !o.platform || o.platform === platform);
  return <div className="space-y-3">
    <p className="text-xs text-muted">Fixed read-only operations only. NETCONF uses TCP 830 with the netconf (else ssh) credential and the pinned SSH host key; RESTCONF uses
      HTTPS 443 with the https (else ssh) credential and pins the device certificate on first use. Secrets in the reply are masked.</p>
    <div className="flex flex-wrap gap-2 items-center">
      <select aria-label="Protocol" className="input py-1" value={sel.proto} onChange={(e) => setSel({ proto: e.target.value as any, op: "" })}>
        <option value="netconf">NETCONF</option><option value="restconf">RESTCONF</option></select>
      <select aria-label="Operation" className="input py-1" value={sel.op} onChange={(e) => setSel({ ...sel, op: e.target.value })}>
        <option value="">— operation —</option>{list.map((o: any) => <option key={o.id} value={o.id}>{o.title}</option>)}</select>
      <button className="btn btn-primary" disabled={!sel.op || run.isPending} onClick={() => run.mutate()}>{run.isPending ? "Running…" : "Run"}</button>
    </div>
    {run.error && <p role="alert" className="text-sm text-red-300">{(run.error as Error).message}</p>}
    {run.data && <div className="space-y-1"><div className="text-xs"><St s={run.data.status} /> {run.data.http_status ? `HTTP ${run.data.http_status} · ` : ""}{run.data.ms} ms
      <a className="link ml-2" href={downloadUrl(`/nms/access/jobs/${run.data.job_id}/export`)}>Download</a></div>
      <pre className="text-xs font-mono whitespace-pre-wrap break-all max-h-96 overflow-auto p-2 bg-slate-950">{run.data.output}</pre></div>}
  </div>;
}


// ------------------------------------------------------------------ console servers
function ConsoleServers({ can }: { can: (p: string) => boolean }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["access-consoles"], queryFn: () => api<any>("/nms/access/console-servers") });
  const vaultQ = useQuery({ queryKey: ["access-vault"], queryFn: () => api<any>("/nms/access/vault"), enabled: can("nms.device.access.credential.manage") });
  const devs = useQuery({ queryKey: ["access-devices-all"], queryFn: () => api<any>("/nms/access/devices", { params: { limit: 2000 } }) });
  const [f, setF] = useState({ name: "", address: "", kind: "opengear", method: "ssh", credential_id: 0, site: "", notes: "" });
  const [port, setPort] = useState<Record<number, { port: string; switch_id: string; label: string }>>({});
  const inv = () => qc.invalidateQueries({ queryKey: ["access-consoles"] });
  const create = useMutation({ mutationFn: () => api("/nms/access/console-servers", { method: "POST", body: { ...f, credential_id: f.credential_id || null } }),
    onSuccess: () => { setF({ ...f, name: "", address: "" }); inv(); } });
  const del = useMutation({ mutationFn: (id: number) => api(`/nms/access/console-servers/${id}`, { method: "DELETE" }), onSuccess: inv });
  const addPort = useMutation({ mutationFn: ({ id, b }: { id: number; b: any }) => api(`/nms/access/console-servers/${id}/ports`, { method: "POST", body: b }), onSuccess: inv });
  const delPort = useMutation({ mutationFn: (id: number) => api(`/nms/access/console-ports/${id}`, { method: "DELETE" }), onSuccess: inv });
  const manage = can("nms.device.manage");
  const sshCreds = (vaultQ.data?.items || []).filter((c: any) => c.kind === "ssh");
  return <>
    <p className="text-xs text-muted">Serial consoles reached through Opengear (SSH as <code>user:portNN</code>) or Cisco terminal servers (SSH as <code>user:line</code>), or by
      reverse Telnet on 2000 + port (clear text; needs ACCESS_TELNET_ENABLED{q.data && !q.data.telnet_enabled ? ", which is off" : ""}). Map each port to its device: the console
      then appears on that device's Access tab, with the same permissions, command guard and audit as SSH.</p>
    {manage && <Card title="Add a console server">
      <div className="flex flex-wrap gap-2 items-end">
        <Field label="Name"><input className="input" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
        <Field label="Management IP"><input className="input" value={f.address} onChange={(e) => setF({ ...f, address: e.target.value })} /></Field>
        <Field label="Kind"><select className="input" value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })}><option value="opengear">Opengear</option><option value="cisco">Cisco terminal server</option></select></Field>
        <Field label="Method"><select className="input" value={f.method} onChange={(e) => setF({ ...f, method: e.target.value })}><option value="ssh">SSH</option><option value="telnet">Telnet (clear text)</option></select></Field>
        <Field label="Credential (vault, ssh)"><select className="input" value={f.credential_id} onChange={(e) => setF({ ...f, credential_id: Number(e.target.value) })}>
          <option value={0}>—</option>{sshCreds.map((c: any) => <option key={c.id} value={c.id}>{c.name}</option>)}</select></Field>
        <Field label="Site"><input className="input w-28" value={f.site} onChange={(e) => setF({ ...f, site: e.target.value })} /></Field>
        <button className="btn btn-primary" disabled={!f.name || !f.address || create.isPending} onClick={() => create.mutate()}>Add</button>
      </div>
      {create.error && <p role="alert" className="text-sm text-red-300 mt-2">{(create.error as Error).message}</p>}
    </Card>}
    <Loading q={q} />
    {q.data && !q.data.items.length && <Card><Empty text="No console servers yet." /></Card>}
    {(q.data?.items || []).map((c: any) => <Card key={c.id} title={`${c.name} · ${c.kind === "opengear" ? "Opengear" : "Cisco"} · ${c.method}`} bodyClass="p-0"
      right={<div className="flex gap-2 items-center text-xs"><span className="font-mono">{c.address}</span><span className="text-muted">{c.host_key_pinned ? "host key pinned" : "host key not seen yet"}</span>
        {manage && <button className="btn btn-danger py-0.5" onClick={() => confirm(`Remove ${c.name} and its port mappings?`) && del.mutate(c.id)}>Remove</button>}</div>}>
      <TableWrap><table className="tbl"><thead><tr><th>Port / line</th><th>Device</th><th>Label</th><th /></tr></thead><tbody>
        {c.ports.map((p: any) => <tr key={p.id}><td>{p.port}</td><td>{p.switch_id ? <Link className="link" to={`/switches/${p.switch_id}?tab=access`}>{p.device}</Link> : "—"}</td>
          <td>{p.label}</td><td>{manage && <button className="btn py-0.5 text-xs" onClick={() => delPort.mutate(p.id)}>Unmap</button>}</td></tr>)}
        {manage && <tr><td><input aria-label="Port" className="input py-0.5 w-20" value={port[c.id]?.port || ""} onChange={(e) => setPort({ ...port, [c.id]: { ...(port[c.id] || { switch_id: "", label: "" }), port: e.target.value } })} /></td>
          <td><select aria-label="Device" className="input py-0.5" value={port[c.id]?.switch_id || ""} onChange={(e) => setPort({ ...port, [c.id]: { ...(port[c.id] || { port: "", label: "" }), switch_id: e.target.value } })}>
            <option value="">— device —</option>{(devs.data?.items || []).map((x: any) => <option key={x.id} value={x.id}>{x.name}</option>)}</select></td>
          <td><input aria-label="Label" className="input py-0.5" value={port[c.id]?.label || ""} onChange={(e) => setPort({ ...port, [c.id]: { ...(port[c.id] || { port: "", switch_id: "" }), label: e.target.value } })} /></td>
          <td><button className="btn py-0.5 text-xs" disabled={!port[c.id]?.port} onClick={() => addPort.mutate({ id: c.id, b: { port: Number(port[c.id].port),
            switch_id: port[c.id].switch_id ? Number(port[c.id].switch_id) : null, label: port[c.id].label } })}>Map port</button></td></tr>}
      </tbody></table></TableWrap>
      {addPort.error && <p role="alert" className="text-sm text-red-300 p-2">{(addPort.error as Error).message}</p>}
    </Card>)}
  </>;
}

// ------------------------------------------------------------------ Ansible automation
const SAMPLE_PB = `- name: Check versions
  hosts: targets
  gather_facts: false
  tasks:
    - name: show version
      cisco.ios.ios_command:
        commands: [show version]
      register: out
    - ansible.builtin.debug: {var: out.stdout_lines}
`;

function Automation({ can, enabled }: { can: (p: string) => boolean; enabled: boolean }) {
  const qc = useQueryClient();
  const me = useMe();
  const [edit, setEdit] = useState<any | null>(null);
  const [runFor, setRunFor] = useState<any | null>(null);
  const [openRun, setOpenRun] = useState<number | null>(null);
  const pbs = useQuery({ queryKey: ["access-playbooks"], queryFn: () => api<any>("/nms/access/playbooks") });
  const runs = useQuery({ queryKey: ["access-pb-runs"], queryFn: () => api<any>("/nms/access/playbooks/runs"),
    refetchInterval: (q) => (q.state.data?.items || []).some((r: any) => ["queued", "running"].includes(r.status)) ? 3000 : 20_000 });
  const inv = () => { qc.invalidateQueries({ queryKey: ["access-playbooks"] }); qc.invalidateQueries({ queryKey: ["access-pb-runs"] }); };
  const act = useMutation({ mutationFn: ({ path }: { path: string }) => api(path, { method: "POST", body: {} }), onSuccess: inv });
  const approver = can("nms.configuration.approve");
  return <>
    <p className="text-xs text-muted">Playbooks run on the Ansible runner against the devices you choose, with credentials from the vault and the host keys Sentinel pinned.
      The policy allows network facts / command modules with read-only commands, debug / set_fact / assert / fail, and network configuration modules (a <b>change</b> playbook);
      shell, command, file, template, lookups, local or delegated tasks are refused. A playbook version runs only after another person approves it; a real run of a change
      playbook also needs a second person's approval{enabled ? "" : " and configuration changes are currently disabled (dry runs still work)"}.</p>
    <Card title="Playbooks" bodyClass="p-0" right={can("nms.automation.execute") && <button className="btn btn-primary py-1" onClick={() => setEdit({ name: "", description: "", content: SAMPLE_PB })}>New playbook</button>}>
      <Loading q={pbs} />
      {pbs.data && (!pbs.data.items.length ? <Empty text="No playbooks yet." /> :
        <TableWrap><table className="tbl"><thead><tr><th>Name</th><th>Kind</th><th>Status</th><th>Last edited by</th><th>Approved by</th><th /></tr></thead>
          <tbody>{pbs.data.items.map((p: any) => <tr key={p.id}><td className="font-medium">{p.name}<div className="text-2xs text-muted">{p.description}</div></td>
            <td>{p.kind === "change" ? <Risk r="HIGH_RISK" /> : <Risk r="READ_ONLY" />}</td>
            <td><St s={p.approved ? "approved" : p.status === "retired" ? "cancelled" : "pending_approval"} /></td><td>{p.updated_by}</td><td>{p.approved_by}</td>
            <td className="whitespace-nowrap space-x-1">
              <button className="btn py-0.5 text-xs" onClick={async () => setEdit(await api<any>(`/nms/access/playbooks/${p.id}`))}>Open</button>
              {approver && !p.approved && p.status !== "retired" && p.updated_by !== me.username && <button className="btn py-0.5 text-xs" onClick={() => act.mutate({ path: `/nms/access/playbooks/${p.id}/approve` })}>Approve</button>}
              {p.approved && can("nms.automation.execute") && <button className="btn btn-primary py-0.5 text-xs" onClick={() => setRunFor(p)}>Run…</button>}
            </td></tr>)}</tbody></table></TableWrap>)}
      {act.error && <p role="alert" className="text-sm text-red-300 p-2">{(act.error as Error).message}</p>}
    </Card>
    <Card title="Runs" bodyClass="p-0">
      {!(runs.data?.items || []).length ? <Empty text="No runs yet." /> :
        <TableWrap maxH="max-h-96"><table className="tbl"><thead><tr><th>#</th><th>Playbook</th><th>Mode</th><th>Status</th><th className="num">Devices</th><th>Requested by</th>
          <th>Approved by</th><th>Created</th><th /></tr></thead>
          <tbody>{runs.data.items.map((r: any) => <tr key={r.id}><td>{r.id}</td><td>{r.playbook}</td><td className="text-xs">{r.mode === "check" ? "dry run" : r.kind === "change" ? "change" : "run"}</td>
            <td><St s={r.status} /></td><td className="num">{r.devices}</td><td>{r.requested_by}</td><td>{r.approved_by}</td><td className="text-xs whitespace-nowrap"><Time v={r.created_at} /></td>
            <td className="whitespace-nowrap space-x-1"><button className="btn py-0.5 text-xs" onClick={() => setOpenRun(r.id)}>Output</button>
              {r.status === "pending_approval" && approver && r.requested_by !== me.username && <>
                <button className="btn py-0.5 text-xs" onClick={() => act.mutate({ path: `/nms/access/playbooks/runs/${r.id}/approve` })}>Approve</button>
                <button className="btn btn-danger py-0.5 text-xs" onClick={() => act.mutate({ path: `/nms/access/playbooks/runs/${r.id}/reject` })}>Reject</button></>}
              {["pending_approval", "queued", "running"].includes(r.status) && <button className="btn py-0.5 text-xs" onClick={() => act.mutate({ path: `/nms/access/playbooks/runs/${r.id}/cancel` })}>Cancel</button>}
            </td></tr>)}</tbody></table></TableWrap>}
    </Card>
    {edit && <PlaybookEditor pb={edit} canEdit={can("nms.automation.execute")} onClose={() => { setEdit(null); inv(); }} />}
    {runFor && <RunDialog pb={runFor} enabled={enabled} onClose={() => { setRunFor(null); inv(); }} />}
    {openRun != null && <RunOutput id={openRun} onClose={() => setOpenRun(null)} />}
  </>;
}

function PlaybookEditor({ pb, canEdit, onClose }: { pb: any; canEdit: boolean; onClose: () => void }) {
  const [f, setF] = useState({ name: pb.name, description: pb.description || "", content: pb.content || "" });
  const check = useMutation({ mutationFn: () => api<any>("/nms/access/playbooks/validate", { method: "POST", body: { content: f.content } }) });
  const save = useMutation({ mutationFn: () => api(pb.id ? `/nms/access/playbooks/${pb.id}` : "/nms/access/playbooks", { method: pb.id ? "PUT" : "POST", body: f }), onSuccess: onClose });
  return <Modal title={pb.id ? `Playbook ${pb.name}` : "New playbook"} onClose={onClose} wide>
    <div className="space-y-3">
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Name"><input className="input w-full" disabled={!canEdit} value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
        <Field label="Description"><input className="input w-full" disabled={!canEdit} value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></Field>
      </div>
      <Field label="Playbook (YAML; hosts: targets)" hint={pb.id ? "Saving a changed version clears its approval." : undefined}>
        <textarea className="input w-full h-80 font-mono text-xs" disabled={!canEdit} value={f.content} onChange={(e) => setF({ ...f, content: e.target.value })} /></Field>
      {check.data && (check.data.ok ? <p className="text-sm text-emerald-300">Accepted: {check.data.kind === "change" ? "change playbook" : "read-only"} ({check.data.modules.join(", ")})</p>
        : <ul className="text-sm text-red-300 list-disc ml-5">{check.data.errors.map((e: string, i: number) => <li key={i}>{e}</li>)}</ul>)}
      {save.error && <p role="alert" className="text-sm text-red-300">{(save.error as Error).message}</p>}
      {canEdit && <div className="flex gap-2"><button className="btn" onClick={() => check.mutate()}>Check policy</button>
        <button className="btn btn-primary" disabled={!f.name || save.isPending} onClick={() => save.mutate()}>Save as draft</button></div>}
    </div>
  </Modal>;
}

function RunDialog({ pb, enabled, onClose }: { pb: any; enabled: boolean; onClose: () => void }) {
  const devs = useQuery({ queryKey: ["access-devices-all"], queryFn: () => api<any>("/nms/access/devices", { params: { limit: 2000 } }) });
  const [sel, setSel] = useState<Set<number>>(new Set());
  const [mode, setMode] = useState(pb.kind === "change" ? "check" : "run");
  const start = useMutation({ mutationFn: () => api<any>(`/nms/access/playbooks/${pb.id}/runs`, { method: "POST", body: { device_ids: [...sel], mode } }), onSuccess: onClose });
  const items: any[] = (devs.data?.items || []).filter((x: any) => x.platform && x.host_key_pinned);
  return <Modal title={`Run ${pb.name}`} onClose={onClose} wide>
    <div className="space-y-3">
      {pb.kind === "change" && <div className="flex gap-3 text-sm"><label className="flex items-center gap-1"><input type="radio" checked={mode === "check"} onChange={() => setMode("check")} />Dry run (--check --diff)</label>
        <label className="flex items-center gap-1"><input type="radio" checked={mode === "run"} disabled={!enabled} onChange={() => setMode("run")} />Apply (needs a second person's approval)</label></div>}
      <p className="text-xs text-muted">Devices with a supported platform and a pinned SSH host key (connect once through Sentinel to pin it).</p>
      <TableWrap maxH="max-h-72"><table className="tbl"><tbody>{items.map((x) => <tr key={x.id}><td><input type="checkbox" aria-label={`Select ${x.name}`} checked={sel.has(x.id)}
        onChange={() => setSel((s) => { const n = new Set(s); n.has(x.id) ? n.delete(x.id) : n.add(x.id); return n; })} /></td><td>{x.name}</td><td className="text-xs">{x.platform_label}</td><td className="text-xs">{x.site}</td></tr>)}</tbody></table></TableWrap>
      {!items.length && devs.data && <Empty text="No device is ready for Ansible yet." />}
      {start.error && <p role="alert" className="text-sm text-red-300">{(start.error as Error).message}</p>}
      <button className="btn btn-primary" disabled={!sel.size || start.isPending} onClick={() => start.mutate()}>{mode === "check" ? "Start dry run" : pb.kind === "change" ? "Request change run" : "Run"} on {sel.size} device{sel.size === 1 ? "" : "s"}</button>
    </div>
  </Modal>;
}

function RunOutput({ id, onClose }: { id: number; onClose: () => void }) {
  const q = useQuery({ queryKey: ["access-pb-run", id], queryFn: () => api<any>(`/nms/access/playbooks/runs/${id}`),
    refetchInterval: (qq) => ["queued", "running"].includes(qq.state.data?.status) ? 2000 : false });
  const r = q.data;
  return <Modal title={r ? `Run #${r.id} — ${r.playbook}` : "Run"} onClose={onClose} wide>
    <Loading q={q} />
    {r && <div className="space-y-2 text-sm">
      <div><St s={r.status} /> {r.error && <span className="text-red-300 text-xs">{r.error}</span>}</div>
      {!!Object.keys(r.hosts || {}).length && <TableWrap><table className="tbl"><thead><tr><th>Host</th><th className="num">ok</th><th className="num">changed</th><th className="num">failed</th>
        <th className="num">unreachable</th><th>Note</th></tr></thead><tbody>{Object.entries(r.hosts).map(([h, v]: [string, any]) => <tr key={h}><td>{h}</td><td className="num">{v.ok ?? ""}</td>
          <td className="num">{v.changed ?? ""}</td><td className="num">{v.failed ?? ""}</td><td className="num">{v.unreachable ?? ""}</td><td className="text-xs">{v.skipped_reason || ""}</td></tr>)}</tbody></table></TableWrap>}
      {r.backups?.diffs && Object.entries(r.backups.diffs).map(([sid, d]: [string, any]) => <pre key={sid} className="text-xs font-mono bg-slate-950 p-2 rounded overflow-auto max-h-48">{d}</pre>)}
      <pre className="text-xs font-mono bg-slate-950 p-2 rounded overflow-auto max-h-[28rem] whitespace-pre-wrap">{r.output || "(no output yet)"}</pre>
    </div>}
  </Modal>;
}
