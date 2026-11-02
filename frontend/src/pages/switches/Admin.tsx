import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { Card, Empty, Modal, TableWrap, Time } from "../../components/ui";
import { MetricStatus, useSwitchMeta } from "./common";

const BLANK = { name: "", address: "", port: 161, credential_id: 0, site: "", building: "", floor: "", rack: "", role: "", notes: "", monitoring: "active",
  poll_interval_seconds: 60, timeout_ms: 3000, retries: 1, group_intervals: {} as Record<string, number>, thresholds: {} as Record<string, number> };

function useCreds() {
  return useQuery({ queryKey: ["switch-creds"], queryFn: () => api<any>("/switches/admin/credentials") });
}

function invalidate(qc: ReturnType<typeof useQueryClient>) {
  for (const k of ["switch-inv", "switch-overview", "switch-filters", "switch-detail", "switch-creds", "switch-nets", "switch-disc"]) qc.invalidateQueries({ queryKey: [k] });
}

export function AddSwitch() {
  const [open, setOpen] = useState(false);
  return <>{<button className="btn btn-primary" onClick={() => setOpen(true)}>+ Add switch</button>}{open && <SwitchForm sw={null} onClose={() => setOpen(false)} />}</>;
}

/** Create / edit a switch. "Test" probes the device (connectivity, credentials, vendor / model, supported metrics) without storing anything. */
export function SwitchForm({ sw, initial, onClose }: { sw: any | null; initial?: any; onClose: () => void }) {
  const qc = useQueryClient();
  const nav = useNavigate();
  const meta = useSwitchMeta();
  const creds = useCreds();
  const [f, setF] = useState<any>(() => ({ ...BLANK, ...(initial || {}), ...(sw || {}), credential_id: sw?.credential_id || initial?.credential_id || 0 }));
  const [gi, setGi] = useState<string>(JSON.stringify(sw?.group_intervals || {}));
  const [th, setTh] = useState<string>(JSON.stringify(sw?.thresholds || {}));
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.value });
  const inp = (k: string, l: string, p: any = {}) => <div><label className="label">{l}</label><input className="input w-full" value={f[k] ?? ""} onChange={set(k)} {...p} /></div>;
  const body = () => {
    let g = {}, t = {};
    try { g = JSON.parse(gi || "{}"); t = JSON.parse(th || "{}"); } catch { throw new Error("group intervals / thresholds must be JSON objects"); }
    return { ...Object.fromEntries(Object.keys(BLANK).map((k) => [k, f[k]])), port: Number(f.port), credential_id: Number(f.credential_id),
      poll_interval_seconds: Number(f.poll_interval_seconds), timeout_ms: Number(f.timeout_ms), retries: Number(f.retries), group_intervals: g, thresholds: t };
  };
  const wlc = String(f.role || "").toLowerCase() === "wlc";  // wireless controller: the test also scans the wireless MIBs
  const test = useMutation({ mutationFn: () => api<any>("/switches/test", { method: "POST", body: { address: f.address, port: Number(f.port), credential_id: Number(f.credential_id),
    timeout_ms: Number(f.timeout_ms), retries: Number(f.retries), full: true, wlc } }) });
  const save = useMutation({ mutationFn: () => api<any>(sw ? `/switches/${sw.id}` : "/switches", { method: sw ? "PUT" : "POST", body: body() }),
    onSuccess: (r) => { invalidate(qc); qc.invalidateQueries({ queryKey: ["wl"] }); onClose(); if (!sw) nav(wlc ? "/wireless?tab=controllers" : `/switches/${r.id}`); } });
  const del = useMutation({ mutationFn: () => api(`/switches/${sw.id}`, { method: "DELETE" }), onSuccess: () => { invalidate(qc); onClose(); nav("/switches?tab=inventory"); } });
  const t = test.data;
  return <Modal wide title={sw ? `Edit ${sw.name}` : wlc ? "Add a wireless controller (Catalyst 9800)" : "Add a switch"} onClose={onClose}>
    <div className="grid gap-2 sm:grid-cols-3">
      {inp("name", "Name", { placeholder: "WH1-ACC-SW01" })}{inp("address", "Management IP", { placeholder: "10.20.0.11" })}
      <div><label className="label">SNMP credential profile</label>
        <select className="input w-full" value={f.credential_id} onChange={(e) => setF({ ...f, credential_id: Number(e.target.value) })}>
          <option value={0}>— choose —</option>{(creds.data?.items || []).map((c: any) => <option key={c.id} value={c.id}>{c.name} ({c.version}{c.version === "v3" ? ` ${c.security_level}` : ""})</option>)}</select></div>
      {inp("site", "Site / warehouse")}{inp("building", "Building")}{inp("floor", "Floor")}{inp("rack", "Rack")}{inp("role", "Role", { placeholder: "access / distribution / core" })}
      {inp("port", "SNMP port", { type: "number", min: 1, max: 65535 })}{inp("poll_interval_seconds", "Poll every (seconds)", { type: "number", min: 30, max: 3600 })}
      {inp("timeout_ms", "SNMP timeout (ms)", { type: "number", min: 500, max: 15000 })}{inp("retries", "Retries", { type: "number", min: 0, max: 3 })}
      <div className="sm:col-span-3">{inp("notes", "Notes")}</div>
      <div className="sm:col-span-3 grid gap-2 sm:grid-cols-2">
        <div><label className="label">Group intervals (JSON, seconds; 0 disables) — groups: {(meta.data?.groups || []).filter((g: any) => g.key !== "system").map((g: any) => g.key).join(", ")}</label>
          <input className="input w-full font-mono text-xs" value={gi} onChange={(e) => setGi(e.target.value)} placeholder='{"mac_table": 1800, "routing": 0}' /></div>
        <div><label className="label">Alert threshold overrides (JSON) — e.g. cpu_pct, mem_pct, celsius, util_pct, min_errors</label>
          <input className="input w-full font-mono text-xs" value={th} onChange={(e) => setTh(e.target.value)} placeholder='{"util_pct": 80}' /></div>
      </div>
    </div>
    <p className="text-2xs text-muted mt-2">The address must be inside an authorised management network (Settings). Monitoring is read-only: the SIEM sends SNMP GET / GETNEXT / GETBULK
      only. Use an SNMPv3 user with authPriv bound to a read-only view.</p>
    {(save.error || del.error || test.error) && <div role="alert" className="text-sm text-red-400 mt-2">{((save.error || del.error || test.error) as Error).message}</div>}
    <div className="flex flex-wrap gap-2 mt-3">
      <button className="btn" disabled={!f.address || !f.credential_id || test.isPending} onClick={() => test.mutate()}>{test.isPending ? "Testing…" : "Test connection & detect metrics"}</button>
      <button className="btn btn-primary" disabled={!f.name || !f.address || !f.credential_id || save.isPending} onClick={() => save.mutate()}>{sw ? "Save" : "Add and start monitoring"}</button>
      {sw && <button className="btn btn-danger ml-auto" onClick={() => confirm(`Remove ${sw.name}? Its inventory, events and history are deleted.`) && del.mutate()}>Remove</button>}
    </div>
    {t && <div className="mt-4 space-y-3">
      {!t.ok ? <div role="alert" className="text-sm text-red-300">{t.stage}: {t.error}{t.hint && <div className="text-muted text-xs mt-1">{t.hint}</div>}</div> : <>
        <div className="text-sm">Answered in {t.duration_ms} ms ({t.requests} requests): <b>{t.identity.vendor}</b> {t.identity.model || t.identity.family} · {t.identity.os} {t.identity.firmware}
          {t.identity.serial && <> · serial <span className="font-mono">{t.identity.serial}</span></>} · <span className="text-muted">{t.system.sys_name}</span>
          {t.coverage.percent != null && <> · <b>{t.coverage.supported}</b> metrics supported, {t.coverage.counts.unsupported || 0} unsupported</>}</div>
        <div className="text-xs text-muted">Preview: {t.preview.interfaces} interfaces ({t.preview.interfaces_up} up, {t.preview.hc_counters} with 64-bit counters) · CPU {t.preview.cpu_pct ?? "—"}%
          · memory {t.preview.memory_pct ?? "—"}% · {t.preview.fans} fans · {t.preview.psus} PSUs · stack members {t.preview.stack_members} · PoE {t.preview.poe_used_w ?? "—"} / {t.preview.poe_budget_w ?? "—"} W
          · {t.preview.vlans} VLANs · {t.preview.macs} MACs (sample) · {t.preview.lags} LAGs · STP {t.preview.stp_mode || "—"}</div>
        {t.preview.aps != null && <div className="text-sm">Wireless: <b>{t.preview.aps}</b> APs · {t.preview.radios} radios · {t.preview.wlans} WLANs · {t.preview.clients} clients
          <span className="text-muted text-xs"> — only what this controller release returned; unsupported objects are listed below</span></div>}
        <TableWrap maxH="max-h-72"><table className="tbl"><thead><tr><th>Metric</th><th>Group</th><th>Status</th><th>Source</th><th className="w-full">Reason</th></tr></thead>
          <tbody>{t.capabilities.map((m: any) => <tr key={m.metric}><td className="font-mono text-xs">{m.metric}</td><td className="text-xs">{m.group}</td><td><MetricStatus s={m.status} /></td>
            <td className="text-xs">{m.source}</td><td className="text-xs text-muted">{m.reason}</td></tr>)}</tbody></table></TableWrap>
      </>}
    </div>}
  </Modal>;
}

export function SwitchSettings() {
  return <div className="space-y-4"><Networks /><Credentials /><Discovery /><ImportCsv /></div>;
}

function Networks() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["switch-nets"], queryFn: () => api<any>("/switches/admin/networks") });
  const [f, setF] = useState({ cidr: "", site: "", description: "", allow_discovery: false });
  const add = useMutation({ mutationFn: () => api("/switches/admin/networks", { method: "POST", body: f }), onSuccess: () => { setF({ cidr: "", site: "", description: "", allow_discovery: false }); invalidate(qc); } });
  const upd = useMutation({ mutationFn: (n: any) => api(`/switches/admin/networks/${n.id}`, { method: "PUT", body: n }), onSuccess: () => invalidate(qc) });
  const del = useMutation({ mutationFn: (id: number) => api(`/switches/admin/networks/${id}`, { method: "DELETE" }), onSuccess: () => invalidate(qc) });
  return <Card title="Authorised management networks" right={<span className="text-2xs text-muted">switches can only be added, polled and discovered inside these networks</span>}>
    <div className="flex flex-wrap gap-2 mb-3">
      <input aria-label="CIDR" className="input py-1 w-44" placeholder="10.20.0.0/24" value={f.cidr} onChange={(e) => setF({ ...f, cidr: e.target.value })} />
      <input aria-label="Site" className="input py-1 w-40" placeholder="Site" value={f.site} onChange={(e) => setF({ ...f, site: e.target.value })} />
      <input aria-label="Description" className="input py-1 flex-1 min-w-[12rem]" placeholder="Description" value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} />
      <label className="text-xs flex items-center gap-1"><input type="checkbox" checked={f.allow_discovery} onChange={(e) => setF({ ...f, allow_discovery: e.target.checked })} /> allow discovery</label>
      <button className="btn btn-primary" disabled={!f.cidr || add.isPending} onClick={() => add.mutate()}>Authorise network</button>
    </div>
    {(add.error || del.error || upd.error) && <div role="alert" className="text-sm text-red-400 mb-2">{((add.error || del.error || upd.error) as Error).message}</div>}
    {!q.data?.items.length ? <Empty text="No networks authorised yet." /> :
      <TableWrap><table className="tbl"><thead><tr><th>Network</th><th>Site</th><th>Description</th><th className="num">Switches</th><th>Discovery</th><th>Added</th><th /></tr></thead>
        <tbody>{q.data.items.map((n: any) => <tr key={n.id}><td className="font-mono">{n.cidr}</td><td>{n.site || "—"}</td><td className="text-xs">{n.description}</td>
          <td className="num">{n.switches}</td>
          <td><label className="text-xs flex items-center gap-1"><input type="checkbox" checked={n.allow_discovery} onChange={(e) => upd.mutate({ ...n, allow_discovery: e.target.checked })} /> allowed</label></td>
          <td className="text-xs">{n.created_by} · <Time v={n.created_at} /></td>
          <td><button className="btn" onClick={() => confirm(`Remove ${n.cidr} from the authorised networks?`) && del.mutate(n.id)}>Remove</button></td></tr>)}</tbody></table></TableWrap>}
  </Card>;
}

const CBLANK = { name: "", version: "v3", username: "", auth_protocol: "sha", priv_protocol: "aes128", auth_key: "", priv_key: "", community: "", description: "" };

function Credentials() {
  const qc = useQueryClient();
  const meta = useSwitchMeta();
  const q = useCreds();
  const [edit, setEdit] = useState<any>(null);
  return <Card title="SNMP credential profiles" right={<button className="btn" onClick={() => setEdit({ ...CBLANK })}>+ New profile</button>}>
    <p className="text-2xs text-muted mb-2">Passphrases and communities are encrypted at rest and are never shown again. SNMPv2c is {meta.data?.snmpv2c_allowed ? "allowed by the server configuration" :
      "disabled (SWITCH_ALLOW_SNMPV2C=false): it sends the community in clear text"}.</p>
    {!q.data?.items.length ? <Empty text="No credential profiles yet." /> :
      <TableWrap><table className="tbl"><thead><tr><th>Name</th><th>Version</th><th>User</th><th>Security</th><th>Auth / priv</th><th className="num">Used by</th><th>Updated</th><th /></tr></thead>
        <tbody>{q.data.items.map((c: any) => <tr key={c.id}><td className="font-medium">{c.name}<div className="text-2xs text-muted">{c.description}</div></td><td>{c.version}</td>
          <td className="font-mono text-xs">{c.username || "—"}</td><td className={c.security_level === "authPriv" ? "text-emerald-300" : "text-amber-300"}>{c.security_level}</td>
          <td className="text-xs">{c.version === "v3" ? `${c.auth_protocol} / ${c.priv_protocol}` : "community"}</td><td className="num">{c.used_by}</td><td><Time v={c.updated_at} /></td>
          <td><button className="btn" onClick={() => setEdit({ ...CBLANK, ...c })}>Edit</button></td></tr>)}</tbody></table></TableWrap>}
    {edit && <CredentialForm c={edit} authProtocols={meta.data?.auth_protocols || []} privProtocols={meta.data?.priv_protocols || []}
      onClose={() => { setEdit(null); invalidate(qc); }} />}
  </Card>;
}

function CredentialForm({ c, authProtocols, privProtocols, onClose }: { c: any; authProtocols: string[]; privProtocols: string[]; onClose: () => void }) {
  const [f, setF] = useState<any>({ ...c, auth_key: "", priv_key: "", community: "" });
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.value });
  const body = () => ({ name: f.name, version: f.version, username: f.username, auth_protocol: f.auth_protocol, priv_protocol: f.priv_protocol, description: f.description,
    auth_key: f.auth_key || null, priv_key: f.priv_key || null, community: f.community || null });
  const save = useMutation({ mutationFn: () => api(c.id ? `/switches/admin/credentials/${c.id}` : "/switches/admin/credentials", { method: c.id ? "PUT" : "POST", body: body() }), onSuccess: onClose });
  const del = useMutation({ mutationFn: () => api(`/switches/admin/credentials/${c.id}`, { method: "DELETE" }), onSuccess: onClose });
  const keep = c.id ? "leave empty to keep the stored value" : "";
  return <Modal title={c.id ? `Edit ${c.name}` : "New SNMP credential profile"} onClose={onClose}>
    <div className="grid gap-2 sm:grid-cols-2">
      <div><label className="label">Name</label><input className="input w-full" value={f.name} onChange={set("name")} /></div>
      <div><label className="label">SNMP version</label><select className="input w-full" value={f.version} onChange={set("version")}><option value="v3">SNMPv3 (recommended)</option><option value="v2c">SNMPv2c</option></select></div>
      {f.version === "v3" ? <>
        <div><label className="label">User name</label><input className="input w-full" autoComplete="off" value={f.username} onChange={set("username")} /></div>
        <div />
        <div><label className="label">Authentication protocol</label><select className="input w-full" value={f.auth_protocol} onChange={set("auth_protocol")}>{authProtocols.map((p) => <option key={p}>{p}</option>)}</select></div>
        <div><label className="label">Authentication passphrase {keep && <span className="text-muted">({keep})</span>}</label><input type="password" autoComplete="new-password" className="input w-full" value={f.auth_key} onChange={set("auth_key")} /></div>
        <div><label className="label">Privacy protocol</label><select className="input w-full" value={f.priv_protocol} onChange={set("priv_protocol")}>{privProtocols.map((p) => <option key={p}>{p}</option>)}</select></div>
        <div><label className="label">Privacy passphrase {keep && <span className="text-muted">({keep})</span>}</label><input type="password" autoComplete="new-password" className="input w-full" value={f.priv_key} onChange={set("priv_key")} /></div>
      </> : <div className="sm:col-span-2"><label className="label">Community {keep && <span className="text-muted">({keep})</span>}</label>
        <input type="password" autoComplete="new-password" className="input w-full" value={f.community} onChange={set("community")} /></div>}
      <div className="sm:col-span-2"><label className="label">Description</label><input className="input w-full" value={f.description} onChange={set("description")} /></div>
    </div>
    <p className="text-2xs text-muted mt-2">Use a read-only view: e.g. Cisco <code>snmp-server group SIEM v3 priv read SIEM-RO</code> (+ <code>context vlan- match prefix</code> for per-VLAN MAC / STP);
      Ruckus <code>snmp-server user siem-ro &lt;group&gt; v3 auth sha … priv aes …</code> with a read-only group.</p>
    {(save.error || del.error) && <div role="alert" className="text-sm text-red-400 mt-2">{((save.error || del.error) as Error).message}</div>}
    <div className="flex gap-2 mt-3"><button className="btn btn-primary" disabled={!f.name || save.isPending} onClick={() => save.mutate()}>Save</button>
      {c.id && <button className="btn btn-danger ml-auto" onClick={() => confirm(`Delete ${c.name}?`) && del.mutate()}>Delete</button>}</div>
  </Modal>;
}

function Discovery() {
  const qc = useQueryClient();
  const nets = useQuery({ queryKey: ["switch-nets"], queryFn: () => api<any>("/switches/admin/networks") });
  const creds = useCreds();
  const runs = useQuery({ queryKey: ["switch-disc"], queryFn: () => api<any>("/switches/admin/discovery"), refetchInterval: (q) => (q.state.data?.items || []).some((r: any) => ["queued", "running"].includes(r.status)) ? 3000 : false });
  const [f, setF] = useState({ network_id: 0, credential_id: 0 });
  const [add, setAdd] = useState<any>(null);
  const start = useMutation({ mutationFn: () => api("/switches/admin/discovery", { method: "POST", body: f }), onSuccess: () => invalidate(qc) });
  const allowed = (nets.data?.items || []).filter((n: any) => n.allow_discovery);
  const last = runs.data?.items?.[0];
  return <Card title="Discovery">
    <p className="text-2xs text-muted mb-2">Sweeps one authorised network that allows discovery: a single SNMP GET (sysDescr / sysObjectID / sysName) per address, 1 s timeout, no retries, bounded concurrency.
      Nothing is added automatically.</p>
    <div className="flex flex-wrap gap-2 mb-3">
      <select aria-label="Network" className="input py-1" value={f.network_id} onChange={(e) => setF({ ...f, network_id: Number(e.target.value) })}>
        <option value={0}>— network —</option>{allowed.map((n: any) => <option key={n.id} value={n.id}>{n.cidr} {n.site && `(${n.site})`}</option>)}</select>
      <select aria-label="Credential" className="input py-1" value={f.credential_id} onChange={(e) => setF({ ...f, credential_id: Number(e.target.value) })}>
        <option value={0}>— credential profile —</option>{(creds.data?.items || []).map((c: any) => <option key={c.id} value={c.id}>{c.name}</option>)}</select>
      <button className="btn btn-primary" disabled={!f.network_id || !f.credential_id || start.isPending} onClick={() => start.mutate()}>Start discovery</button>
      {!allowed.length && <span className="text-xs text-muted self-center">Enable "allow discovery" on a network first.</span>}
    </div>
    {start.error && <div role="alert" className="text-sm text-red-400 mb-2">{(start.error as Error).message}</div>}
    {last && <div className="space-y-2">
      <div className="text-sm">Last run: <span className="font-mono">{last.cidr}</span> · {last.status} · scanned {last.scanned} · found {last.found} · by {last.requested_by} · <Time v={last.finished_at || last.created_at} />
        {last.error && <span className="text-red-300"> · {last.error}</span>}</div>
      {!!last.results?.length && <TableWrap maxH="max-h-80"><table className="tbl"><thead><tr><th>Address</th><th>Status</th><th>sysName</th><th>Vendor</th><th>Model</th><th>Firmware</th><th /></tr></thead>
        <tbody>{last.results.map((r: any) => <tr key={r.address}><td className="font-mono">{r.address}</td><td className={r.status === "found" ? "" : "text-amber-300"}>{r.status}</td>
          <td>{r.sys_name || "—"}</td><td>{r.vendor || "—"}</td><td>{r.model || "—"}</td><td className="text-xs">{r.firmware || "—"}</td>
          <td>{r.already_monitored ? <span className="text-2xs text-muted">monitored</span> : r.status === "found" &&
            <button className="btn" onClick={() => setAdd({ name: r.sys_name || r.address, address: r.address, credential_id: last.credential_id })}>Add</button>}</td></tr>)}</tbody></table></TableWrap>}
    </div>}
    {add && <SwitchForm sw={null} initial={add} onClose={() => setAdd(null)} key={add.address} />}
  </Card>;
}

function ImportCsv() {
  const qc = useQueryClient();
  const [text, setText] = useState("name,address,credential,site,building,floor,rack,role\n");
  const run = useMutation({ mutationFn: (dry: boolean) => api<any>("/switches/import", { method: "POST", body: { csv: text, dry_run: dry } }), onSuccess: () => invalidate(qc) });
  const r = run.data;
  return <Card title="Bulk import (CSV)">
    <p className="text-2xs text-muted mb-2">Columns: <code>name,address,credential</code> (profile name) and optionally <code>site,building,floor,rack,role,port,poll_interval_seconds,notes</code>.
      Validate first; the import is all-or-nothing.</p>
    <textarea aria-label="CSV" className="input w-full font-mono text-xs h-32" value={text} onChange={(e) => setText(e.target.value)} />
    <div className="flex gap-2 mt-2"><button className="btn" disabled={run.isPending} onClick={() => run.mutate(true)}>Validate</button>
      <button className="btn btn-primary" disabled={run.isPending || !r || r.invalid > 0 || !r.dry_run} onClick={() => run.mutate(false)}>Import {r?.valid || ""} switches</button></div>
    {run.error && <div role="alert" className="text-sm text-red-400 mt-2">{(run.error as Error).message}</div>}
    {r && <div className="mt-2 text-sm">{r.dry_run ? `${r.valid} valid, ${r.invalid} invalid` : `${r.created} created`} {r.note}
      {!!r.invalid && <TableWrap maxH="max-h-60"><table className="tbl"><thead><tr><th className="num">Line</th><th>Name</th><th>Address</th><th className="w-full">Problem</th></tr></thead>
        <tbody>{r.rows.filter((x: any) => x.errors.length).map((x: any) => <tr key={x.line}><td className="num">{x.line}</td><td>{x.name}</td><td className="font-mono text-xs">{x.address}</td>
          <td className="text-xs text-red-300">{x.errors.join("; ")}</td></tr>)}</tbody></table></TableWrap>}</div>}
  </Card>;
}
