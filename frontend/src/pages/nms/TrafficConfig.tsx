/** Application & Protocol Intelligence: detections (acknowledge / assign / resolve / suppress), detection rules and
 *  thresholds, custom watch rules, signature registry, VLAN policies, network ranges and settings, collectors. Controls
 *  appear only with the matching permission; the API enforces the same permissions. */
import { Fragment, ReactNode, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { fmtBytes, fmtNum } from "../../lib/format";
import { useMe } from "../../lib/context";
import { Card, Drawer, Empty, Field, Loading, Pager, Sev, TableWrap, Tabs, Time, rowProps } from "../../components/ui";
import { Conf, ExportLink, Nav } from "./Traffic";
import { paramText, parseParam } from "./traffic/model";

const SEVS = ["critical", "high", "medium", "low", "informational"];
const PAGE = 50;

function Err({ e }: { e: unknown }) {
  return e ? <p role="alert" className="text-xs text-red-400">{(e as Error).message}</p> : null;
}

// ------------------------------------------------------------------ detections
export function DetectionsTab({ nav }: { nav: Nav }) {
  const [status, setStatus] = useState("open");
  const [severity, setSeverity] = useState("");
  const [rule, setRule] = useState("");
  const [page, setPage] = useState(1);
  const [sel, setSel] = useState<any>(null);
  const range = ["5m", "15m", "1h", "6h", "24h"].includes(nav.f.range || "") ? "24h" : nav.f.range === "30d" ? "30d" : "7d";
  const params: Record<string, any> = { range, limit: PAGE, offset: (page - 1) * PAGE, rule: rule || undefined, ip: nav.f.ip || undefined,
    status: status === "open" ? ["new", "investigating"] : status ? [status] : undefined, severity: severity ? [severity] : undefined };
  const q = useQuery<any>({ queryKey: ["traffic-det", params], queryFn: () => api("/nms/traffic/detections", { params }), placeholderData: (p: any) => p, refetchInterval: 60_000 });
  const rules = useQuery<any[]>({ queryKey: ["traffic-det-rules"], queryFn: () => api("/nms/traffic/detection-rules") });
  return <Card bodyClass="p-0" title="Traffic security detections" right={<div className="flex flex-wrap gap-2 items-center">
    <select aria-label="Status" className="input py-0.5 text-xs" value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }}>
      <option value="open">Open</option><option value="new">New</option><option value="investigating">Acknowledged</option><option value="resolved">Resolved</option>
      <option value="suppressed">Suppressed</option><option value="">All</option></select>
    <select aria-label="Severity" className="input py-0.5 text-xs" value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }}>
      <option value="">Any severity</option>{SEVS.map((s) => <option key={s}>{s}</option>)}</select>
    <select aria-label="Rule" className="input py-0.5 text-xs" value={rule} onChange={(e) => { setRule(e.target.value); setPage(1); }}>
      <option value="">All rules</option>{(rules.data || []).map((r) => <option key={r.key} value={r.key}>{r.name}</option>)}</select>
    <ExportLink view="detections" f={nav.f} nav={nav} /></div>}>
    <Loading q={q} />
    {q.data && <div className="flex flex-wrap gap-3 px-3 py-2 text-xs">{SEVS.map((s) => <span key={s}><Sev s={s} /> {q.data.open_by_severity[s] || 0} open</span>)}</div>}
    {q.data && (!q.data.items.length ? <Empty text="No detections match. Rules aggregate flows per window, so a quiet list is normal." /> : <TableWrap maxH="max-h-[40rem]"><table className="tbl"><thead><tr>
      <th>Severity</th><th>Detection</th><th>Source</th><th>Destination</th><th>Evidence</th><th className="num">Events</th><th>Status</th><th>Owner</th><th>Last seen</th></tr></thead>
      <tbody>{q.data.items.map((d: any) => <tr key={d.id} {...rowProps(() => setSel(d))}>
        <td><Sev s={d.severity} /></td><td className="text-xs"><b>{d.name}</b><span className="block text-muted max-w-[28rem] truncate" title={d.explanation}>{d.explanation}</span></td>
        <td className="font-mono text-xs">{d.src_ip || "—"}</td><td className="font-mono text-xs">{d.dst_ip || "—"}</td><td><Conf c={d.confidence} /></td>
        <td className="num">{fmtNum(d.event_count)}</td><td className="text-xs">{d.status === "investigating" ? "acknowledged" : d.status}</td><td className="text-xs">{d.assignee || "—"}</td>
        <td className="text-xs"><Time v={d.last_seen} /></td></tr>)}</tbody></table></TableWrap>)}
    {q.data && <Pager page={page} size={PAGE} total={q.data.total} onPage={setPage} />}
    {sel && <DetectionDrawer d={sel} nav={nav} onClose={() => setSel(null)} />}
  </Card>;
}

function DetectionDrawer({ d, nav, onClose }: { d: any; nav: Nav; onClose: () => void }) {
  const me = useMe();
  const qc = useQueryClient();
  const [notes, setNotes] = useState(d.notes || "");
  const done = () => { qc.invalidateQueries({ queryKey: ["traffic-det"] }); onClose(); };
  const upd = useMutation({ mutationFn: (body: any) => api(`/nms/traffic/detections/${d.id}`, { method: "PATCH", body }), onSuccess: done });
  const esc = useMutation({ mutationFn: () => api<any>(`/incidents/from-alert/${d.id}`, { method: "POST", body: { note: "Escalated from Sentinel NMS traffic detection." } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["traffic-det"] }) });
  const sup = useMutation({ mutationFn: (hours: number) => api(`/nms/traffic/detections/${d.id}/suppress`, { method: "POST", body: { hours, scope: "group" } }), onSuccess: done });
  const ev = d.evidence || {};
  const shown = Object.entries(ev).filter(([k]) => !["rule", "troubleshooting"].includes(k));
  return <Drawer title={d.name} onClose={onClose}>
    <div className="space-y-3 text-xs">
      <p><Sev s={d.severity} /> {d.explanation}</p>
      <dl className="grid grid-cols-[8rem_1fr] gap-y-1">
        {shown.map(([k, v]) => <Fragment key={k}><dt className="text-muted">{k.replace(/_/g, " ")}</dt>
          <dd className="break-all">{k === "bytes" ? fmtBytes(v as number) : typeof v === "object" ? JSON.stringify(v) : String(v)}</dd></Fragment>)}
        <dt className="text-muted">first / last</dt><dd><Time v={d.first_seen} /> → <Time v={d.last_seen} /></dd>
        <dt className="text-muted">rule</dt><dd className="font-mono">{d.rule_key}</dd>
      </dl>
      {ev.troubleshooting?.length > 0 && <div><h3 className="font-semibold">Next steps</h3><ul className="list-disc pl-5">{ev.troubleshooting.map((t: string) => <li key={t}>{t}</li>)}</ul></div>}
      <Field label="Resolution notes"><textarea className="input w-full h-20" value={notes} onChange={(e) => setNotes(e.target.value)} /></Field>
      <div className="flex flex-wrap gap-2">
        <button type="button" className="btn" disabled={upd.isPending} onClick={() => upd.mutate({ status: "investigating", assignee: d.assignee || me.username, notes })}>Acknowledge</button>
        <button type="button" className="btn" disabled={upd.isPending} onClick={() => upd.mutate({ assignee: me.username, notes })}>Assign to me</button>
        <button type="button" className="btn btn-primary" disabled={upd.isPending} onClick={() => upd.mutate({ status: "resolved", notes })}>Resolve</button>
        {nav.opts?.permissions.rules && <button type="button" className="btn" disabled={sup.isPending} onClick={() => sup.mutate(24)}>Suppress 24 h</button>}
        {d.filter && Object.keys(d.filter).length > 0 && <button type="button" className="btn" onClick={() => { nav.go({ ...d.filter, tab: "conversations", range: "24h" }); onClose(); }}>View traffic</button>}
        {(d.incident_id || esc.data?.id) ? <a className="btn" href={`/incidents/${d.incident_id || esc.data.id}`}>Incident #{d.incident_id || esc.data.id}</a>
          : me.products.includes("grid") && <button type="button" className="btn" disabled={esc.isPending} onClick={() => esc.mutate()}>Open security incident</button>}
      </div>
      <Err e={upd.error || sup.error || esc.error} />
    </div>
  </Drawer>;
}

// ------------------------------------------------------------------ rules, signatures, VLAN policies
export function RulesTab({ nav }: { nav: Nav }) {
  const [sub, setSub] = useState("detection");
  return <div className="space-y-3">
    <Tabs value={sub} onChange={setSub} tabs={[{ key: "detection", label: "Detection rules" }, { key: "custom", label: "Custom watch rules" },
      { key: "signatures", label: "Signature registry" }, { key: "policies", label: "VLAN / zone policies" }]} />
    {sub === "detection" && <DetectionRules can={!!nav.opts?.permissions.rules} />}
    {sub === "custom" && <WatchRules can={!!nav.opts?.permissions.rules} />}
    {sub === "signatures" && <Signatures can={!!nav.opts?.permissions.rules} />}
    {sub === "policies" && <Policies can={!!nav.opts?.permissions.rules} zones={nav.opts?.zones || []} />}
  </div>;
}

function DetectionRules({ can }: { can: boolean }) {
  const q = useQuery<any[]>({ queryKey: ["traffic-det-rules"], queryFn: () => api("/nms/traffic/detection-rules") });
  return <Card bodyClass="p-0" title="Detection rules"><Loading q={q} />
    {q.data && <div className="divide-y divide-line">{q.data.map((r) => <DetectionRule key={r.key} r={r} can={can} />)}</div>}
    <p className="text-2xs text-muted px-3 py-2">Thresholds apply to what the telemetry shows: with sampling, distinct ports / hosts are lower bounds and volumes are estimates.</p></Card>;
}

function DetectionRule({ r, can }: { r: any; can: boolean }) {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [vals, setVals] = useState<Record<string, string>>(Object.fromEntries(Object.entries(r.params).filter(([k]) => !k.startsWith("_")).map(([k, v]) => [k, paramText(v)])));
  const [sev, setSev] = useState(r.severity);
  const save = useMutation({ mutationFn: (body: any) => api(`/nms/traffic/detection-rules/${r.key}`, { method: "PUT", body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["traffic-det-rules"] }) });
  const submit = () => {
    const params: Record<string, unknown> = {};
    for (const [k, t] of Object.entries(vals)) {
      const v = parseParam(r.defaults[k] ?? r.params[k], t);
      if (v === null) { save.reset(); alert(`${k}: not a whole number`); return; }
      params[k] = v;
    }
    save.mutate({ params, severity: sev });
  };
  return <div className="p-3">
    <div className="flex flex-wrap items-center gap-2">
      <b className="text-sm flex-1">{r.name}</b><Sev s={r.severity} />
      <label className="text-xs inline-flex items-center gap-1"><input type="checkbox" checked={r.enabled} disabled={!can || save.isPending}
        onChange={(e) => save.mutate({ enabled: e.target.checked })} />enabled</label>
      <button type="button" className="link text-xs" onClick={() => setOpen(!open)}>{open ? "Hide" : can ? "Thresholds" : "Details"}</button>
    </div>
    <p className="text-xs text-muted">{r.description}</p>
    {open && <div className="grid gap-2 sm:grid-cols-3 mt-2">
      <Field label="Severity"><select className="input w-full" disabled={!can} value={sev} onChange={(e) => setSev(e.target.value)}>{SEVS.map((s) => <option key={s}>{s}</option>)}</select></Field>
      {Object.keys(vals).map((k) => <Field key={k} label={k.replace(/_/g, " ")} hint={Array.isArray(r.defaults[k]) ? "comma-separated" : undefined}>
        {typeof r.defaults[k] === "boolean" ? <select className="input w-full" disabled={!can} value={vals[k]} onChange={(e) => setVals({ ...vals, [k]: e.target.value })}>
          <option value="true">yes</option><option value="false">no</option></select>
          : <input className="input w-full" disabled={!can} value={vals[k]} onChange={(e) => setVals({ ...vals, [k]: e.target.value })} />}</Field>)}
      {can && <div className="sm:col-span-3"><button type="button" className="btn btn-primary" disabled={save.isPending} onClick={submit}>Save</button></div>}
      <div className="sm:col-span-3"><Err e={save.error} /></div>
    </div>}
  </div>;
}

const EMPTY_RULE = { name: "", description: "", enabled: true, severity: "medium", proto: "", ports: "", src_cidrs: "", dst_cidrs: "", exclude_cidrs: "", direction: "any", min_bytes: "0", window_minutes: "15" };

function WatchRules({ can }: { can: boolean }) {
  const qc = useQueryClient();
  const q = useQuery<any[]>({ queryKey: ["traffic-watch"], queryFn: () => api("/nms/traffic/rules") });
  const [form, setForm] = useState<any>(null);
  const list = (s: string) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
  const save = useMutation({ mutationFn: (f: any) => {
    const body = { ...f, proto: f.proto === "" ? null : Number(f.proto), ports: list(f.ports).map(Number), src_cidrs: list(f.src_cidrs), dst_cidrs: list(f.dst_cidrs),
      exclude_cidrs: list(f.exclude_cidrs), min_bytes: Number(f.min_bytes || 0), window_minutes: Number(f.window_minutes || 15) };
    delete body.id;
    return f.id ? api(`/nms/traffic/rules/${f.id}`, { method: "PUT", body }) : api("/nms/traffic/rules", { method: "POST", body });
  }, onSuccess: () => { qc.invalidateQueries({ queryKey: ["traffic-watch"] }); setForm(null); } });
  const del = useMutation({ mutationFn: (id: number) => api(`/nms/traffic/rules/${id}`, { method: "DELETE" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["traffic-watch"] }) });
  return <Card bodyClass="p-0" title="Custom watch rules" right={can && <button type="button" className="btn py-0.5 text-xs" onClick={() => setForm({ ...EMPTY_RULE })}>Add rule</button>}>
    <Loading q={q} />{q.data && (!q.data.length ? <Empty text="No custom rules. A rule matches protocol / ports / networks / direction above a volume and raises a 'Custom traffic rule' detection." /> :
      <TableWrap><table className="tbl"><thead><tr><th>Name</th><th>Match</th><th>Direction</th><th className="num">Min volume</th><th>Window</th><th>Severity</th><th>Enabled</th><th /></tr></thead>
        <tbody>{q.data.map((r) => <tr key={r.id}><td className="text-xs">{r.name}</td>
          <td className="text-2xs font-mono">{[r.proto != null && `proto ${r.proto}`, r.ports.length && `ports ${r.ports.join(",")}`, r.src_cidrs.length && `src ${r.src_cidrs.join(",")}`,
            r.dst_cidrs.length && `dst ${r.dst_cidrs.join(",")}`].filter(Boolean).join(" · ") || "any"}</td>
          <td className="text-xs">{r.direction}</td><td className="num">{fmtBytes(r.min_bytes)}</td><td className="text-xs">{r.window_minutes} min</td><td><Sev s={r.severity} /></td>
          <td className="text-xs">{r.enabled ? "yes" : "no"}</td>
          <td>{can && <><button type="button" className="link text-xs" onClick={() => setForm({ ...r, proto: r.proto ?? "", ports: r.ports.join(", "), src_cidrs: r.src_cidrs.join(", "),
            dst_cidrs: r.dst_cidrs.join(", "), exclude_cidrs: r.exclude_cidrs.join(", "), min_bytes: String(r.min_bytes), window_minutes: String(r.window_minutes) })}>Edit</button>
            <button type="button" className="link text-xs ml-2 text-red-300" onClick={() => confirm(`Delete rule ${r.name}?`) && del.mutate(r.id)}>Delete</button></>}</td></tr>)}</tbody></table></TableWrap>)}
    {form && <Drawer title={form.id ? `Edit ${form.name}` : "New watch rule"} onClose={() => setForm(null)}>
      <div className="grid gap-2">
        {([["name", "Name"], ["description", "Description"], ["proto", "IP protocol number (6 TCP, 17 UDP; empty = any)"], ["ports", "Service ports"], ["src_cidrs", "Source networks"],
          ["dst_cidrs", "Destination networks"], ["exclude_cidrs", "Excluded networks"], ["min_bytes", "Minimum bytes in the window"], ["window_minutes", "Window (minutes)"]] as [string, string][])
          .map(([k, l]) => <Field key={k} label={l}><input className="input w-full" value={form[k]} onChange={(e) => setForm({ ...form, [k]: e.target.value })} /></Field>)}
        <Field label="Direction"><select className="input w-full" value={form.direction} onChange={(e) => setForm({ ...form, direction: e.target.value })}>
          {["any", "outbound", "inbound", "east_west", "transit"].map((x) => <option key={x}>{x}</option>)}</select></Field>
        <Field label="Severity"><select className="input w-full" value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>{SEVS.map((s) => <option key={s}>{s}</option>)}</select></Field>
        <label className="text-xs inline-flex gap-1 items-center"><input type="checkbox" checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />enabled</label>
        <button type="button" className="btn btn-primary" disabled={save.isPending || !form.name} onClick={() => save.mutate(form)}>Save</button><Err e={save.error} />
      </div></Drawer>}
  </Card>;
}

function Signatures({ can }: { can: boolean }) {
  const qc = useQueryClient();
  const [kind, setKind] = useState("port");
  const [page, setPage] = useState(1);
  const q = useQuery<any[]>({ queryKey: ["traffic-sigs", kind], queryFn: () => api("/nms/traffic/signatures", { params: { kind } }) });
  const [form, setForm] = useState<any>(null);
  const save = useMutation({ mutationFn: (f: any) => {
    const body = { kind: f.kind, app: f.app, category: f.category, description: f.description, enabled: f.enabled, ambiguous: f.ambiguous,
      encrypted: f.encrypted === "" ? null : f.encrypted === "true", match: f.match || "", proto: f.proto === "" ? null : Number(f.proto),
      port_from: f.port_from === "" ? null : Number(f.port_from), port_to: f.port_to === "" ? null : Number(f.port_to) };
    return f.id ? api(`/nms/traffic/signatures/${f.id}`, { method: "PUT", body }) : api("/nms/traffic/signatures", { method: "POST", body });
  }, onSuccess: () => { qc.invalidateQueries({ queryKey: ["traffic-sigs"] }); setForm(null); } });
  const del = useMutation({ mutationFn: (id: number) => api(`/nms/traffic/signatures/${id}`, { method: "DELETE" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["traffic-sigs"] }) });
  const rows = (q.data || []).slice((page - 1) * PAGE, page * PAGE);
  const edit = (r: any) => setForm({ ...r, proto: r.proto ?? "", port_from: r.port_from ?? "", port_to: r.port_to ?? "", encrypted: r.encrypted === null || r.encrypted === undefined ? "" : String(r.encrypted) });
  return <Card bodyClass="p-0" title="Signature registry" right={<div className="flex gap-2 items-center">
    <select aria-label="Kind" className="input py-0.5 text-xs" value={kind} onChange={(e) => { setKind(e.target.value); setPage(1); }}>
      <option value="port">Protocol / port</option><option value="asn">ASN provider</option><option value="domain">Domain</option></select>
    {can && <button type="button" className="btn py-0.5 text-xs" onClick={() => edit({ kind, app: "", category: "other", description: "", enabled: true, ambiguous: false, match: "", proto: 6, port_from: "", port_to: null, encrypted: null })}>Add</button>}</div>}>
    <Loading q={q} />
    {q.data && <TableWrap maxH="max-h-[36rem]"><table className="tbl"><thead><tr><th>Match</th><th>Application</th><th>Category</th><th>Encrypted</th><th>Origin</th><th>Enabled</th><th /></tr></thead>
      <tbody>{rows.map((r) => <tr key={r.id}><td className="font-mono text-xs">{r.kind === "port" ? (r.port_from == null ? `IP proto ${r.proto}` : `${r.proto === 6 ? "TCP" : r.proto === 17 ? "UDP" : r.proto}/${r.port_from}${r.port_to !== r.port_from ? `-${r.port_to}` : ""}`) : r.match}</td>
        <td className="text-xs">{r.label}</td><td className="text-xs">{r.category}</td><td className="text-xs">{r.encrypted === true ? "yes" : r.encrypted === false ? "no" : "depends"}</td>
        <td className="text-2xs text-muted">{r.builtin_key ? "built-in" : `added by ${r.updated_by}`}</td><td className="text-xs">{r.enabled ? "yes" : "no"}</td>
        <td>{can && <><button type="button" className="link text-xs" onClick={() => edit(r)}>Edit</button>
          <button type="button" className="link text-xs ml-2 text-red-300" onClick={() => confirm(`Delete signature ${r.label}?`) && del.mutate(r.id)}>Delete</button></>}</td></tr>)}</tbody></table></TableWrap>}
    {q.data && <Pager page={page} size={PAGE} total={q.data.length} onPage={setPage} />}
    <p className="text-2xs text-muted px-3 pb-2">Changes take effect within 30 seconds. Port signatures are port-based evidence; ASN rows identify a provider, never a product; domain rows need DNS logs.</p>
    {form && <Drawer title={form.id ? `Edit ${form.app}` : "New signature"} onClose={() => setForm(null)}>
      <div className="grid gap-2">
        {form.kind === "port" ? <>
          <Field label="IP protocol number"><input className="input w-full" value={form.proto} onChange={(e) => setForm({ ...form, proto: e.target.value })} /></Field>
          <Field label="Port from (empty: protocol only)"><input className="input w-full" value={form.port_from} onChange={(e) => setForm({ ...form, port_from: e.target.value })} /></Field>
          <Field label="Port to (empty: single port)"><input className="input w-full" value={form.port_to ?? ""} onChange={(e) => setForm({ ...form, port_to: e.target.value })} /></Field>
          <label className="text-xs inline-flex gap-1 items-center"><input type="checkbox" checked={form.ambiguous} onChange={(e) => setForm({ ...form, ambiguous: e.target.checked })} />
            ambiguous (several applications use this port: labelled "possible")</label>
        </> : <Field label={form.kind === "asn" ? "AS number" : "Domain suffix"}><input className="input w-full" value={form.match} onChange={(e) => setForm({ ...form, match: e.target.value })} /></Field>}
        <Field label="Application"><input className="input w-full" value={form.app} onChange={(e) => setForm({ ...form, app: e.target.value })} /></Field>
        <Field label="Category"><input className="input w-full" value={form.category} onChange={(e) => setForm({ ...form, category: e.target.value })} /></Field>
        <Field label="Encrypted"><select className="input w-full" value={form.encrypted ?? ""} onChange={(e) => setForm({ ...form, encrypted: e.target.value })}>
          <option value="">depends / unknown</option><option value="true">yes</option><option value="false">no</option></select></Field>
        <Field label="Description"><input className="input w-full" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
        <label className="text-xs inline-flex gap-1 items-center"><input type="checkbox" checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />enabled</label>
        <button type="button" className="btn btn-primary" disabled={save.isPending || !form.app} onClick={() => save.mutate(form)}>Save</button><Err e={save.error} />
      </div></Drawer>}
  </Card>;
}

function Policies({ can, zones }: { can: boolean; zones: string[] }) {
  const qc = useQueryClient();
  const q = useQuery<any[]>({ queryKey: ["traffic-pol"], queryFn: () => api("/nms/traffic/vlan-policies") });
  const [form, setForm] = useState<any>(null);
  const save = useMutation({ mutationFn: (f: any) => {
    const body = { name: f.name, src: f.src, dst: f.dst, action: f.action, severity: f.severity, enabled: f.enabled, description: f.description || "" };
    return f.id ? api(`/nms/traffic/vlan-policies/${f.id}`, { method: "PUT", body }) : api("/nms/traffic/vlan-policies", { method: "POST", body });
  }, onSuccess: () => { qc.invalidateQueries({ queryKey: ["traffic-pol"] }); setForm(null); } });
  const del = useMutation({ mutationFn: (id: number) => api(`/nms/traffic/vlan-policies/${id}`, { method: "DELETE" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["traffic-pol"] }) });
  return <Card bodyClass="p-0" title="VLAN / zone policies" right={can && <button type="button" className="btn py-0.5 text-xs" onClick={() => setForm({ name: "", src: "zone:guest", dst: "zone:corporate", action: "deny", severity: "medium", enabled: true })}>Add policy</button>}>
    <Loading q={q} />{q.data && <TableWrap><table className="tbl"><thead><tr><th>Name</th><th>From</th><th>To</th><th>Action</th><th>Severity</th><th>Enabled</th><th /></tr></thead>
      <tbody>{q.data.map((p) => <tr key={p.id}><td className="text-xs">{p.name}</td><td className="font-mono text-xs">{p.src}</td><td className="font-mono text-xs">{p.dst}</td>
        <td className={`text-xs ${p.action === "deny" ? "text-red-300" : "text-emerald-300"}`}>{p.action}</td><td><Sev s={p.severity} /></td><td className="text-xs">{p.enabled ? "yes" : "no"}</td>
        <td>{can && <><button type="button" className="link text-xs" onClick={() => setForm(p)}>Edit</button>
          <button type="button" className="link text-xs ml-2 text-red-300" onClick={() => confirm(`Delete policy ${p.name}?`) && del.mutate(p.id)}>Delete</button></>}</td></tr>)}</tbody></table></TableWrap>}
    <p className="text-2xs text-muted px-3 pb-2">Endpoints: any, internal, external, zone:&lt;zone&gt; ({zones.join(", ")}) or vlan:&lt;id&gt;. Zone policies take effect for ranges tagged with that zone
      (Networks & Settings). A VLAN-level allow overrides a zone-level deny.</p>
    {form && <Drawer title={form.id ? `Edit ${form.name}` : "New policy"} onClose={() => setForm(null)}>
      <div className="grid gap-2">
        {([["name", "Name"], ["src", "From (zone:guest, vlan:20, internal, any)"], ["dst", "To (zone:corporate, vlan:30, external, any)"], ["description", "Description"]] as [string, string][])
          .map(([k, l]) => <Field key={k} label={l}><input className="input w-full" value={form[k] || ""} onChange={(e) => setForm({ ...form, [k]: e.target.value })} /></Field>)}
        <Field label="Action"><select className="input w-full" value={form.action} onChange={(e) => setForm({ ...form, action: e.target.value })}><option>deny</option><option>allow</option></select></Field>
        <Field label="Severity"><select className="input w-full" value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>{SEVS.map((s) => <option key={s}>{s}</option>)}</select></Field>
        <label className="text-xs inline-flex gap-1 items-center"><input type="checkbox" checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />enabled</label>
        <button type="button" className="btn btn-primary" disabled={save.isPending || !form.name} onClick={() => save.mutate(form)}>Save</button><Err e={save.error} />
      </div></Drawer>}
  </Card>;
}

// ------------------------------------------------------------------ networks & settings
export function SettingsTab({ nav }: { nav: Nav }) {
  const p = nav.opts?.permissions;
  return <div className="space-y-3"><NetworksCard can={!!p?.collector} zones={nav.opts?.zones || []} /><SettingsCard canCollect={!!p?.collector} canEnrich={!!p?.enrichment} /></div>;
}

function NetworksCard({ can, zones }: { can: boolean; zones: string[] }) {
  const qc = useQueryClient();
  const q = useQuery<any>({ queryKey: ["traffic-nets"], queryFn: () => api("/nms/traffic/networks") });
  const [form, setForm] = useState<any>(null);
  const save = useMutation({ mutationFn: (f: any) => {
    const body = { cidr: f.cidr, name: f.name || "", site: f.site || "", vlan: f.vlan === "" || f.vlan == null ? null : Number(f.vlan), zone: f.zone, internal: f.internal, description: f.description || "" };
    return f.id ? api(`/nms/traffic/networks/${f.id}`, { method: "PUT", body }) : api("/nms/traffic/networks", { method: "POST", body });
  }, onSuccess: () => { qc.invalidateQueries({ queryKey: ["traffic-nets"] }); qc.invalidateQueries({ queryKey: ["traffic"] }); setForm(null); } });
  const del = useMutation({ mutationFn: (id: number) => api(`/nms/traffic/networks/${id}`, { method: "DELETE" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["traffic-nets"] }) });
  return <Card bodyClass="p-0" title="Network ranges (direction, VLAN, zone, site)" right={can && <button type="button" className="btn py-0.5 text-xs" onClick={() => setForm({ cidr: "", zone: "corporate", internal: true, vlan: "" })}>Add range</button>}>
    <Loading q={q} />
    {q.data && (!q.data.items.length ? <Empty text={`No ranges configured: ${q.data.fallback_internal.join(", ")} count as internal until you add your own.`} /> :
      <TableWrap><table className="tbl"><thead><tr><th>Network</th><th>Name</th><th>Site</th><th>VLAN</th><th>Zone</th><th>Internal</th><th /></tr></thead>
        <tbody>{q.data.items.map((n: any) => <tr key={n.id}><td className="font-mono text-xs">{n.cidr}</td><td className="text-xs">{n.name}</td><td className="text-xs">{n.site}</td>
          <td className="text-xs">{n.vlan ?? "—"}</td><td className="text-xs">{n.zone}</td><td className="text-xs">{n.internal ? "yes" : "no"}</td>
          <td>{can && <><button type="button" className="link text-xs" onClick={() => setForm({ ...n, vlan: n.vlan ?? "" })}>Edit</button>
            <button type="button" className="link text-xs ml-2 text-red-300" onClick={() => confirm(`Delete ${n.cidr}?`) && del.mutate(n.id)}>Delete</button></>}</td></tr>)}</tbody></table></TableWrap>)}
    <p className="text-2xs text-muted px-3 pb-2">The most specific range containing an address decides its site, VLAN and zone. Mark a range not internal to carve it out of a larger internal one.</p>
    {form && <Drawer title={form.id ? `Edit ${form.cidr}` : "New range"} onClose={() => setForm(null)}>
      <div className="grid gap-2">
        {([["cidr", "Network (CIDR)"], ["name", "Name"], ["site", "Site"], ["vlan", "VLAN (1–4094)"], ["description", "Description"]] as [string, string][])
          .map(([k, l]) => <Field key={k} label={l}><input className="input w-full" value={form[k] ?? ""} onChange={(e) => setForm({ ...form, [k]: e.target.value })} /></Field>)}
        <Field label="Zone"><select className="input w-full" value={form.zone} onChange={(e) => setForm({ ...form, zone: e.target.value })}>{zones.map((z) => <option key={z}>{z}</option>)}</select></Field>
        <label className="text-xs inline-flex gap-1 items-center"><input type="checkbox" checked={form.internal} onChange={(e) => setForm({ ...form, internal: e.target.checked })} />internal</label>
        <button type="button" className="btn btn-primary" disabled={save.isPending || !form.cidr} onClick={() => save.mutate(form)}>Save</button><Err e={save.error} />
      </div></Drawer>}
  </Card>;
}

const LISTS: [string, string][] = [["snmp_managers", "Authorised SNMP managers / trap receivers (include this NMS server)"], ["dns_resolvers", "Approved DNS resolvers"],
  ["mqtt_brokers", "Approved MQTT brokers"], ["mqtt_clients", "Networks allowed to use MQTT (empty: any)"], ["detection_exclusions", "Excluded from every traffic detection"]];
const ENRICH: [string, string][] = [["enrich_dns", "Correlate DNS logs (Zeek, FortiGate DNS, resolver syslog)"], ["enrich_firewall_apps", "Use firewall application control"],
  ["enrich_asn", "Local ASN / GeoIP databases"], ["enrich_rdns", "Reverse DNS (PTR) lookups through the server's resolver"]];

function SettingsCard({ canCollect, canEnrich }: { canCollect: boolean; canEnrich: boolean }) {
  const qc = useQueryClient();
  const q = useQuery<any>({ queryKey: ["traffic-settings"], queryFn: () => api("/nms/traffic/settings") });
  const [draft, setDraft] = useState<Record<string, any> | null>(null);
  const save = useMutation({ mutationFn: (body: any) => api("/nms/traffic/settings", { method: "PUT", body }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["traffic-settings"] }); qc.invalidateQueries({ queryKey: ["traffic"] }); setDraft(null); } });
  if (!q.data) return <Card><Loading q={q} /></Card>;
  const d = { ...q.data, ...(draft || {}) };
  const set = (k: string, v: any) => setDraft({ ...(draft || {}), [k]: v });
  const row = (label: ReactNode, control: ReactNode) => <Field label={label}>{control}</Field>;
  return <Card title="Traffic settings">
    <div className="grid gap-3 md:grid-cols-2">
      {row("Count a conversation seen by several devices", <select className="input w-full" disabled={!canCollect} value={d.dedup} onChange={(e) => set("dedup", e.target.value)}>
        <option value="max_across_exporters">once (largest exporter's figures)</option><option value="none">once per device (added up)</option></select>)}
      {row("LAG interfaces", <select className="input w-full" disabled={!canCollect} value={d.lag_mode} onChange={(e) => set("lag_mode", e.target.value)}>
        <option value="members">count members, show their sum on the LAG</option><option value="logical">count the logical LAG</option></select>)}
      {LISTS.map(([k, l]) => <Field key={k} label={l} hint="addresses or CIDRs, comma-separated"><textarea className="input w-full h-16 font-mono text-xs" disabled={!canCollect}
        value={Array.isArray(d[k]) ? d[k].join(", ") : d[k]} onChange={(e) => set(k, e.target.value.split(/[\s,]+/).filter(Boolean))} /></Field>)}
      {row("Report new VLAN pairs (informational)", <select className="input w-full" disabled={!canCollect} value={String(d.alert_new_vlan_pairs)} onChange={(e) => set("alert_new_vlan_pairs", e.target.value === "true")}>
        <option value="false">no</option><option value="true">yes</option></select>)}
      {ENRICH.map(([k, l]) => <label key={k} className="text-xs inline-flex gap-2 items-center"><input type="checkbox" disabled={!canEnrich} checked={!!d[k]} onChange={(e) => set(k, e.target.checked)} />{l}</label>)}
      {row("Destinations enriched per run", <input className="input w-full" disabled={!canEnrich} value={d.enrich_top_n} onChange={(e) => set("enrich_top_n", Number(e.target.value) || 0)} />)}
    </div>
    {draft && <div className="mt-3 flex gap-2"><button type="button" className="btn btn-primary" disabled={save.isPending} onClick={() => save.mutate(draft)}>Save</button>
      <button type="button" className="btn" onClick={() => setDraft(null)}>Cancel</button></div>}
    <Err e={save.error} />
    <p className="text-2xs text-muted mt-2">Enrichment runs in the background every 5 minutes for the busiest destinations; analytics never wait for it. Reverse DNS is off by default.</p>
  </Card>;
}

// ------------------------------------------------------------------ collectors
export function CollectorsTab() {
  const q = useQuery<any>({ queryKey: ["traffic-collectors"], queryFn: () => api("/nms/traffic/collectors"), refetchInterval: 30_000 });
  const d = q.data;
  return <div className="space-y-3"><Loading q={q} />
    {d && <>
      <Card title="Flow collector">{d.collector ? <dl className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
        {([["Last report", <Time v={d.collector.last} />], ["Datagrams", fmtNum(d.collector.datagrams)], ["Records decoded", fmtNum(d.collector.records)], ["Stored", fmtNum(d.collector.stored)],
          ["Decode errors", fmtNum(d.collector.decode_errors)], ["Missing templates", fmtNum(d.collector.missing_template)], ["Dropped (queue full)", fmtNum(d.collector.dropped_queue_full)],
          ["Insert errors", fmtNum(d.collector.insert_errors)], ["Queue depth", fmtNum(d.collector.queue_depth)], ["Known exporters", fmtNum(d.collector.exporters_known)],
          ["Unknown senders (dropped)", fmtNum(d.collector.unknown_exporter)]] as [string, ReactNode][]).map(([k, v]) => <div key={k}><dt className="text-muted">{k}</dt><dd className="font-semibold">{v}</dd></div>)}
      </dl> : <Empty text="The flow collector has not reported in the last 10 minutes (service 'flows')." />}</Card>
      {d.collector?.unknown_senders?.length > 0 && <Card bodyClass="p-0" title="Senders that are not inventory devices (their flows are dropped)">
        <TableWrap><table className="tbl"><thead><tr><th>Address</th><th className="num">Datagrams</th></tr></thead><tbody>{d.collector.unknown_senders.map((u: any) => <tr key={u.ip}>
          <td className="font-mono text-xs">{u.ip}</td><td className="num">{fmtNum(u.datagrams)}</td></tr>)}</tbody></table></TableWrap>
        <p className="text-2xs text-muted px-3 pb-2">Add the device to the inventory, or set its export source interface to its management address.</p></Card>}
      <Card bodyClass="p-0" title="Exporters (last 24 hours)">{!d.exporters.length ? <Empty text="No device has exported flows in the last 24 hours." /> :
        <TableWrap><table className="tbl"><thead><tr><th>Device</th><th>Address</th><th>Status</th><th>Last sample</th><th className="num">Records (1 h)</th><th className="num">Traffic (1 h)</th>
          <th>Telemetry</th><th>Sampling</th></tr></thead><tbody>{d.exporters.map((x: any) => <tr key={x.exporter}><td className="text-xs">{x.device}</td><td className="font-mono text-xs">{x.exporter}</td>
            <td className={`text-xs ${x.status === "ok" ? "text-emerald-300" : x.status === "stale" ? "text-amber-300" : "text-red-300"}`}>{x.status}</td><td className="text-xs"><Time v={x.last} /></td>
            <td className="num">{fmtNum(x.records_1h)}</td><td className="num">{fmtBytes(x.bytes_1h)}</td><td className="text-xs">{x.telemetry.join(", ")}</td>
            <td className="text-xs">{x.sampling > 1 ? `1:${x.sampling} (estimates)` : "unsampled"}</td></tr>)}</tbody></table></TableWrap>}</Card>
      {d.inventory_without_data.length > 0 && <Card title="Inventory devices without flow data"><p className="text-xs">{d.inventory_without_data.join(", ")}</p></Card>}
      <ul className="text-2xs text-muted list-disc pl-5">{d.notes.map((x: string) => <li key={x}>{x}</li>)}</ul>
    </>}
  </div>;
}
