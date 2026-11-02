import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { useMe } from "../../lib/context";
import { fmtNum } from "../../lib/format";
import { Card, Empty, Kpi, Loading, Modal, Sev, TableWrap, Tabs, Time } from "../../components/ui";
import { StateDot } from "../switches/common";
import { CELL, CONFIDENCE, VENDOR_LABEL, matrixCounts, pctTone, vendorKey } from "./snmp";

/** Sentinel NMS → SNMP monitoring: vendor / device overview, polling health, traps, MIB / OID registry with OID test,
 *  custom OID profiles, MIB modules and the support matrix. Everything is read from /api/snmp; changes need the
 *  administrator role. Fixture data is never shown here — every value comes from devices this NMS polls. */
export const SNMP_TABS: [string, string][] = [["vendors", "Vendor & Device Overview"], ["health", "Polling Health"], ["traps", "SNMP Traps"],
  ["registry", "MIB / OID Registry"], ["custom", "Custom OIDs"], ["mibs", "MIB Modules"], ["matrix", "Support Matrix"]];

export function SnmpPage() {
  const [sp, setSp] = useSearchParams();
  const tab = SNMP_TABS.some(([k]) => k === sp.get("tab")) ? sp.get("tab")! : "vendors";
  return <div className="min-w-0">
    <Tabs value={tab} onChange={(t) => setSp({ tab: t })} tabs={SNMP_TABS.map(([key, label]) => ({ key, label }))} />
    <div key={tab}>
      {tab === "vendors" && <Vendors />}
      {tab === "health" && <PollingHealth />}
      {tab === "traps" && <Traps />}
      {tab === "registry" && <Registry />}
      {tab === "custom" && <CustomOids />}
      {tab === "mibs" && <Mibs />}
      {tab === "matrix" && <Matrix />}
    </div>
  </div>;
}

const useAdmin = () => useMe()?.role === "admin";
const Err = ({ e }: { e: unknown }) => e ? <div role="alert" className="text-sm text-red-300">{(e as Error).message}</div> : null;

// ------------------------------------------------------------------ vendors
function Vendors() {
  const admin = useAdmin();
  const q = useQuery({ queryKey: ["snmp-vendors"], queryFn: () => api<any>("/snmp/vendors"), refetchInterval: 60_000 });
  const [vendor, setVendor] = useState("");
  const [edit, setEdit] = useState<any>(null);
  const rows = (q.data?.devices || []).filter((d: any) => !vendor || vendorKey(d.vendor) === vendor);
  return <div className="space-y-4">
    <p className="text-xs text-muted">Devices are identified from sysObjectID first (vendor enterprise number, product subtree), then sysDescr. Confidence shows how the
      profile was chosen; an administrator can override vendor and product line per device.</p>
    <Loading q={q} />
    {q.data && <>
      <div className="kpi-grid">{q.data.vendors.map((v: any) => <Kpi key={v.vendor} label={VENDOR_LABEL[v.vendor]} value={fmtNum(v.devices)}
        tone={v.down ? "bad" : undefined} sub={v.devices ? `${v.up} up · ${v.down} down · ${v.families.slice(0, 3).map((f: any) => `${f.family} ${f.count}`).join(", ")}` : "none"}
        onClick={() => setVendor(vendor === v.vendor ? "" : v.vendor)} />)}</div>
      <Card title={vendor ? `${VENDOR_LABEL[vendor]} devices` : "All devices"} bodyClass="p-0" right={vendor && <button className="link text-xs" onClick={() => setVendor("")}>Show all</button>}>
        {!rows.length ? <Empty text="No devices." /> : <TableWrap maxH="max-h-[36rem]"><table className="tbl"><thead><tr><th>Device</th><th>Vendor</th><th>Product line / model</th>
          <th>Software</th><th>Address</th><th>Site</th><th>Type</th><th>State</th><th className="num">CPU</th><th className="num">Memory</th><th>Last poll</th><th>SNMP</th>
          <th className="num">Alerts</th><th>Profile</th>{admin && <th />}</tr></thead>
          <tbody>{rows.map((d: any) => <tr key={d.id}>
            <td><Link className="link" to={`/switches/${d.id}`}>{d.name}</Link></td><td>{d.vendor}</td>
            <td>{d.product_line || "—"}<div className="text-2xs text-muted">{[d.family !== d.product_line && d.family, d.model].filter(Boolean).join(" · ")}</div></td>
            <td className="text-xs">{[d.os, d.firmware].filter(Boolean).join(" ") || "—"}</td><td className="font-mono text-xs">{d.address}</td><td>{d.site || "—"}</td>
            <td className="text-xs">{d.device_type || "—"}</td><td><StateDot s={d.state} monitoring={d.monitoring} /></td>
            <td className="num">{d.cpu_pct == null ? "—" : `${d.cpu_pct}%`}</td><td className="num">{d.mem_pct == null ? "—" : `${d.mem_pct}%`}</td>
            <td className="text-xs"><Time v={d.last_success_at} /></td><td className="text-xs">{d.snmp_version || "—"}</td>
            <td className="num">{d.alerts_open ? <span className="text-red-300">{d.alerts_open}</span> : "—"}</td>
            <td className="text-xs" title={d.identity?.matched_by}>{CONFIDENCE[d.id_confidence] || d.id_confidence || "—"}
              {d.identity?.override_conflict && <div className="text-amber-300">{d.identity.override_conflict}</div>}</td>
            {admin && <td><button className="link text-xs" onClick={() => setEdit(d)}>Override</button></td>}</tr>)}</tbody></table></TableWrap>}</Card>
    </>}
    {edit && <ProfileForm d={edit} onClose={() => setEdit(null)} />}
  </div>;
}

function ProfileForm({ d, onClose }: { d: any; onClose: () => void }) {
  const qc = useQueryClient();
  const fp = useQuery({ queryKey: ["snmp-fp"], queryFn: () => api<any>("/snmp/fingerprints"), staleTime: 300_000 });
  const [f, setF] = useState({ vendor_override: d.vendor_override || "", family_override: d.family_override || "" });
  const families = useMemo(() => Array.from(new Set([...(fp.data?.descr_rules || []), ...(fp.data?.oid_rules || [])]
    .filter((r: any) => r.family && (!f.vendor_override || r.vendor === f.vendor_override)).map((r: any) => r.family))).sort() as string[], [fp.data, f.vendor_override]);
  const save = useMutation({ mutationFn: () => api(`/snmp/devices/${d.id}/profile`, { method: "PUT", body: f }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["snmp-vendors"] }); onClose(); } });
  return <Modal title={`Monitoring profile: ${d.name}`} onClose={onClose}>
    <p className="text-xs text-muted mb-2">Detected: {d.vendor} {d.product_line || ""} ({CONFIDENCE[d.id_confidence] || "not identified yet"}). {d.identity?.matched_by}.
      An override applies on the next poll; if the device's own sysObjectID disagrees, the conflict is shown on this page.</p>
    <div className="grid gap-2 sm:grid-cols-2">
      <div><label className="label">Vendor</label><select className="input w-full" value={f.vendor_override} onChange={(e) => setF({ vendor_override: e.target.value, family_override: "" })}>
        <option value="">Automatic</option>{["cisco", "fortinet", "juniper", "ruckus", "generic"].map((v) => <option key={v}>{v}</option>)}</select></div>
      <div><label className="label">Product line</label><select className="input w-full" value={f.family_override} onChange={(e) => setF({ ...f, family_override: e.target.value })}>
        <option value="">Automatic</option>{families.map((x) => <option key={x}>{x}</option>)}</select></div>
    </div>
    <Err e={save.error} />
    <div className="flex justify-end gap-2 mt-3"><button className="btn" onClick={onClose}>Cancel</button>
      <button className="btn btn-primary" disabled={save.isPending} onClick={() => save.mutate()}>Save</button></div>
  </Modal>;
}

// ------------------------------------------------------------------ polling health
function PollingHealth() {
  const [range, setRange] = useState("24h");
  const q = useQuery({ queryKey: ["snmp-health", range], queryFn: () => api<any>("/snmp/polling-health", { params: { range } }), refetchInterval: 60_000 });
  const d = q.data;
  const s = d?.summary || {};
  return <div className="space-y-4">
    <div className="flex items-center gap-3"><p className="text-xs text-muted flex-1">Polls, failures and timing per device. One SNMP request is in flight per device at a time;
      failing devices back off so a dead switch is not hammered. Unsupported = the device answered noSuchObject / empty for a metric its profile asks for.</p>
      <select className="input py-1 text-xs" value={range} onChange={(e) => setRange(e.target.value)} aria-label="Range">{["1h", "24h", "7d"].map((r) => <option key={r}>{r}</option>)}</select></div>
    <Loading q={q} />
    {d && <>
      <div className="kpi-grid">
        <Kpi label="Polling success" value={s.success_pct == null ? "—" : `${s.success_pct}%`} tone={pctTone(s.success_pct)} sub={`${fmtNum(s.polls)} polls`} />
        <Kpi label="Failures" value={fmtNum(s.failures)} tone={s.failures ? "warn" : "ok"} sub={`${fmtNum(s.timeouts)} timeouts · ${fmtNum(s.auth_failures)} auth`} />
        <Kpi label="Average poll" value={s.avg_duration_ms == null ? "—" : `${(s.avg_duration_ms / 1000).toFixed(1)} s`} />
        <Kpi label="Backing off" value={fmtNum(s.backing_off)} tone={s.backing_off ? "warn" : undefined} sub={`${s.inflight} poll(s) in flight`} />
        <Kpi label="Unsupported metrics" value={fmtNum(s.unsupported_metrics)} sub="across all devices" />
        <Kpi label="Traps received" value={d.traps ? fmtNum(d.traps.received) : "—"} sub={d.traps ? `${d.traps.devices} device(s)` : "trap store unavailable"} />
      </div>
      <Card title="Engine" bodyClass="p-3 text-xs text-muted">Up to {d.engine.max_concurrent_polls} devices polled at once, {d.engine.requests_in_flight_per_device} request in flight per
        device; poll budget {d.engine.poll_timeout_s} s ({d.engine.wlc_poll_timeout_s} s for wireless controllers); SNMPv2c {d.engine.snmpv2c_allowed ? "allowed" : "disabled (v3 only)"};
        backoff: {d.engine.backoff}.</Card>
      <Card title="Devices (least successful first)" bodyClass="p-0">
        <TableWrap maxH="max-h-[36rem]"><table className="tbl"><thead><tr><th>Device</th><th>Vendor</th><th>State</th><th className="num">Polls</th><th className="num">Success</th>
          <th className="num">Timeouts</th><th className="num">Avg / max</th><th className="num">Metrics ok / unsupported / failing</th><th>Last success</th><th>Backoff</th><th>Last error</th></tr></thead>
          <tbody>{d.devices.map((x: any) => <tr key={x.switch_id}><td><Link className="link" to={`/switches/${x.switch_id}?tab=health`}>{x.name}</Link></td>
            <td className="text-xs">{x.vendor} {x.product_line}</td><td><StateDot s={x.state} monitoring={x.monitoring} /></td><td className="num">{x.polls}</td>
            <td className="num"><span className={x.success_pct == null ? "text-muted" : x.success_pct < 90 ? "text-red-300" : x.success_pct < 99 ? "text-amber-300" : "text-emerald-300"}>
              {x.success_pct == null ? "—" : `${x.success_pct}%`}</span></td><td className="num">{x.timeouts}</td>
            <td className="num text-xs">{x.avg_duration_ms == null ? "—" : `${(x.avg_duration_ms / 1000).toFixed(1)} / ${(x.max_duration_ms / 1000).toFixed(1)} s`}</td>
            <td className="num text-xs">{x.healthy_metrics} / {x.unsupported} / {x.failed_metrics + x.stale_metrics}</td><td className="text-xs"><Time v={x.last_success_at} /></td>
            <td className="text-xs">{x.backoff_until && new Date(x.backoff_until) > new Date() ? <span className="text-amber-300">until <Time v={x.backoff_until} /></span> : "—"}</td>
            <td className="text-xs max-w-[20rem] truncate" title={x.last_error}>{x.last_error || "—"}</td></tr>)}</tbody></table></TableWrap></Card>
    </>}
  </div>;
}

// ------------------------------------------------------------------ traps
function Traps() {
  const [range, setRange] = useState("24h");
  const [sev, setSev] = useState("");
  const [qq, setQ] = useState("");
  const [open, setOpen] = useState<any>(null);
  const q = useQuery({ queryKey: ["snmp-traps", range, sev, qq], queryFn: () => api<any>("/snmp/traps", { params: { range, severity: sev ? [sev] : [], q: qq || undefined } }),
    refetchInterval: 30_000, placeholderData: (p) => p });
  const d = q.data;
  return <div className="space-y-4">
    <p className="text-xs text-muted">Notifications received on UDP 162 (v1 / v2c traps, v3 traps and informs). Only devices in the inventory, authenticating with their own
      credential profile, are accepted. Repeats of the same trap within 30 s are counted, not stored again.</p>
    <div className="flex flex-wrap items-center gap-2">
      <select className="input py-1 text-xs" value={range} onChange={(e) => setRange(e.target.value)} aria-label="Range">{["1h", "24h", "7d", "30d"].map((r) => <option key={r}>{r}</option>)}</select>
      <select className="input py-1 text-xs" value={sev} onChange={(e) => setSev(e.target.value)} aria-label="Severity"><option value="">All severities</option>
        {["critical", "high", "medium", "low", "informational"].map((x) => <option key={x}>{x}</option>)}</select>
      <input className="input py-1 text-xs w-64" placeholder="Search trap, component or OID" value={qq} onChange={(e) => setQ(e.target.value)} />
    </div>
    <Loading q={q} />
    {d && <>
      <div className="kpi-grid">{["critical", "high", "medium", "low", "informational"].map((k) => <Kpi key={k} label={k} value={fmtNum(d.by_severity[k] || 0)}
        tone={(d.by_severity[k] || 0) && ["critical", "high"].includes(k) ? "bad" : undefined} onClick={() => setSev(sev === k ? "" : k)} />)}</div>
      <Card title="Traps" bodyClass="p-0">{!d.items.length ? <Empty text="No traps in this range. Point devices' trap host at this NMS (UDP 162) — see docs/SNMP.md." /> :
        <TableWrap maxH="max-h-[36rem]"><table className="tbl"><thead><tr><th>Time</th><th>Device</th><th>Severity</th><th>Trap</th><th>Component</th><th>Summary</th><th>Ver.</th>
          <th className="num">Repeats</th></tr></thead>
          <tbody>{d.items.map((t: any, i: number) => <tr key={i} className="cursor-pointer hover:bg-white/5" onClick={() => setOpen(t)}><td className="text-xs"><Time v={t.ts} /></td>
            <td>{t.switch ? <Link className="link" to={`/switches/${t.switch_id}`} onClick={(e) => e.stopPropagation()}>{t.switch}</Link> : t.source_ip}</td>
            <td><Sev s={t.severity} /></td><td className="text-xs">{t.trap_name}</td><td className="text-xs">{t.component || "—"}</td><td className="text-xs">{t.summary}</td>
            <td className="text-xs">{t.version}</td><td className="num">{t.repeats || "—"}</td></tr>)}</tbody></table></TableWrap>}</Card>
    </>}
    {open && <Modal wide title={`${open.trap_name} from ${open.switch || open.source_ip}`} onClose={() => setOpen(null)}>
      <div className="text-xs text-muted mb-2">{open.ts} · {open.version} · trap OID <span className="font-mono">{open.trap_oid}</span></div>
      <TableWrap maxH="max-h-96"><table className="tbl"><thead><tr><th>Varbind</th><th>OID</th><th>Type</th><th>Value</th></tr></thead>
        <tbody>{open.varbinds.map((v: any, i: number) => <tr key={i}><td className="text-xs">{v.name || "—"}</td><td className="font-mono text-xs">{v.oid}</td><td className="text-xs">{v.type}</td>
          <td className="font-mono text-xs break-all">{String(v.value)}</td></tr>)}</tbody></table></TableWrap>
    </Modal>}
  </div>;
}

// ------------------------------------------------------------------ registry, OID search and test
function Registry() {
  const admin = useAdmin();
  const qc = useQueryClient();
  const [vendor, setVendor] = useState("");
  const [qq, setQ] = useState("");
  const q = useQuery({ queryKey: ["snmp-registry", vendor, qq], queryFn: () => api<any>("/snmp/registry", { params: { vendor: vendor || undefined, q: qq || undefined } }),
    placeholderData: (p) => p });
  const toggle = useMutation({ mutationFn: ({ key, enabled }: any) => api(`/snmp/registry/${key}`, { method: "PUT", body: { enabled } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["snmp-registry"] }) });
  return <div className="space-y-4">
    <OidTools />
    <Card title="Built-in metric definitions" bodyClass="p-0" right={<div className="flex gap-2">
      <select className="input py-1 text-xs" value={vendor} onChange={(e) => setVendor(e.target.value)} aria-label="Vendor"><option value="">All vendors</option>
        {["cisco", "fortinet", "juniper", "ruckus", "generic"].map((v) => <option key={v}>{v}</option>)}</select>
      <input className="input py-1 text-xs w-48" placeholder="Filter metric / MIB / OID" value={qq} onChange={(e) => setQ(e.target.value)} /></div>}>
      <Loading q={q} /><Err e={toggle.error} />
      {q.data && <TableWrap maxH="max-h-[40rem]"><table className="tbl"><thead><tr><th>Metric</th><th>Group</th><th>Source (MIB object)</th><th>OID</th><th>Type</th><th>Unit</th>
        <th>Vendors</th><th>Observed on</th><th>Collect</th></tr></thead>
        <tbody>{q.data.items.map((m: any, i: number) => <tr key={i}><td className="font-mono text-xs">{m.key}</td><td className="text-xs">{m.group_label}</td>
          <td className="text-xs max-w-[22rem]">{m.source}{m.note && <div className="text-2xs text-muted">{m.note}</div>}</td><td className="font-mono text-2xs">{m.oid || "—"}</td>
          <td className="text-xs">{m.type}</td><td className="text-xs">{m.unit || "—"}</td><td className="text-xs">{m.vendors.join(", ")}</td>
          <td className="text-xs">{Object.entries(m.observed_devices).filter(([, n]) => n).map(([v, n]) => `${v} ${n}`).join(", ") || <span className="text-muted">not yet</span>}</td>
          <td>{admin ? <input type="checkbox" checked={m.enabled} aria-label={`Collect ${m.key}`} disabled={["switch_up", "switch_system_info"].includes(m.key)}
            onChange={(e) => toggle.mutate({ key: m.key, enabled: e.target.checked })} /> : m.enabled ? "yes" : "off"}</td></tr>)}</tbody></table></TableWrap>}</Card>
  </div>;
}

function OidTools() {
  const admin = useAdmin();
  const [qq, setQ] = useState("");
  const search = useQuery({ queryKey: ["snmp-oid-search", qq], queryFn: () => api<any>("/snmp/oids/search", { params: { q: qq } }), enabled: qq.length >= 2 });
  const devs = useQuery({ queryKey: ["snmp-vendors"], queryFn: () => api<any>("/snmp/vendors") });
  const [t, setT] = useState({ switch_id: "", oid: "", method: "get" });
  const test = useMutation({ mutationFn: () => api<any>("/snmp/oids/test", { method: "POST", body: { ...t, switch_id: Number(t.switch_id) } }) });
  return <div className="grid gap-4 xl:grid-cols-2">
    <Card title="Search OIDs (registry, notifications, imported MIBs)" bodyClass="p-0">
      <div className="p-3"><input className="input w-full" placeholder="Name or OID prefix, e.g. ifHCInOctets or 1.3.6.1.4.1.12356" value={qq} onChange={(e) => setQ(e.target.value)} /></div>
      {search.data && (!search.data.items.length ? <Empty text="No match." /> : <TableWrap maxH="max-h-80"><table className="tbl"><thead><tr><th>Name</th><th>OID</th><th>Source</th></tr></thead>
        <tbody>{search.data.items.map((x: any, i: number) => <tr key={i} className={admin ? "cursor-pointer hover:bg-white/5" : ""} onClick={() => admin && setT({ ...t, oid: x.oid })}>
          <td className="text-xs">{x.name}{x.description && <div className="text-2xs text-muted truncate max-w-[22rem]">{x.description}</div>}</td>
          <td className="font-mono text-2xs">{x.oid}</td><td className="text-xs">{x.source}</td></tr>)}</tbody></table></TableWrap>)}
    </Card>
    <Card title="Test an OID against a device (read-only)">
      {!admin ? <Empty text="Administrators can run OID tests." /> : <div className="space-y-2">
        <div className="grid gap-2 sm:grid-cols-3">
          <select className="input" value={t.switch_id} onChange={(e) => setT({ ...t, switch_id: e.target.value })} aria-label="Device"><option value="">Device…</option>
            {(devs.data?.devices || []).map((d: any) => <option key={d.id} value={d.id}>{d.name}</option>)}</select>
          <input className="input font-mono text-xs" placeholder="1.3.6.1.2.1.1.3.0" value={t.oid} onChange={(e) => setT({ ...t, oid: e.target.value })} aria-label="OID" />
          <select className="input" value={t.method} onChange={(e) => setT({ ...t, method: e.target.value })} aria-label="Method"><option value="get">GET (scalar)</option><option value="walk">WALK (GETBULK)</option></select>
        </div>
        <div className="flex items-center gap-2"><button className="btn btn-primary" disabled={!t.switch_id || !t.oid || test.isPending} onClick={() => test.mutate()}>{test.isPending ? "Asking…" : "Run"}</button>
          <span className="text-2xs text-muted">Sends GET / GETBULK only, with the device's own credential profile. Audited.</span></div>
        <Err e={test.error} />
        {test.data && <><div className="text-xs">{test.data.answered ? <span className="text-emerald-300">answered</span> : <span className="text-amber-300">not supported by this device (noSuchObject / empty)</span>}
          {test.data.truncated && " · first 200 rows"}</div>
          <TableWrap maxH="max-h-72"><table className="tbl"><thead><tr><th>OID</th><th>Name</th><th>Type</th><th>Raw</th><th>Parsed</th></tr></thead>
            <tbody>{test.data.rows.map((r: any, i: number) => <tr key={i}><td className="font-mono text-2xs">{r.oid}</td><td className="text-xs">{r.name !== r.oid ? r.name : "—"}</td>
              <td className="text-xs">{r.type}</td><td className="font-mono text-xs break-all">{r.raw == null ? "—" : String(r.raw)}</td><td className="text-xs">{r.value == null ? "—" : String(r.value)}</td></tr>)}</tbody></table></TableWrap></>}
      </div>}
    </Card>
  </div>;
}

// ------------------------------------------------------------------ custom OIDs
const CUSTOM_BLANK = { name: "", oid: "", method: "get", value_type: "gauge", unit: "", scale: 1, vendor: "", product_line: "", switch_ids: [] as number[], description: "", enabled: true };

function CustomOids() {
  const admin = useAdmin();
  const q = useQuery({ queryKey: ["snmp-custom"], queryFn: () => api<any>("/snmp/custom") });
  const [edit, setEdit] = useState<any>(undefined);
  const [hist, setHist] = useState<any>(null);
  return <div className="space-y-4">
    <div className="flex items-center gap-2"><p className="text-xs text-muted flex-1">Read-only items of your own (Zabbix items / LibreNMS custom OIDs). Each is polled every 5 minutes with the
      device's credential and graphed as metric <span className="font-mono">custom:&lt;name&gt;</span>; counters are turned into per-second rates. Every change is versioned.</p>
      {admin && <button className="btn btn-primary" onClick={() => setEdit(null)}>+ Add custom OID</button>}</div>
    <Card title="Custom OIDs" bodyClass="p-0"><Loading q={q} />
      {q.data && (!q.data.items.length ? <Empty text="No custom OIDs." /> : <TableWrap><table className="tbl"><thead><tr><th>Name</th><th>OID</th><th>Method</th><th>Type</th>
        <th>Applies to</th><th>Version</th><th>Enabled</th><th /></tr></thead>
        <tbody>{q.data.items.map((c: any) => <tr key={c.id}><td className="font-mono text-xs">{c.name}{c.description && <div className="text-2xs text-muted">{c.description}</div>}</td>
          <td className="font-mono text-2xs">{c.oid}</td><td className="text-xs">{c.method}</td><td className="text-xs">{c.value_type}{c.unit && ` (${c.unit})`}{c.scale !== 1 && ` ×${c.scale}`}</td>
          <td className="text-xs">{[c.vendor || "any vendor", c.product_line, c.switch_ids.length ? `${c.switch_ids.length} device(s)` : "all matching devices"].filter(Boolean).join(" · ")}</td>
          <td className="num">{c.version}</td><td>{c.enabled ? "yes" : "no"}</td>
          <td className="whitespace-nowrap"><button className="link text-xs mr-2" onClick={() => setHist(c)}>History</button>{admin && <button className="link text-xs" onClick={() => setEdit(c)}>Edit</button>}</td></tr>)}</tbody></table></TableWrap>)}</Card>
    {edit !== undefined && <CustomForm c={edit} onClose={() => setEdit(undefined)} />}
    {hist && <CustomHistory c={hist} admin={admin} onClose={() => setHist(null)} />}
  </div>;
}

function CustomForm({ c, onClose }: { c: any | null; onClose: () => void }) {
  const qc = useQueryClient();
  const devs = useQuery({ queryKey: ["snmp-vendors"], queryFn: () => api<any>("/snmp/vendors") });
  const [f, setF] = useState<any>(() => ({ ...CUSTOM_BLANK, ...(c || {}) }));
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value });
  const done = () => { qc.invalidateQueries({ queryKey: ["snmp-custom"] }); onClose(); };
  const body = () => ({ ...Object.fromEntries(Object.keys(CUSTOM_BLANK).map((k) => [k, f[k]])), scale: Number(f.scale) || 1 });
  const save = useMutation({ mutationFn: () => api(c ? `/snmp/custom/${c.id}` : "/snmp/custom", { method: c ? "PUT" : "POST", body: body() }), onSuccess: done });
  const del = useMutation({ mutationFn: () => api(`/snmp/custom/${c.id}`, { method: "DELETE" }), onSuccess: done });
  const inp = (k: string, l: string, p: any = {}) => <div><label className="label">{l}</label><input className="input w-full" value={f[k] ?? ""} onChange={set(k)} {...p} /></div>;
  return <Modal wide title={c ? `Edit ${c.name}` : "Add a custom OID"} onClose={onClose}>
    <div className="grid gap-2 sm:grid-cols-3">
      {inp("name", "Name (metric custom:<name>)", { placeholder: "fgt_ssl_vpn_users" })}{inp("oid", "OID (numeric)", { placeholder: "1.3.6.1.4.1.12356.101.12.2.3.1.2" })}
      <div><label className="label">Method</label><select className="input w-full" value={f.method} onChange={set("method")}><option value="get">GET (one scalar)</option><option value="walk">WALK (one table column)</option></select></div>
      <div><label className="label">Value type</label><select className="input w-full" value={f.value_type} onChange={set("value_type")}>
        {[["gauge", "gauge"], ["counter", "counter (rate per second)"], ["state", "state"], ["info", "info (text, not graphed)"]].map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></div>
      {inp("unit", "Unit")}{inp("scale", "Multiply by", { type: "number", step: "any" })}
      <div><label className="label">Vendor</label><select className="input w-full" value={f.vendor} onChange={set("vendor")}><option value="">Any</option>
        {["cisco", "fortinet", "juniper", "ruckus", "generic"].map((v) => <option key={v}>{v}</option>)}</select></div>
      {inp("product_line", "Product line (optional)", { placeholder: "FortiGate" })}
      <label className="flex items-center gap-2 text-sm mt-5"><input type="checkbox" checked={f.enabled} onChange={set("enabled")} /> Enabled</label>
      <div className="sm:col-span-3"><label className="label">Only these devices (none = every matching device)</label>
        <div className="max-h-32 overflow-auto border border-line rounded p-2 grid sm:grid-cols-3 gap-1">{(devs.data?.devices || []).map((d: any) =>
          <label key={d.id} className="flex items-center gap-1 text-xs"><input type="checkbox" checked={f.switch_ids.includes(d.id)}
            onChange={() => setF({ ...f, switch_ids: f.switch_ids.includes(d.id) ? f.switch_ids.filter((x: number) => x !== d.id) : [...f.switch_ids, d.id] })} />{d.name}</label>)}</div></div>
      <div className="sm:col-span-3">{inp("description", "Description")}</div>
    </div>
    <p className="text-2xs text-muted mt-2">Tip: try the OID first with "Test an OID" on the MIB / OID Registry tab.</p>
    <Err e={save.error || del.error} />
    <div className="flex justify-end gap-2 mt-3">{c && <button className="btn mr-auto text-red-300" onClick={() => confirm(`Delete ${c.name}?`) && del.mutate()}>Delete</button>}
      <button className="btn" onClick={onClose}>Cancel</button><button className="btn btn-primary" disabled={save.isPending || !f.name || !f.oid} onClick={() => save.mutate()}>Save</button></div>
  </Modal>;
}

function CustomHistory({ c, admin, onClose }: { c: any; admin: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["snmp-custom-v", c.id], queryFn: () => api<any>(`/snmp/custom/${c.id}/versions`) });
  const rb = useMutation({ mutationFn: (v: number) => api(`/snmp/custom/${c.id}/rollback/${v}`, { method: "POST" }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["snmp-custom"] }); qc.invalidateQueries({ queryKey: ["snmp-custom-v", c.id] }); } });
  return <Modal wide title={`History: ${c.name}`} onClose={onClose}><Loading q={q} /><Err e={rb.error} />
    {q.data && <TableWrap maxH="max-h-96"><table className="tbl"><thead><tr><th className="num">Version</th><th>Change</th><th>By</th><th>When</th><th>Definition</th><th /></tr></thead>
      <tbody>{q.data.items.map((v: any) => <tr key={v.version}><td className="num">{v.version}</td><td className="text-xs">{v.action}</td><td className="text-xs">{v.by}</td>
        <td className="text-xs"><Time v={v.at} /></td><td className="font-mono text-2xs">{v.data.oid} · {v.data.method} · {v.data.value_type}{v.data.unit && ` · ${v.data.unit}`}</td>
        <td>{admin && v.version !== c.version && v.action !== "delete" && <button className="link text-xs" onClick={() => rb.mutate(v.version)}>Restore</button>}</td></tr>)}</tbody></table></TableWrap>}
  </Modal>;
}

// ------------------------------------------------------------------ MIB modules
function Mibs() {
  const admin = useAdmin();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["snmp-mibs"], queryFn: () => api<any>("/snmp/mibs") });
  const [view, setView] = useState<number | null>(null);
  const [msg, setMsg] = useState("");
  const imp = useMutation({ mutationFn: (b: any) => api<any>("/snmp/mibs", { method: "POST", body: b }),
    onSuccess: (r) => { setMsg(r.unchanged ? `${r.name}: identical to the stored version` : `${r.name}: ${r.objects} definitions${r.unresolved.length ? `, unresolved parents: ${r.unresolved.join(", ")} (import those modules first)` : ""}`);
      qc.invalidateQueries({ queryKey: ["snmp-mibs"] }); } });
  const act = useMutation({ mutationFn: ({ id, op }: any) => op === "rollback" ? api(`/snmp/mibs/${id}/rollback`, { method: "POST" }) : op === "delete" ?
    api(`/snmp/mibs/${id}`, { method: "DELETE" }) : api(`/snmp/mibs/${id}`, { method: "PUT", body: { enabled: op === "enable" } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["snmp-mibs"] }) });
  const onFile = async (e: any) => {
    for (const file of Array.from(e.target.files as FileList)) {
      if (file.size > 2 * 1024 * 1024) { setMsg(`${file.name}: larger than 2 MB`); continue; }
      await imp.mutateAsync({ filename: file.name, content: await file.text() }).catch(() => undefined);
    }
    e.target.value = "";
  };
  return <div className="space-y-4">
    <div className="flex flex-wrap items-center gap-2"><p className="text-xs text-muted flex-1 min-w-[18rem]">Imported MIB modules name OIDs in search results, OID tests and trap varbinds. Files are
      parsed as text (OBJECT-TYPE / OBJECT IDENTIFIER / NOTIFICATION-TYPE assignments) and never executed. A definition in a MIB does not mean a device supports it — the
      support matrix only counts what devices actually answered. Import dependencies (e.g. FORTINET-CORE-MIB) before the modules that use them.</p>
      {admin && <label className="btn btn-primary cursor-pointer">Import MIB files<input type="file" multiple accept=".mib,.my,.txt,text/plain" className="hidden" onChange={onFile} /></label>}
      <a className="btn" href="/api/snmp/export" target="_blank" rel="noreferrer">Export profiles (JSON)</a></div>
    {msg && <div className="text-sm">{msg}</div>}<Err e={imp.error || act.error} />
    <Card title="MIB modules" bodyClass="p-0"><Loading q={q} />
      {q.data && (!q.data.items.length ? <Empty text="No MIB modules imported. Built-in metric definitions and standard notifications work without any." /> :
        <TableWrap><table className="tbl"><thead><tr><th>Module</th><th className="num">Definitions</th><th>Imports</th><th>Unresolved</th><th className="num">Version</th><th>Imported</th><th>Enabled</th><th /></tr></thead>
          <tbody>{q.data.items.map((m: any) => <tr key={m.id}><td><button className="link" onClick={() => setView(m.id)}>{m.name}</button></td><td className="num">{m.objects}</td>
            <td className="text-2xs max-w-[16rem]">{m.imports.join(", ") || "—"}</td><td className="text-2xs text-amber-300">{m.unresolved.join(", ") || <span className="text-muted">—</span>}</td>
            <td className="num">{m.version}</td><td className="text-xs">{m.imported_by} · <Time v={m.imported_at} /></td><td>{m.enabled ? "yes" : "no"}</td>
            <td className="whitespace-nowrap">{admin && <>
              <button className="link text-xs mr-2" onClick={() => act.mutate({ id: m.id, op: m.enabled ? "disable" : "enable" })}>{m.enabled ? "Disable" : "Enable"}</button>
              {m.version > 1 && <button className="link text-xs mr-2" onClick={() => act.mutate({ id: m.id, op: "rollback" })}>Roll back</button>}
              <button className="link text-xs text-red-300" onClick={() => confirm(`Delete ${m.name}?`) && act.mutate({ id: m.id, op: "delete" })}>Delete</button></>}</td></tr>)}</tbody></table></TableWrap>)}</Card>
    {view && <MibView id={view} onClose={() => setView(null)} />}
  </div>;
}

function MibView({ id, onClose }: { id: number; onClose: () => void }) {
  const q = useQuery({ queryKey: ["snmp-mib", id], queryFn: () => api<any>(`/snmp/mibs/${id}`) });
  const [f, setF] = useState("");
  const defs = (q.data?.definitions || []).filter((d: any) => !f || d.name.toLowerCase().includes(f.toLowerCase()) || d.oid.startsWith(f));
  return <Modal wide title={q.data?.name || "MIB module"} onClose={onClose}><Loading q={q} />
    <input className="input w-full mb-2" placeholder="Filter by name or OID" value={f} onChange={(e) => setF(e.target.value)} />
    <TableWrap maxH="max-h-[28rem]"><table className="tbl"><thead><tr><th>Name</th><th>OID</th><th>Kind</th><th>Syntax</th><th>Access</th></tr></thead>
      <tbody>{defs.slice(0, 1000).map((d: any) => <tr key={d.name}><td className="text-xs" title={d.description}>{d.name}</td><td className="font-mono text-2xs">{d.oid}</td>
        <td className="text-2xs">{d.kind}</td><td className="text-2xs">{d.syntax || "—"}</td><td className="text-2xs">{d.access || "—"}</td></tr>)}</tbody></table></TableWrap>
  </Modal>;
}

// ------------------------------------------------------------------ support matrix
function Matrix() {
  const q = useQuery({ queryKey: ["snmp-matrix"], queryFn: () => api<any>("/snmp/support-matrix") });
  const [onlyRelevant, setOnly] = useState(true);
  const d = q.data;
  const metrics = useMemo(() => !d ? [] : d.metrics.filter((m: any) => !onlyRelevant || d.columns.some((c: any) => c.cells[m.key] && c.cells[m.key] !== "not_applicable")), [d, onlyRelevant]);
  return <div className="space-y-4">
    <p className="text-xs text-muted">One column per vendor product line in your inventory. <b>Observed</b> = at least one of these devices has returned the metric; <b>implemented</b> = the adapter asks
      for it but no device of this line has answered yet; <b>unsupported</b> = every device asked answered noSuchObject / empty; <b>failing</b> = requests error. Nothing is marked observed from a
      MIB definition or a test fixture.</p>
    <Loading q={q} />
    {d && <>
      <div className="flex flex-wrap gap-3 text-xs">{Object.entries(CELL).map(([k, [cls, l]]) => <span key={k} className={`pill ${cls}`}>{l}</span>)}
        <label className="flex items-center gap-1 ml-auto"><input type="checkbox" checked={onlyRelevant} onChange={(e) => setOnly(e.target.checked)} /> hide metrics no column uses</label></div>
      {!d.columns.length ? <Empty text="No devices in your scope yet." /> : <Card title="Metric support by product line" bodyClass="p-0">
        <TableWrap maxH="max-h-[40rem]"><table className="tbl"><thead><tr><th>Metric</th>{d.columns.map((c: any) => <th key={c.vendor + c.product_line} className="text-center text-xs">
          {c.vendor}<div className="text-2xs text-muted">{c.product_line} · {c.devices}</div></th>)}</tr></thead>
          <tbody>{metrics.map((m: any) => <tr key={m.key}><td className="font-mono text-2xs">{m.key}</td>{d.columns.map((c: any) => {
            const [cls, l] = CELL[c.cells[m.key]] || CELL.not_applicable;
            return <td key={c.vendor + c.product_line} className="text-center"><span className={`pill text-2xs ${cls}`}>{l}</span></td>; })}</tr>)}</tbody></table></TableWrap>
        <div className="p-3 text-xs text-muted">{d.columns.map((c: any) => { const n = matrixCounts(c.cells); return `${c.vendor} ${c.product_line}: ${n.observed} observed, ${n.unsupported} unsupported`; }).join(" · ")}</div>
      </Card>}
      <Card title="Adapters" bodyClass="p-3 text-sm">{d.adapters.map((a: any) => <div key={a.vendor}><b>{a.vendor}</b>: {a.families.join(", ") || "standard MIBs only"}</div>)}</Card>
      <Card title="Not implemented yet" bodyClass="p-0"><TableWrap><table className="tbl"><thead><tr><th>Area</th><th>Item</th><th>Why / what it needs</th></tr></thead>
        <tbody>{d.not_implemented.map((x: any, i: number) => <tr key={i}><td>{x.area}</td><td>{x.item}</td><td className="text-xs text-muted">{x.why}</td></tr>)}</tbody></table></TableWrap></Card>
    </>}
  </div>;
}
