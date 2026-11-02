import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { useMe } from "../../lib/context";
import { Card, Empty, Loading, Modal, TableWrap } from "../../components/ui";
import { Field, StateDot, useWanMeta } from "./common";
import { useGo } from "./Overview";

const BLANK = { name: "", circuit_id: "", isp_name: "", site: "", location: "", firewall_id: null as number | null, interface: "", gateway: "",
  bandwidth_mbps: null as number | null, role: "primary", target_availability: 99.5, owner: "", support_contact: "", notes: "", enabled: true, monitoring_start: null as string | null };

export function WanCircuits() {
  const me = useMe();
  const admin = me.role === "admin";
  const qc = useQueryClient();
  const go = useGo();
  const q = useQuery({ queryKey: ["wan-circuits"], queryFn: () => api<any>("/wan/circuits") });
  const [edit, setEdit] = useState<any>(null);
  const [text, setText] = useState("");
  const rows = useMemo(() => (q.data?.items || []).filter((c: any) => !text || JSON.stringify([c.label, c.isp_name, c.effective_site, c.circuit_id, c.firewall, c.gateway])
    .toLowerCase().includes(text.toLowerCase())), [q.data, text]);
  return (
    <div className="space-y-4 min-w-0">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-xs text-muted flex-1 min-w-[16rem]">A circuit is one ISP connection at a site (several per ISP and site are fine). SD-WAN members discovered from firewalls appear here
          automatically; circuits monitored only by ICMP can be added by hand. Monitored targets (gateway, WAN IP, upstream hosts) attach to a circuit; one public IP never
          identifies a circuit on its own.</p>
        <input aria-label="Search circuits" className="input py-1 w-52" placeholder="Search ISP, site, circuit ID" value={text} onChange={(e) => setText(e.target.value)} />
        {admin && <button className="btn btn-primary" onClick={() => setEdit({ ...BLANK })}>+ Add circuit</button>}
      </div>
      <Loading q={q} />
      {q.data && <Card title={`Circuits (${rows.length})`} bodyClass="p-0">
        {!rows.length ? <Empty text="No circuits yet. They appear when SD-WAN logs arrive, or add one for an ICMP-only connection." /> :
          <TableWrap><table className="tbl"><thead><tr><th>Circuit</th><th>ISP</th><th>Site / location</th><th>Device / interface</th><th>Circuit ID</th>
            <th className="num">Bandwidth</th><th>Role</th><th className="num">SLA target</th><th>Monitored targets</th><th>Owner</th>{admin && <th />}</tr></thead>
            <tbody>{rows.map((c: any) => <tr key={c.id} className={c.enabled ? "" : "opacity-60"}>
              <td className="font-medium">{c.label}{c.hidden && <span className="pill bg-slate-700/60 text-slate-300 ml-1">hidden</span>}{!c.enabled && <span className="pill bg-slate-700/60 text-slate-300 ml-1">disabled</span>}</td>
              <td>{c.isp_name || <span className="text-muted" title="discovered ASN organisation">{c.as_org || "—"}</span>}</td>
              <td>{c.effective_site || "—"}{c.location && <div className="text-2xs text-muted">{c.location}</div>}</td>
              <td className="text-xs">{c.firewall ? `${c.firewall} / ${c.interface}` : "—"}{c.gateway && <div className="font-mono text-2xs text-muted">gw {c.gateway}</div>}</td>
              <td className="font-mono text-xs">{c.circuit_id || "—"}</td>
              <td className="num">{c.bandwidth_mbps ? (c.bandwidth_mbps >= 1000 ? `${(c.bandwidth_mbps / 1000).toFixed(1)} Gbps` : `${c.bandwidth_mbps} Mbps`) : "—"}</td>
              <td>{c.role}</td><td className="num">{c.target_availability}%</td>
              <td>{c.targets.length ? c.targets.map((t: any) => <button key={t.id} className="flex items-center gap-1 text-xs hover:underline" onClick={() => go("live", { q: t.address })}>
                <StateDot s={t.state} /><span className="font-mono">{t.address}</span></button>) : <span className="text-muted text-xs">none{c.gateway && " (gateway suggested on the Live tab)"}</span>}</td>
              <td className="text-xs">{c.owner || "—"}{c.support_contact && <div className="text-2xs text-muted">{c.support_contact}</div>}</td>
              {admin && <td><button className="btn py-0.5 text-xs" onClick={() => setEdit(c)}>Edit</button></td>}
            </tr>)}</tbody></table></TableWrap>}
      </Card>}
      {q.data?.unlinked_targets?.length > 0 && <Card title="Targets not linked to a circuit">
        <p className="text-xs text-muted mb-2">Each counts as its own circuit in summaries until it is linked (Live tab → Edit → Circuit).</p>
        <div className="flex flex-wrap gap-2">{q.data.unlinked_targets.map((t: any) => <span key={t.id} className="pill bg-slate-800 text-slate-300">{t.name} · <span className="font-mono">{t.address}</span></span>)}</div>
      </Card>}
      {edit && <CircuitForm c={edit} onClose={() => { setEdit(null); qc.invalidateQueries({ queryKey: ["wan-circuits"] }); qc.invalidateQueries({ queryKey: ["wan-meta"] }); }} />}
    </div>
  );
}

function CircuitForm({ c, onClose }: { c: any; onClose: () => void }) {
  const meta = useWanMeta();
  const discovered = !!(c.id && c.firewall_id && c.interface);
  const [f, setF] = useState<any>({ ...BLANK, ...c, isp_name: c.isp_name || c.as_org || "", monitoring_start: c.monitoring_start ? c.monitoring_start.slice(0, 10) : "" });
  const body = () => ({ ...Object.fromEntries(Object.keys(BLANK).map((k) => [k, f[k]])), bandwidth_mbps: f.bandwidth_mbps === "" || f.bandwidth_mbps == null ? null : Number(f.bandwidth_mbps),
    target_availability: Number(f.target_availability), firewall_id: f.firewall_id ? Number(f.firewall_id) : null,
    monitoring_start: f.monitoring_start ? new Date(`${f.monitoring_start}T00:00:00Z`).toISOString() : null });
  const save = useMutation({ mutationFn: () => api(c.id ? `/wan/circuits/${c.id}` : "/wan/circuits", { method: c.id ? "PUT" : "POST", body: body() }), onSuccess: onClose });
  const del = useMutation({ mutationFn: () => api(`/wan/circuits/${c.id}`, { method: "DELETE" }), onSuccess: onClose });
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value });
  const inp = (k: string, l: string, p: any = {}, hint?: string) => <Field label={l} hint={hint}><input className="input w-full" value={f[k] ?? ""} onChange={set(k)} {...p} /></Field>;
  return (
    <Modal title={c.id ? `Edit circuit ${c.label || ""}` : "Add circuit"} onClose={onClose} wide>
      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
        {inp("isp_name", "ISP / provider", { placeholder: "TTSL" })}{inp("name", "Circuit name", { placeholder: "TTSL 1.5 Gbps ILL" })}{inp("circuit_id", "Circuit ID", { placeholder: "provider reference" })}
        {inp("site", "Site / warehouse", {}, discovered ? "empty: the firewall's site" : undefined)}{inp("location", "Location (address, rack)")}
        <Field label="Firewall"><select className="input w-full" disabled={discovered} value={f.firewall_id || ""} onChange={(e) => setF({ ...f, firewall_id: e.target.value || null })}>
          <option value="">— none —</option>{(meta.data?.firewalls || []).map((x: any) => <option key={x.id} value={x.id}>{x.name}</option>)}</select></Field>
        {inp("interface", "WAN interface", { disabled: discovered, placeholder: "port1 / wan1" })}{inp("gateway", "Gateway IP", { placeholder: "monitored gateway" })}
        {inp("bandwidth_mbps", "Bandwidth (Mbps)", { type: "number", min: 0 })}
        <Field label="Role"><select className="input w-full" value={f.role} onChange={set("role")}><option value="primary">Primary</option><option value="backup">Backup</option></select></Field>
        {inp("target_availability", "SLA availability target (%)", { type: "number", step: "0.01" })}{inp("monitoring_start", "Monitoring start", { type: "date" })}
        {inp("owner", "Owner")}{inp("support_contact", "Provider support contact")}
        <Field label="Notes"><textarea className="input w-full h-16" value={f.notes} onChange={set("notes")} /></Field>
        <label className="text-sm flex items-center gap-2"><input type="checkbox" checked={f.enabled} onChange={set("enabled")} />Enabled</label>
      </div>
      {discovered && <p className="text-2xs text-muted mt-2">Discovered from {c.firewall} / {c.interface}: the device and interface come from the firewall; SD-WAN outage detection settings
        stay on the SD-WAN tab.</p>}
      {(save.error || del.error) && <div role="alert" className="text-sm text-red-400 mt-2">{((save.error || del.error) as Error).message}</div>}
      <div className="flex gap-2 mt-3">
        <button className="btn btn-primary" disabled={!f.isp_name || save.isPending} onClick={() => save.mutate()}>Save</button>
        {c.id && !c.firewall_id && <button className="btn btn-danger ml-auto" onClick={() => confirm("Delete this circuit? Its outage history stays.") && del.mutate()}>Delete</button>}
      </div>
    </Modal>
  );
}
