/** Add Device: any SNMP device (switch, router, firewall, controller, AP, server, UPS, printer, …). The server validates
 *  the address, pings it, tests SNMP, identifies vendor / model / OS / type, discovers interfaces and only then saves it
 *  (/api/devices/onboard); every step's result is shown. Nothing is saved when SNMP fails. */
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { Modal } from "../../components/ui";

const BLANK = { name: "", address: "", fqdn: "", credential_id: 0, device_type: "", template_id: 0, site: "", building: "", floor: "", rack: "", role: "",
  tags: "", notes: "", poll_interval_seconds: "", icmp_enabled: true, snmp_enabled: true, port: 161, timeout_ms: 3000, retries: 1 };
const OUTCOME: Record<string, string> = { added: "Device added", partial: "Device added — partially discovered", inventory_only: "Added without SNMP monitoring",
  auth_failed: "SNMP authentication failed", unreachable: "Device unreachable", snmp_no_response: "No SNMP response", unsupported_response: "Unsupported SNMP response",
  duplicate: "Already monitored", invalid: "Invalid configuration", snmp_failed: "SNMP test failed" };
const DOT: Record<string, string> = { ok: "dot-ok", failed: "dot-bad", skipped: "dot-unknown" };

export function AddDevice({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const nav = useNavigate();
  const [f, setF] = useState<any>(BLANK);
  const [adv, setAdv] = useState(false);
  const meta = useQuery<any>({ queryKey: ["devices-meta"], queryFn: () => api("/devices/meta"), staleTime: 300_000 });
  const creds = useQuery<any>({ queryKey: ["switch-creds"], queryFn: () => api("/switches/admin/credentials") });
  const run = useMutation<any>({ mutationFn: () => api("/devices/onboard", { method: "POST", body: {
    ...f, credential_id: Number(f.credential_id), template_id: Number(f.template_id) || null, tags: String(f.tags).split(",").map((t: string) => t.trim()).filter(Boolean),
    poll_interval_seconds: f.poll_interval_seconds ? Number(f.poll_interval_seconds) : null, port: Number(f.port), timeout_ms: Number(f.timeout_ms), retries: Number(f.retries) } }),
    onSuccess: (r) => { if (r.ok) for (const k of ["switch-inv", "switch-overview", "switch-filters", "all-ifs"]) qc.invalidateQueries({ queryKey: [k] }); } });
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value });
  const inp = (k: string, l: string, p: any = {}) => <label className="block min-w-0"><span className="label">{l}</span><input className="input w-full" value={f[k]} onChange={set(k)} {...p} /></label>;
  const r = run.data;
  const ready = f.name.trim() && (f.address.trim() || f.fqdn.trim()) && Number(f.credential_id) > 0;
  return <Modal title="Add device" onClose={onClose} wide>
    {!r?.ok && <>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {inp("name", "Device name", { placeholder: "DC1-CORE-RTR01", autoFocus: true })}
        {inp("address", "Management IP", { placeholder: "10.20.0.1", inputMode: "decimal" })}
        {inp("fqdn", "FQDN (optional)", { placeholder: "core-rtr01.example.net" })}
        <label className="block min-w-0"><span className="label">SNMP profile</span><select className="input w-full" value={f.credential_id} onChange={set("credential_id")}>
          <option value={0}>— choose —</option>{(creds.data?.items || []).map((c: any) => <option key={c.id} value={c.id}>{c.name} · SNMP{c.version}{c.version === "v3" ? ` ${c.security_level}` : ""}</option>)}</select></label>
        <label className="block min-w-0"><span className="label">Device type</span><select className="input w-full" value={f.device_type} onChange={set("device_type")}>
          <option value="">Detect automatically</option>{(meta.data?.device_types || []).map((t: any) => <option key={t.key} value={t.key}>{t.label}</option>)}</select></label>
        <label className="block min-w-0"><span className="label">Monitoring template</span><select className="input w-full" value={f.template_id} onChange={set("template_id")}>
          <option value={0}>By device type</option>{(meta.data?.templates || []).map((t: any) => <option key={t.id} value={t.id}>{t.name}</option>)}</select></label>
        {inp("site", "Site")}{inp("building", "Location / building")}{inp("rack", "Rack")}
        {inp("tags", "Tags (comma-separated)", { placeholder: "core, dc1" })}
        {inp("poll_interval_seconds", "Polling interval (s)", { placeholder: "from template (60)", inputMode: "numeric" })}
        {inp("notes", "Description")}
      </div>
      <div className="flex flex-wrap items-center gap-4 mt-3 text-sm">
        <label className="flex items-center gap-2"><input type="checkbox" checked={f.icmp_enabled} onChange={set("icmp_enabled")} /> ICMP monitoring</label>
        <label className="flex items-center gap-2"><input type="checkbox" checked={f.snmp_enabled} onChange={set("snmp_enabled")} /> SNMP monitoring</label>
        <button type="button" className="btn btn-ghost btn-sm" aria-expanded={adv} onClick={() => setAdv(!adv)}>{adv ? "Hide" : "Show"} SNMP options</button>
      </div>
      {adv && <div className="grid gap-3 sm:grid-cols-3 mt-3">{inp("port", "SNMP port", { inputMode: "numeric" })}{inp("timeout_ms", "Timeout (ms)", { inputMode: "numeric" })}
        {inp("retries", "Retries", { inputMode: "numeric" })}</div>}
      <p className="text-2xs text-subtle mt-3">SNMP communities and SNMPv3 passphrases live only in the SNMP profile (encrypted, never shown again). The address must be inside an
        authorised management network (Settings → Networks). Sentinel only reads (GET / GETNEXT / GETBULK).</p>
    </>}
    {r && <div className="mt-4 space-y-3">
      <div className={`text-sm font-medium ${r.ok ? "" : "text-red-400"}`}>{OUTCOME[r.outcome] || r.outcome}</div>
      {r.message && <p className="text-sm text-muted">{r.message}</p>}
      {r.hint && <p className="text-xs text-subtle">{r.hint}</p>}
      <ol className="space-y-1.5">{(r.steps || []).map((s: any) => <li key={s.key} className="flex items-start gap-2 text-sm">
        <span className={`dot mt-1.5 ${DOT[s.status]}`} role="img" aria-label={s.status} /><span className="min-w-[13rem]">{s.label}</span>
        <span className="text-muted text-xs mt-0.5 min-w-0 break-words">{s.detail}</span></li>)}</ol>
    </div>}
    {run.error && <div role="alert" className="text-sm text-red-400 mt-3">{(run.error as Error).message}</div>}
    <div className="flex flex-wrap gap-2 mt-4">
      {r?.ok ? <>
        <button className="btn btn-primary" onClick={() => { onClose(); nav(`/switches/${r.id}`); }}>Open device</button>
        <button className="btn" onClick={() => { run.reset(); setF(BLANK); }}>Add another</button>
        <button className="btn btn-ghost" onClick={onClose}>Close</button>
      </> : <>
        <button className="btn btn-primary" disabled={!ready || run.isPending} onClick={() => run.mutate()}>{run.isPending ? "Testing and discovering…" : r ? "Try again" : "Test and add"}</button>
        {r?.existing_id && <button className="btn" onClick={() => { onClose(); nav(`/switches/${r.existing_id}`); }}>Open existing device</button>}
        <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
      </>}
    </div>
  </Modal>;
}
