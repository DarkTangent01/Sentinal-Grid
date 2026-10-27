import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../lib/api";
import { useData, useMe } from "../lib/context";
import { fmtBytes, fmtNum } from "../lib/format";
import { Card, Empty, Loading, Modal, TableWrap, Tabs, Time, useDebounced } from "../components/ui";

// ---------------------------------------------------------------- spec types (mirror app/hardening/spec.py)
interface Address { name: string; subnet?: string | null; fqdn?: string | null; comment?: string }
interface Group { name: string; members: string[]; comment?: string }
interface Service { name: string; tcp: string[]; udp: string[]; comment?: string }
interface UrlEntry { url: string; type: "simple" | "wildcard" | "regex"; action: "allow" | "block" | "monitor" | "exempt" }
interface UrlFilter { table_id: number; name: string; entries: UrlEntry[]; block_others: boolean; profile_name?: string | null }
interface Policy {
  name: string; srcintf: string[]; dstintf: string[]; srcaddr: string[]; dstaddr: string[]; service: string[];
  action: "accept" | "deny"; nat: boolean; schedule: string; webfilter_profile?: string | null; ssl_ssh_profile: string;
  logtraffic: "all" | "utm" | "disable"; comments: string;
}
interface Spec { vdom?: string | null; addresses: Address[]; address_groups: Group[]; services: Service[]; service_groups: Group[]; url_filters: UrlFilter[]; policies: Policy[] }
interface Plan { id: number; name: string; description: string; firewall_id: number | null; status: string; spec: Spec; last_check: any; updated_by: string; updated_at: string; last_exported_at: string | null }

const EMPTY: Spec = { vdom: null, addresses: [], address_groups: [], services: [], service_groups: [], url_filters: [], policies: [] };
const NEW_POLICY: Policy = { name: "", srcintf: [], dstintf: [], srcaddr: ["all"], dstaddr: ["all"], service: [], action: "accept", nat: true,
  schedule: "always", webfilter_profile: null, ssl_ssh_profile: "certificate-inspection", logtraffic: "all", comments: "" };
// well-known ports that map to predefined FortiOS services (others become custom services)
const PREDEFINED: Record<string, string> = { "TCP/80": "HTTP", "TCP/443": "HTTPS", "UDP/53": "DNS", "TCP/53": "DNS", "UDP/123": "NTP",
  "TCP/22": "SSH", "TCP/25": "SMTP", "TCP/465": "SMTPS", "TCP/993": "IMAPS", "TCP/995": "POP3S", "TCP/3389": "RDP", "TCP/21": "FTP" };

const list = (s: string) => s.split(/[,\s]+/).map((x) => x.trim()).filter(Boolean);
const join = (a?: string[]) => (a || []).join(", ");

function ListInput({ value, onChange, placeholder, label }: { value: string[]; onChange: (v: string[]) => void; placeholder?: string; label: string }) {
  const [text, setText] = useState(join(value));
  useEffect(() => setText(join(value)), [value.join("|")]);
  return <input aria-label={label} className="input w-full" placeholder={placeholder} value={text}
    onChange={(e) => setText(e.target.value)} onBlur={() => onChange(list(text))} />;
}

function Section({ title, count, onAdd, children, hint, readOnly }: { title: string; count: number; onAdd: () => void; children: React.ReactNode; hint?: string; readOnly: boolean }) {
  return (
    <Card title={`${title} (${count})`} right={!readOnly && <button className="btn" onClick={onAdd}>+ Add</button>}>
      {hint && <p className="text-xs text-muted mb-2">{hint}</p>}
      {count ? children : <Empty text="None." />}
    </Card>
  );
}

const Del = ({ onClick, readOnly }: { onClick: () => void; readOnly: boolean }) =>
  readOnly ? null : <button aria-label="Remove" className="text-muted hover:text-red-400 px-1" onClick={onClick}>✕</button>;

// ---------------------------------------------------------------- page
export function Hardening() {
  const me = useMe();
  const qc = useQueryClient();
  const plans = useQuery({ queryKey: ["hardening-plans"], queryFn: () => api<Plan[]>("/hardening/plans") });
  const fws = useQuery({ queryKey: ["firewalls"], queryFn: () => api<any[]>("/firewalls") });
  const [selId, setSelId] = useState<number | "new" | null>(null);
  const selected = plans.data?.find((p) => p.id === selId) || null;

  useEffect(() => {
    if (selId === null && plans.data?.length) setSelId(plans.data[0].id);
  }, [plans.data, selId]);

  return (
    <div className="space-y-3 min-w-0">
      <div className="card !block p-3 border-sky-800/60 bg-sky-500/5 text-xs text-sky-100">
        The SIEM stays <b>read-only</b>. Plans are rendered as FortiOS CLI that an engineer reviews and applies on the firewall
        (take a config backup first). Suggestions come from logged traffic. Confirm business requirements before restricting access.
      </div>
      <div className="grid-cards lg:grid-cols-[16rem_1fr]">
        <Card title="Plans" right={me.role === "admin" && <button className="btn btn-primary" onClick={() => setSelId("new")}>+ New</button>}>
          <Loading q={plans} />
          {plans.data && !plans.data.length && <Empty text="No plans yet." />}
          <ul className="space-y-1">
            {(plans.data || []).map((p) => (
              <li key={p.id}>
                <button onClick={() => setSelId(p.id)} className={`w-full text-left rounded px-2 py-1.5 border ${selId === p.id ? "border-brand-500/60 bg-brand-500/10" : "border-transparent hover:bg-slate-800/50"}`}>
                  <div className="text-sm truncate">{p.name}</div>
                  <div className="text-2xs text-muted">{p.status} · <Time v={p.updated_at} /></div>
                </button>
              </li>
            ))}
          </ul>
        </Card>
        <div className="min-w-0">
          {selId === "new" && <PlanEditor key="new" fws={fws.data || []} onSaved={(id) => { qc.invalidateQueries({ queryKey: ["hardening-plans"] }); setSelId(id); }} />}
          {selected && <PlanEditor key={selected.id} plan={selected} fws={fws.data || []}
            onSaved={() => qc.invalidateQueries({ queryKey: ["hardening-plans"] })}
            onDeleted={() => { qc.invalidateQueries({ queryKey: ["hardening-plans"] }); setSelId(null); }} />}
          {selId === null && !plans.isLoading && <Card><Empty text={me.role === "admin" ? "Create a plan to start." : "No plan selected."} /></Card>}
        </div>
      </div>
    </div>
  );
}

function PlanEditor({ plan, fws, onSaved, onDeleted }: { plan?: Plan; fws: any[]; onSaved: (id: number) => void; onDeleted?: () => void }) {
  const me = useMe();
  const readOnly = me.role !== "admin";
  const [name, setName] = useState(plan?.name || "New hardening plan");
  const [description, setDescription] = useState(plan?.description || "");
  const [firewallId, setFirewallId] = useState<number | null>(plan?.firewall_id ?? null);
  const [status, setStatus] = useState(plan?.status || "draft");
  const [spec, setSpec] = useState<Spec>({ ...EMPTY, ...(plan?.spec || {}) });
  const [msg, setMsg] = useState("");
  const [cli, setCli] = useState<any>(null);
  const [check, setCheck] = useState<any>(plan?.last_check && Object.keys(plan.last_check).length ? plan.last_check : null);
  const [tab, setTab] = useState("services");

  const upd = <K extends keyof Spec>(k: K, v: Spec[K]) => setSpec((s) => ({ ...s, [k]: v }));
  const updAt = <K extends "addresses" | "address_groups" | "services" | "service_groups" | "url_filters" | "policies">(k: K, i: number, patch: Partial<Spec[K][number]>) =>
    setSpec((s) => ({ ...s, [k]: (s[k] as any[]).map((x, j) => (j === i ? { ...x, ...patch } : x)) }));
  const delAt = (k: keyof Spec, i: number) => setSpec((s) => ({ ...s, [k]: (s[k] as any[]).filter((_, j) => j !== i) }));

  // live validation against the same server-side rules used on save
  const dSpec = useDebounced(spec, 500);
  const val = useQuery({ queryKey: ["hardening-validate", dSpec], queryFn: () => api<any>("/hardening/validate", { method: "POST", body: dSpec }) });

  const save = useMutation({
    mutationFn: () => {
      const body = { name, description, firewall_id: firewallId, status, spec };
      return plan ? api<Plan>(`/hardening/plans/${plan.id}`, { method: "PUT", body }) : api<Plan>("/hardening/plans", { method: "POST", body });
    },
    onSuccess: (p) => { setMsg("Saved."); onSaved(p.id); },
    onError: (e) => setMsg((e as ApiError).message),
  });
  const del = useMutation({ mutationFn: () => api(`/hardening/plans/${plan!.id}`, { method: "DELETE" }), onSuccess: () => onDeleted?.() });
  const runCheck = useMutation({ mutationFn: () => api<any>(`/hardening/plans/${plan!.id}/check`, { method: "POST" }), onSuccess: setCheck, onError: (e) => setMsg((e as Error).message) });
  const genCli = useMutation({ mutationFn: () => api<any>(`/hardening/plans/${plan!.id}/cli`), onSuccess: setCli, onError: (e) => setMsg((e as Error).message) });

  const dirty = !plan || JSON.stringify({ name, description, firewallId, status, spec }) !==
    JSON.stringify({ name: plan.name, description: plan.description, firewallId: plan.firewall_id, status: plan.status, spec: { ...EMPTY, ...plan.spec } });
  const realFws = fws.filter((f) => !f.is_demo);

  return (
    <div className="space-y-3 min-w-0">
      <Card title={plan ? `Plan #${plan.id}` : "New plan"} right={
        <div className="flex flex-wrap gap-2">
          {!readOnly && <button className="btn btn-primary" disabled={save.isPending || !val.data?.valid} onClick={() => save.mutate()}>{dirty ? "Save" : "Saved"}</button>}
          {plan && !readOnly && <button className="btn" disabled={dirty || !firewallId || runCheck.isPending} title={!firewallId ? "Select a target firewall" : dirty ? "Save first" : ""}
            onClick={() => runCheck.mutate()}>{runCheck.isPending ? "Checking…" : "Check against firewall"}</button>}
          {plan && <button className="btn" disabled={dirty || genCli.isPending} title={dirty ? "Save first" : ""} onClick={() => genCli.mutate()}>Generate CLI</button>}
          {plan && !readOnly && <button className="btn btn-danger" onClick={() => confirm(`Delete plan "${plan.name}"?`) && del.mutate()}>Delete</button>}
        </div>}>
        <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
          <div className="xl:col-span-2"><label className="label">Name</label><input className="input w-full" disabled={readOnly} value={name} onChange={(e) => setName(e.target.value)} /></div>
          <div><label className="label">Target firewall (for checks)</label>
            <select className="input w-full" disabled={readOnly} value={firewallId ?? ""} onChange={(e) => setFirewallId(e.target.value ? Number(e.target.value) : null)}>
              <option value="">— none —</option>{realFws.map((f) => <option key={f.id} value={f.id}>{f.name}</option>)}
            </select></div>
          <div className="grid grid-cols-2 gap-2">
            <div><label className="label">VDOM (multi-VDOM only)</label><input className="input w-full" disabled={readOnly} placeholder="none" value={spec.vdom || ""} onChange={(e) => upd("vdom", e.target.value || null)} /></div>
            <div><label className="label">Status</label><select className="input w-full" disabled={readOnly} value={status} onChange={(e) => setStatus(e.target.value)}>
              <option value="draft">draft</option><option value="ready">ready</option><option value="exported">exported</option></select></div>
          </div>
          <div className="sm:col-span-2 xl:col-span-4"><label className="label">Description / change reference</label>
            <input className="input w-full" disabled={readOnly} placeholder="e.g. CHG-1234: restrict guest VLAN to web + DNS" value={description} onChange={(e) => setDescription(e.target.value)} /></div>
        </div>
        {msg && <div className={`text-xs mt-2 ${msg === "Saved." ? "text-emerald-400" : "text-red-400"}`} role="status">{msg}</div>}
        <ValidationPanel val={val.data} />
        {check && <CheckPanel check={check} />}
      </Card>

      <Suggestions firewallId={firewallId} spec={spec} setSpec={setSpec} readOnly={readOnly} />

      <Tabs value={tab} onChange={setTab} tabs={[
        { key: "services", label: `Services & groups (${spec.services.length + spec.service_groups.length})` },
        { key: "urls", label: `URL filters (${spec.url_filters.length})` },
        { key: "addresses", label: `Addresses & groups (${spec.addresses.length + spec.address_groups.length})` },
        { key: "policies", label: `Policies (${spec.policies.length})` }]} />

      {tab === "services" && <div className="grid-cards xl:grid-cols-2">
        <Section title="Custom services" count={spec.services.length} readOnly={readOnly} hint="Ports as 443 or 8000-8080, comma-separated. Use predefined FortiOS services (HTTPS, DNS…) directly in groups."
          onAdd={() => upd("services", [...spec.services, { name: "", tcp: [], udp: [] }])}>
          <TableWrap><table className="tbl"><thead><tr><th>Name</th><th>TCP ports</th><th>UDP ports</th><th /></tr></thead>
            <tbody>{spec.services.map((s, i) => <tr key={i}>
              <td className="min-w-[9rem]"><input aria-label="Service name" className="input w-full" disabled={readOnly} value={s.name} onChange={(e) => updAt("services", i, { name: e.target.value })} /></td>
              <td className="min-w-[8rem]"><ListInput label="TCP ports" value={s.tcp} onChange={(v) => updAt("services", i, { tcp: v })} placeholder="443, 8443" /></td>
              <td className="min-w-[8rem]"><ListInput label="UDP ports" value={s.udp} onChange={(v) => updAt("services", i, { udp: v })} placeholder="53" /></td>
              <td><Del readOnly={readOnly} onClick={() => delAt("services", i)} /></td></tr>)}</tbody></table></TableWrap>
        </Section>
        <Section title="Service groups" count={spec.service_groups.length} readOnly={readOnly} hint="Members: custom services above or predefined/existing services on the firewall."
          onAdd={() => upd("service_groups", [...spec.service_groups, { name: "", members: [] }])}>
          <TableWrap><table className="tbl"><thead><tr><th>Group name</th><th>Members</th><th /></tr></thead>
            <tbody>{spec.service_groups.map((g, i) => <tr key={i}>
              <td className="min-w-[10rem]"><input aria-label="Group name" className="input w-full" disabled={readOnly} value={g.name} onChange={(e) => updAt("service_groups", i, { name: e.target.value })} /></td>
              <td className="min-w-[14rem]"><ListInput label="Members" value={g.members} onChange={(v) => updAt("service_groups", i, { members: v })} placeholder="HTTPS, DNS, TCP-8443" /></td>
              <td><Del readOnly={readOnly} onClick={() => delAt("service_groups", i)} /></td></tr>)}</tbody></table></TableWrap>
        </Section>
      </div>}

      {tab === "urls" && <Section title="URL filter tables" count={spec.url_filters.length} readOnly={readOnly}
        hint="Patterns without http(s)://, e.g. *.example.com (wildcard) or www.example.com/path (simple). 'Block everything else' appends a * block entry so only listed URLs are reachable."
        onAdd={() => upd("url_filters", [...spec.url_filters, { table_id: 100 + spec.url_filters.length, name: "", entries: [], block_others: false, profile_name: "" }])}>
        <div className="space-y-4">{spec.url_filters.map((u, i) => (
          <div key={i} className="border border-line rounded p-3 space-y-2">
            <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-5 items-end">
              <div><label className="label">Table ID</label><input type="number" min={1} className="input w-full" disabled={readOnly} value={u.table_id} onChange={(e) => updAt("url_filters", i, { table_id: Number(e.target.value) })} /></div>
              <div><label className="label">Table name</label><input className="input w-full" disabled={readOnly} value={u.name} onChange={(e) => updAt("url_filters", i, { name: e.target.value })} /></div>
              <div><label className="label">Web-filter profile (optional)</label><input className="input w-full" disabled={readOnly} value={u.profile_name || ""} onChange={(e) => updAt("url_filters", i, { profile_name: e.target.value || null })} /></div>
              <label className="text-sm flex items-center gap-2"><input type="checkbox" disabled={readOnly} checked={u.block_others} onChange={(e) => updAt("url_filters", i, { block_others: e.target.checked })} />Block everything else</label>
              <div className="flex gap-2 justify-end">{!readOnly && <button className="btn" onClick={() => updAt("url_filters", i, { entries: [...u.entries, { url: "", type: "wildcard", action: "allow" }] })}>+ Entry</button>}<Del readOnly={readOnly} onClick={() => delAt("url_filters", i)} /></div>
            </div>
            <TableWrap maxH="max-h-72"><table className="tbl"><thead><tr><th>URL pattern</th><th>Type</th><th>Action</th><th /></tr></thead>
              <tbody>{u.entries.map((e, j) => <tr key={j}>
                <td className="min-w-[14rem]"><input aria-label="URL pattern" className="input w-full font-mono" disabled={readOnly} value={e.url}
                  onChange={(ev) => updAt("url_filters", i, { entries: u.entries.map((x, k) => (k === j ? { ...x, url: ev.target.value.trim() } : x)) })} /></td>
                <td><select aria-label="Type" className="input" disabled={readOnly} value={e.type} onChange={(ev) => updAt("url_filters", i, { entries: u.entries.map((x, k) => (k === j ? { ...x, type: ev.target.value as UrlEntry["type"] } : x)) })}>
                  <option>wildcard</option><option>simple</option><option>regex</option></select></td>
                <td><select aria-label="Action" className="input" disabled={readOnly} value={e.action} onChange={(ev) => updAt("url_filters", i, { entries: u.entries.map((x, k) => (k === j ? { ...x, action: ev.target.value as UrlEntry["action"] } : x)) })}>
                  <option>allow</option><option>block</option><option>monitor</option><option>exempt</option></select></td>
                <td><Del readOnly={readOnly} onClick={() => updAt("url_filters", i, { entries: u.entries.filter((_, k) => k !== j) })} /></td></tr>)}</tbody></table></TableWrap>
          </div>))}</div>
      </Section>}

      {tab === "addresses" && <div className="grid-cards xl:grid-cols-2">
        <Section title="Addresses" count={spec.addresses.length} readOnly={readOnly} hint="IPv4 host/subnet (10.10.20.0/24) or FQDN."
          onAdd={() => upd("addresses", [...spec.addresses, { name: "", subnet: "" }])}>
          <TableWrap><table className="tbl"><thead><tr><th>Name</th><th>Type</th><th>Value</th><th /></tr></thead>
            <tbody>{spec.addresses.map((a, i) => { const isFqdn = a.fqdn !== undefined && a.fqdn !== null; return <tr key={i}>
              <td className="min-w-[9rem]"><input aria-label="Address name" className="input w-full" disabled={readOnly} value={a.name} onChange={(e) => updAt("addresses", i, { name: e.target.value })} /></td>
              <td><select aria-label="Address type" className="input" disabled={readOnly} value={isFqdn ? "fqdn" : "subnet"}
                onChange={(e) => updAt("addresses", i, e.target.value === "fqdn" ? { fqdn: a.subnet || "", subnet: null } : { subnet: a.fqdn || "", fqdn: null })}>
                <option value="subnet">subnet</option><option value="fqdn">fqdn</option></select></td>
              <td className="min-w-[10rem]"><input aria-label="Address value" className="input w-full font-mono" disabled={readOnly} value={(isFqdn ? a.fqdn : a.subnet) || ""}
                onChange={(e) => updAt("addresses", i, isFqdn ? { fqdn: e.target.value.trim() } : { subnet: e.target.value.trim() })} /></td>
              <td><Del readOnly={readOnly} onClick={() => delAt("addresses", i)} /></td></tr>; })}</tbody></table></TableWrap>
        </Section>
        <Section title="Address groups" count={spec.address_groups.length} readOnly={readOnly} onAdd={() => upd("address_groups", [...spec.address_groups, { name: "", members: [] }])}>
          <TableWrap><table className="tbl"><thead><tr><th>Group name</th><th>Members</th><th /></tr></thead>
            <tbody>{spec.address_groups.map((g, i) => <tr key={i}>
              <td className="min-w-[10rem]"><input aria-label="Group name" className="input w-full" disabled={readOnly} value={g.name} onChange={(e) => updAt("address_groups", i, { name: e.target.value })} /></td>
              <td className="min-w-[14rem]"><ListInput label="Members" value={g.members} onChange={(v) => updAt("address_groups", i, { members: v })} /></td>
              <td><Del readOnly={readOnly} onClick={() => delAt("address_groups", i)} /></td></tr>)}</tbody></table></TableWrap>
        </Section>
      </div>}

      {tab === "policies" && <Section title="Firewall policies" count={spec.policies.length} readOnly={readOnly}
        hint="Policies are created with 'edit 0' and land at the end of the policy list. The generated script explains how to move them above broader rules."
        onAdd={() => upd("policies", [...spec.policies, { ...NEW_POLICY, name: `SIEM-Policy-${spec.policies.length + 1}` }])}>
        <div className="space-y-3">{spec.policies.map((p, i) => (
          <div key={i} className="border border-line rounded p-3 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
            <div><label className="label">Name (≤35)</label><input className="input w-full" disabled={readOnly} value={p.name} onChange={(e) => updAt("policies", i, { name: e.target.value })} /></div>
            <div><label className="label">Incoming interface(s)</label><ListInput label="Source interfaces" value={p.srcintf} onChange={(v) => updAt("policies", i, { srcintf: v })} placeholder="port1" /></div>
            <div><label className="label">Outgoing interface(s)</label><ListInput label="Destination interfaces" value={p.dstintf} onChange={(v) => updAt("policies", i, { dstintf: v })} placeholder="wan1" /></div>
            <div><label className="label">Action</label><select className="input w-full" disabled={readOnly} value={p.action} onChange={(e) => updAt("policies", i, { action: e.target.value as Policy["action"] })}><option>accept</option><option>deny</option></select></div>
            <div><label className="label">Source address(es)</label><ListInput label="Source addresses" value={p.srcaddr} onChange={(v) => updAt("policies", i, { srcaddr: v })} /></div>
            <div><label className="label">Destination address(es)</label><ListInput label="Destination addresses" value={p.dstaddr} onChange={(v) => updAt("policies", i, { dstaddr: v })} /></div>
            <div><label className="label">Service(s) / group</label><ListInput label="Services" value={p.service} onChange={(v) => updAt("policies", i, { service: v })} /></div>
            <div><label className="label">Web-filter profile</label><input className="input w-full" disabled={readOnly || p.action === "deny"} value={p.webfilter_profile || ""} onChange={(e) => updAt("policies", i, { webfilter_profile: e.target.value || null })} /></div>
            <div><label className="label">Log traffic</label><select className="input w-full" disabled={readOnly} value={p.logtraffic} onChange={(e) => updAt("policies", i, { logtraffic: e.target.value as Policy["logtraffic"] })}><option>all</option><option>utm</option><option>disable</option></select></div>
            <label className="text-sm flex items-center gap-2 self-end"><input type="checkbox" disabled={readOnly || p.action === "deny"} checked={p.nat} onChange={(e) => updAt("policies", i, { nat: e.target.checked })} />NAT</label>
            <div className="sm:col-span-2 xl:col-span-1 flex justify-end items-end"><Del readOnly={readOnly} onClick={() => delAt("policies", i)} /></div>
          </div>))}</div>
      </Section>}

      {cli && <CliModal cli={cli} plan={plan!} onClose={() => setCli(null)} />}
    </div>
  );
}

function ValidationPanel({ val }: { val: any }) {
  if (!val) return null;
  if (!val.valid) return (
    <div role="alert" className="mt-2 text-xs text-red-300 space-y-0.5"><b>Fix before saving:</b>{val.errors.map((e: string, i: number) => <div key={i} className="cell-wrap">• {e}</div>)}</div>);
  const refs = val.external_references || {};
  const items = Object.entries(refs).filter(([, v]) => (v as string[]).length);
  return (
    <div className="mt-2 text-xs text-muted">
      <span className="text-emerald-400">✓ Plan is valid.</span>
      {items.length > 0 && <> Must already exist on the firewall: {items.map(([k, v]) => <span key={k} className="mr-2"><b>{k}</b>: {(v as string[]).join(", ")}</span>)}</>}
    </div>);
}

function CheckPanel({ check }: { check: any }) {
  return (
    <div className="mt-3 border border-line rounded p-2 text-xs space-y-1">
      <div className="text-muted">Checked against <b>{check.firewall}</b> <Time v={check.checked_at} /> (read-only GET requests)</div>
      {check.error && <div className="text-red-400">Check failed: {check.error}</div>}
      {check.overwrites?.length > 0 && <div className="text-amber-300">⚠ Already exist, so applying will <b>modify</b> them: {check.overwrites.map((o: any) => `${o.kind} "${o.name}"`).join(", ")}</div>}
      {check.missing?.length > 0 && <div className="text-red-300">✗ Referenced but missing (the CLI will fail): {check.missing.map((o: any) => `${o.kind} "${o.name}"`).join(", ")}</div>}
      {check.forbidden?.length > 0 && <div className="text-amber-300">API user cannot read: {check.forbidden.map((o: any) => o.kind).join(", ")}</div>}
      {!check.error && !check.overwrites?.length && !check.missing?.length && <div className="text-emerald-400">✓ No collisions and all references exist.</div>}
    </div>);
}

function Suggestions({ firewallId, spec, setSpec, readOnly }: { firewallId: number | null; spec: Spec; setSpec: (s: Spec) => void; readOnly: boolean }) {
  const [open, setOpen] = useState(true);
  const [srcCidr, setSrcCidr] = useState("");
  const dSrc = useDebounced(srcCidr);
  const validSrc = !dSrc || /^[0-9a-fA-F:.]+(\/\d{1,3})?$/.test(dSrc);
  const q = useData<any>("/hardening/suggest", { limit: 100, firewall_id: firewallId ? [firewallId] : undefined, src_ip: validSrc && dSrc ? dSrc : undefined }, { enabled: open });
  const [selPorts, setSelPorts] = useState<Set<string>>(new Set());
  const [selDoms, setSelDoms] = useState<Set<string>>(new Set());
  const [groupName, setGroupName] = useState("Internet-Allowed-Ports");
  const [urlAction, setUrlAction] = useState<"allow" | "block">("allow");
  const toggle = (set: Set<string>, setter: (s: Set<string>) => void, k: string) => { const n = new Set(set); n.has(k) ? n.delete(k) : n.add(k); setter(n); };

  // build the next spec from the current one, then update state once (no setState inside an updater)
  const addPorts = () => {
    const s = spec;
    const services = [...s.services];
    const members: string[] = [];
    for (const k of selPorts) {
      const [proto, port] = k.split("/");
      const pre = PREDEFINED[k];
      if (pre) { members.push(pre); continue; }
      const name = `${proto}-${port}`;
      if (!services.some((x) => x.name === name)) services.push({ name, tcp: proto === "TCP" ? [port] : [], udp: proto === "UDP" ? [port] : [] });
      members.push(name);
    }
    const groups = [...s.service_groups];
    const gi = groups.findIndex((g) => g.name === groupName);
    if (gi >= 0) groups[gi] = { ...groups[gi], members: Array.from(new Set([...groups[gi].members, ...members])) };
    else groups.push({ name: groupName, members: Array.from(new Set(members)) });
    setSpec({ ...s, services, service_groups: groups });
    setSelPorts(new Set());
  };

  const addDomains = () => {
    const s = spec;
    const filters = [...s.url_filters];
    if (!filters.length) filters.push({ table_id: 100, name: "SIEM-URL-List", entries: [], block_others: false, profile_name: "" });
    const f = filters[0];
    const existing = new Set(f.entries.map((e) => e.url));
    const add = Array.from(selDoms).map((d) => `*.${d}`).filter((u) => !existing.has(u)).map((url) => ({ url, type: "wildcard" as const, action: urlAction }));
    filters[0] = { ...f, entries: [...f.entries, ...add] };
    setSpec({ ...s, url_filters: filters });
    setSelDoms(new Set());
  };

  const inPlan = useMemo(() => new Set(spec.service_groups.flatMap((g) => g.members)), [spec.service_groups]);
  return (
    <Card title="Suggestions from observed traffic (selected time range)" right={<button className="btn" aria-expanded={open} onClick={() => setOpen(!open)}>{open ? "Hide" : "Show"}</button>}>
      {open && <div className="space-y-3">
        <div className="flex flex-wrap gap-2 items-end">
          <div><label className="label">Limit to source IP / subnet</label><input className={`input ${validSrc ? "" : "border-red-500"}`} aria-invalid={!validSrc} placeholder="10.10.20.0/24" value={srcCidr} onChange={(e) => setSrcCidr(e.target.value.trim())} /></div>
          <p className="text-xs text-muted flex-1 min-w-[14rem]">{q.data?.note} Firewall filter: {firewallId ? "plan target" : "global selection"}.</p>
        </div>
        <Loading q={q} />
        <div className="grid-cards xl:grid-cols-2">
          <div className="min-w-0 space-y-2">
            <div className="flex flex-wrap gap-2 items-center text-sm">
              <b>Destination ports</b><span className="text-muted text-xs">{selPorts.size} selected</span><div className="flex-1" />
              {!readOnly && <><input aria-label="Target service group" className="input py-1 w-48" value={groupName} onChange={(e) => setGroupName(e.target.value)} />
                <button className="btn" disabled={!selPorts.size || !groupName.trim()} onClick={addPorts}>Add to service group</button></>}
            </div>
            {q.data?.ports?.length ? <TableWrap maxH="max-h-80"><table className="tbl"><thead><tr><th /><th>Port</th><th>Logged service</th><th className="num">Allowed</th><th className="num">Denied</th><th className="num">Sources</th><th className="num">Bytes</th></tr></thead>
              <tbody>{q.data.ports.map((r: any) => { const k = `${r.proto}/${r.port}`; const member = PREDEFINED[k] || `${r.proto}-${r.port}`; return (
                <tr key={k}><td><input type="checkbox" aria-label={`Select ${k}`} disabled={readOnly} checked={selPorts.has(k)} onChange={() => toggle(selPorts, setSelPorts, k)} /></td>
                  <td className="font-mono nowrap">{k}{inPlan.has(member) && <span className="pill bg-emerald-800/50 text-emerald-200 ml-1">in plan</span>}</td>
                  <td className="text-xs">{r.service || <span className="text-slate-600">not logged</span>}</td>
                  <td className="num text-emerald-400">{fmtNum(r.allowed)}</td><td className="num text-red-400">{fmtNum(r.denied)}</td>
                  <td className="num">{fmtNum(r.sources)}</td><td className="num">{fmtBytes(r.bytes)}</td></tr>); })}</tbody></table></TableWrap>
              : q.data && <Empty text="No TCP/UDP traffic in this range." />}
          </div>
          <div className="min-w-0 space-y-2">
            <div className="flex flex-wrap gap-2 items-center text-sm">
              <b>Web domains</b><span className="text-muted text-xs">{selDoms.size} selected</span><div className="flex-1" />
              {!readOnly && <><select aria-label="URL action" className="input py-1" value={urlAction} onChange={(e) => setUrlAction(e.target.value as "allow" | "block")}><option value="allow">allow</option><option value="block">block</option></select>
                <button className="btn" disabled={!selDoms.size} onClick={addDomains}>Add to URL list</button></>}
            </div>
            {q.data?.domains?.length ? <TableWrap maxH="max-h-80"><table className="tbl"><thead><tr><th /><th>Domain</th><th>Category</th><th className="num">Allowed</th><th className="num">Blocked</th><th className="num">Clients</th></tr></thead>
              <tbody>{q.data.domains.map((r: any) => (
                <tr key={r.domain}><td><input type="checkbox" aria-label={`Select ${r.domain}`} disabled={readOnly} checked={selDoms.has(r.domain)} onChange={() => toggle(selDoms, setSelDoms, r.domain)} /></td>
                  <td className="font-mono text-xs cell-wrap">{r.domain}</td><td className="text-xs">{r.url_cat || "—"}</td>
                  <td className="num text-emerald-400">{fmtNum(r.allowed)}</td><td className="num text-red-400">{fmtNum(r.blocked)}</td><td className="num">{fmtNum(r.clients)}</td></tr>))}</tbody></table></TableWrap>
              : q.data && <Empty text="No web-filter logs in this range." />}
          </div>
        </div>
      </div>}
    </Card>
  );
}

function CliModal({ cli, plan, onClose }: { cli: any; plan: Plan; onClose: () => void }) {
  const [tab, setTab] = useState("apply");
  const [copied, setCopied] = useState(false);
  const text: string = tab === "apply" ? cli.apply : cli.rollback;
  const download = () => {
    const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    const a = document.createElement("a");
    a.href = url; a.download = `siem-plan-${plan.id}-${tab}.txt`; a.click();
    URL.revokeObjectURL(url);
  };
  const missing = cli.last_check?.missing?.length;
  return (
    <Modal title={`FortiOS CLI — plan #${plan.id}: ${plan.name}`} onClose={onClose} wide>
      {!cli.last_check?.checked_at && <div className="text-xs text-amber-300 mb-2">Not yet checked against the firewall. Run "Check against firewall" to detect collisions and missing references.</div>}
      {missing > 0 && <div className="text-xs text-red-300 mb-2">Last check found {missing} missing reference(s). The script will fail until they exist.</div>}
      <Tabs value={tab} onChange={setTab} tabs={[{ key: "apply", label: "Apply script" }, { key: "rollback", label: "Rollback script" }]} />
      <div className="flex flex-wrap gap-2 mb-2">
        <button className="btn btn-primary" onClick={() => navigator.clipboard.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500); })}>{copied ? "Copied" : "Copy"}</button>
        <button className="btn" onClick={download}>Download .txt</button>
      </div>
      <pre className="text-xs bg-panel2 border border-line rounded p-3 max-h-[60vh] overflow-auto font-mono whitespace-pre">{text}</pre>
    </Modal>
  );
}
