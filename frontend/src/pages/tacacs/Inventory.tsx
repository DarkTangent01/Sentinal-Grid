import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { Card, Empty, Loading, Modal, TableWrap, Time } from "../../components/ui";
import { ErrorText, Field, Pager, SecretOnce, Status, useCan, useSave, useTacMeta } from "./common";

const SBLANK = { name: "", kind: "managed", management_address: "tacacs", client_address: "", port: 49, site: "", environment: "production", role: "primary",
  monitoring: true, notes: "" };

export function Servers() {
  const can = useCan();
  const q = useQuery({ queryKey: ["tac-servers"], queryFn: () => api<any>("/tacacs/servers"), refetchInterval: 30_000 });
  const [edit, setEdit] = useState<any>(null);
  const check = useSave((id: number) => api(`/tacacs/servers/${id}/check`, { method: "POST" }), ["tac-servers"]);
  return <Card title={`TACACS+ servers${q.data ? ` (${q.data.items.length})` : ""}`} bodyClass="p-0"
    right={can("operator") && <button className="btn btn-primary" onClick={() => setEdit({ ...SBLANK })}>+ Add server</button>}>
    <Loading q={q} />
    {q.data && (!q.data.items.length ? <Empty text="No servers. A managed server is the tac_plus-ng container started with COMPOSE_PROFILES=tacacs (address: tacacs)." /> :
      <TableWrap><table className="tbl"><thead><tr><th>Server</th><th>Kind</th><th>Role</th><th>Management address</th><th>Client address</th><th>Status</th><th>Version</th>
        <th>Last OK</th><th>Last config</th><th>Last accounting</th><th>Last authentication</th><th className="w-full">Error</th><th /></tr></thead>
        <tbody>{q.data.items.map((x: any) => <tr key={x.id}>
          <td className="font-medium">{x.name}<div className="text-2xs text-muted">{x.site} · {x.environment}</div></td><td className="text-xs">{x.kind}</td><td>{x.role}</td>
          <td className="font-mono text-xs">{x.management_address}:{x.port}</td><td className="font-mono text-xs">{x.client_address || "—"}</td>
          <td><Status s={x.monitoring ? x.status : "unmonitored"} /><div className="text-2xs text-muted"><Time v={x.status_since} /></div></td>
          <td className="text-xs">{x.version || "—"}{x.agent?.agent_version && <div className="text-2xs text-muted">agent {x.agent.agent_version}</div>}</td>
          <td><Time v={x.last_ok_at} /></td><td>{x.deployed_version_id ? <>#{x.deployed_version_id} <Time v={x.last_deploy_at} /></> : "—"}</td>
          <td><Time v={x.last_accounting_at} /></td><td><Time v={x.last_authentication_at} /></td><td className="text-xs text-red-300">{x.last_error}</td>
          <td className="whitespace-nowrap">{can("operator") && <><button className="btn" disabled={check.isPending} onClick={() => check.mutate(x.id)}>Check now</button>{" "}
            <button className="btn" onClick={() => setEdit(x)}>Edit</button></>}</td></tr>)}</tbody></table></TableWrap>)}
    <ErrorText e={check.error} />
    {check.data && <p className="text-xs p-2">Check: <Status s={(check.data as any).status} /> {(check.data as any).detail}</p>}
    {edit && <ServerForm x={edit} onClose={() => setEdit(null)} />}
  </Card>;
}

function ServerForm({ x, onClose }: { x: any; onClose: () => void }) {
  const [f, setF] = useState<any>({ ...SBLANK, ...x });
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value });
  const body = () => Object.fromEntries(Object.keys(SBLANK).map((k) => [k, k === "port" ? Number(f[k]) : f[k]]));
  const save = useSave(() => api(x.id ? `/tacacs/servers/${x.id}` : "/tacacs/servers", { method: x.id ? "PUT" : "POST", body: body() }), ["tac-servers"], onClose);
  const del = useSave(() => api(`/tacacs/servers/${x.id}`, { method: "DELETE" }), ["tac-servers"], onClose);
  return <Modal title={x.id ? `Edit ${x.name}` : "Add TACACS+ server"} onClose={onClose}>
    <div className="grid gap-2 sm:grid-cols-2">
      <Field label="Name"><input className="input w-full" value={f.name} onChange={set("name")} /></Field>
      <Field label="Kind"><select className="input w-full" value={f.kind} onChange={set("kind")} disabled={!!x.id}>
        <option value="managed">managed (tac_plus-ng + SIEM agent)</option><option value="external">external (monitor and test only)</option></select></Field>
      <Field label="Management address (SIEM → server)"><input className="input w-full" value={f.management_address} onChange={set("management_address")} /></Field>
      <Field label="Client-facing address (devices → server)"><input className="input w-full" value={f.client_address} onChange={set("client_address")} placeholder="10.0.0.5" /></Field>
      <Field label="Port"><input className="input w-full" type="number" value={f.port} onChange={set("port")} /></Field>
      <Field label="Role"><select className="input w-full" value={f.role} onChange={set("role")}><option>primary</option><option>secondary</option></select></Field>
      <Field label="Site"><input className="input w-full" value={f.site} onChange={set("site")} /></Field>
      <Field label="Environment"><select className="input w-full" value={f.environment} onChange={set("environment")}>{["production", "staging", "lab"].map((v) => <option key={v}>{v}</option>)}</select></Field>
      <label className="text-sm flex items-center gap-2"><input type="checkbox" checked={f.monitoring} onChange={set("monitoring")} />Monitoring enabled</label>
      <div className="sm:col-span-2"><Field label="Notes"><input className="input w-full" value={f.notes} onChange={set("notes")} /></Field></div>
    </div>
    <p className="text-2xs text-muted mt-2">The SIEM checks TCP/{f.port} and, for a managed server, the agent status on the shared volume. TACACS+ body obfuscation is not
      transport encryption: keep TCP/49 on management networks only.</p>
    <ErrorText e={save.error || del.error} />
    <div className="flex gap-2 mt-3"><button className="btn btn-primary" disabled={save.isPending || !f.name} onClick={() => save.mutate(null)}>Save</button>
      {x.id && <button className="btn btn-danger ml-auto" onClick={() => confirm(`Remove ${x.name}?`) && del.mutate(null)}>Remove</button>}</div>
  </Modal>;
}

const CBLANK = { name: "", address: "", vendor: "cisco", model: "", firmware: "", site: "", device_group: "", role: "", primary_server_id: "", secondary_server_id: "",
  enabled: true, notes: "", wide_cidr_justification: "" };

export function Clients() {
  const can = useCan();
  const meta = useTacMeta();
  const [qText, setQ] = useState("");
  const [vendor, setVendor] = useState("");
  const [offset, setOffset] = useState(0);
  const [edit, setEdit] = useState<any>(null);
  const [secret, setSecret] = useState<any>(null);
  const [tpl, setTpl] = useState<any>(null);
  const [hist, setHist] = useState<any>(null);
  const q = useQuery({ queryKey: ["tac-clients", qText, vendor, offset], placeholderData: (p) => p,
    queryFn: () => api<any>("/tacacs/clients", { params: { q: qText || undefined, vendor: vendor || undefined, limit: 100, offset } }) });
  const rotate = useSave((id: number) => api<any>(`/tacacs/clients/${id}/rotate`, { method: "POST" }), ["tac-clients"], (r: any) => setSecret(r));
  const finish = useSave(({ id, action }: any) => api(`/tacacs/clients/${id}/rotate/${action}`, { method: "POST" }), ["tac-clients"]);
  return <div className="space-y-4">
    <Card title={`Device clients${q.data ? ` (${q.data.total})` : ""}`} bodyClass="p-0" right={<>
      <input aria-label="Search" className="input py-1 w-44" placeholder="Name, IP, model" value={qText} onChange={(e) => { setQ(e.target.value); setOffset(0); }} />
      <select aria-label="Vendor" className="input py-1" value={vendor} onChange={(e) => setVendor(e.target.value)}><option value="">All vendors</option>
        {["fortinet", "cisco", "ruckus", "other"].map((v) => <option key={v}>{v}</option>)}</select>
      {can("operator") && <button className="btn btn-primary" onClick={() => setEdit({ ...CBLANK })}>+ Add client</button>}</>}>
      <Loading q={q} />
      {q.data && (!q.data.items.length ? <Empty text="No device clients. Authorise the client networks under Settings first." /> :
        <TableWrap><table className="tbl"><thead><tr><th>Device</th><th>Address</th><th>Vendor / model</th><th>Site / group</th><th>Servers</th><th>Secret</th>
          <th>Config</th><th>Last auth test</th><th>Last authentication</th><th>Last accounting</th><th /></tr></thead>
          <tbody>{q.data.items.map((c: any) => <tr key={c.id} className={c.enabled ? "" : "opacity-60"}>
            <td className="font-medium">{c.name}{c.role && <div className="text-2xs text-muted">{c.role}</div>}</td>
            <td className="font-mono text-xs">{c.address}{c.wide_cidr && <div className="text-2xs text-amber-300" title={c.wide_cidr_justification}>range approved by {c.wide_cidr_approved_by}</div>}</td>
            <td>{c.vendor} <span className="text-muted text-xs">{c.model} {c.firmware}</span>
              <div className="text-2xs text-muted">{c.capabilities?.enforcement === "per-command" ? "per-command authorization" : "profile-only authorization"}</div></td>
            <td className="text-xs">{c.site || "—"}{c.device_group && ` / ${c.device_group}`}</td>
            <td className="text-xs">{c.primary_server || "—"}{c.secondary_server && <div className="text-muted">secondary {c.secondary_server}</div>}</td>
            <td className="text-xs">v{c.secret_version}{c.rotation_state === "pending" && <div className="text-amber-300">rotation pending</div>}<div className="text-muted"><Time v={c.secret_rotated_at} /></div></td>
            <td><Status s={c.sync_status} /></td>
            <td>{c.last_auth_test_ok == null ? "—" : <Status s={c.last_auth_test_ok ? "passed" : "failed"} />}</td>
            <td><Time v={c.last_authentication_at} /></td><td><Time v={c.last_accounting_at} /></td>
            <td className="whitespace-nowrap">
              <button className="btn" onClick={() => api(`/tacacs/clients/${c.id}/template`).then(setTpl).catch((e) => alert(e.message))}>Template</button>{" "}
              <button className="btn" onClick={() => api(`/tacacs/clients/${c.id}/history`).then((h) => setHist({ c, h }))}>History</button>{" "}
              {can("operator") && <>
                <button className="btn" onClick={() => setEdit({ ...CBLANK, ...c, primary_server_id: c.primary_server_id || "", secondary_server_id: c.secondary_server_id || "" })}>Edit</button>{" "}
                {c.rotation_state === "pending" ? <>
                  <button className="btn" onClick={() => confirm("Only complete after the device uses the new key and a login worked. Complete?") && finish.mutate({ id: c.id, action: "complete" })}>Complete rotation</button>{" "}
                  <button className="btn" onClick={() => finish.mutate({ id: c.id, action: "cancel" })}>Cancel</button></>
                  : <button className="btn" onClick={() => confirm(`Generate a new shared secret for ${c.name}? The old one keeps working until the rotation is completed.`) && rotate.mutate(c.id)}>Rotate secret</button>}</>}
            </td></tr>)}</tbody></table></TableWrap>)}
      {q.data && <Pager total={q.data.total} limit={100} offset={offset} onChange={setOffset} />}
      <ErrorText e={rotate.error || finish.error} />
    </Card>
    <Card title="Vendor capability matrix" bodyClass="p-0">
      <TableWrap><table className="tbl"><thead><tr><th>Vendor</th><th>Authentication</th><th>Exec authorization</th><th>Command authorization</th><th>Accounting (exec / commands)</th>
        <th className="w-full">Privilege semantics</th></tr></thead>
        <tbody>{Object.entries(meta.data?.vendors || {}).map(([k, v]: [string, any]) => <tr key={k}><td className="font-medium">{v.label}</td><td className="text-xs">{v.authentication}</td>
          <td className="text-xs">{v.exec_authorization}</td><td className="text-xs">{v.command_authorization}</td><td className="text-xs">{v.accounting_exec} / {v.accounting_commands}</td>
          <td className="text-xs">{v.privilege}</td></tr>)}</tbody></table></TableWrap></Card>
    {edit && <ClientForm x={edit} onClose={() => setEdit(null)} onSecret={setSecret} />}
    {secret && <SecretOnce secret={secret.shared_secret} notice={secret.secret_notice} onClose={() => setSecret(null)} />}
    {tpl && <Modal wide title={`${tpl.label} template · ${tpl.device}`} onClose={() => setTpl(null)}>
      <p className="text-sm text-amber-300 mb-2">{tpl.warning}</p>
      <div className="text-xs text-muted mb-2">Firmware: {tpl.firmware} · primary {tpl.primary} · secondary {tpl.secondary || "none (add one)"}</div>
      <pre className="input w-full font-mono text-xs whitespace-pre overflow-auto max-h-96">{tpl.config}</pre>
      <div className="grid gap-3 sm:grid-cols-2 mt-3 text-xs">
        {(["requirements", "limitations", "validation", "rollback"] as const).map((k) => <div key={k}><b className="capitalize">{k}</b>
          <ul className="list-disc ml-4">{tpl[k].map((x: string) => <li key={x}>{x}</li>)}</ul></div>)}</div>
      <p className="text-2xs text-muted mt-2">{tpl.secret_note}</p>
      <button className="btn mt-2" onClick={() => { const b = new Blob([tpl.config], { type: "text/plain" }); const a = document.createElement("a");
        a.href = URL.createObjectURL(b); a.download = `${tpl.device}-tacacs.txt`; a.click(); }}>Export</button>
    </Modal>}
    {hist && <Modal title={`Change history · ${hist.c.name}`} onClose={() => setHist(null)}>
      {!hist.h.items.length ? <Empty text="No recorded changes." /> : <TableWrap maxH="max-h-96"><table className="tbl"><thead><tr><th>Time</th><th>User</th><th>Action</th><th>Detail</th></tr></thead>
        <tbody>{hist.h.items.map((a: any, i: number) => <tr key={i}><td><Time v={a.ts} /></td><td>{a.user}</td><td className={a.success ? "" : "text-red-300"}>{a.action}</td>
          <td className="text-xs font-mono">{JSON.stringify(a.detail)}</td></tr>)}</tbody></table></TableWrap>}</Modal>}
  </div>;
}

function ClientForm({ x, onClose, onSecret }: { x: any; onClose: () => void; onSecret: (s: any) => void }) {
  const servers = useQuery({ queryKey: ["tac-servers"], queryFn: () => api<any>("/tacacs/servers") });
  const [f, setF] = useState<any>({ ...x });
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value });
  const body = () => ({ ...Object.fromEntries(Object.keys(CBLANK).map((k) => [k, f[k]])), primary_server_id: f.primary_server_id ? Number(f.primary_server_id) : null,
    secondary_server_id: f.secondary_server_id ? Number(f.secondary_server_id) : null });
  const save = useSave(() => api<any>(x.id ? `/tacacs/clients/${x.id}` : "/tacacs/clients", { method: x.id ? "PUT" : "POST", body: body() }), ["tac-clients"],
    (r: any) => { onClose(); if (r.shared_secret) onSecret(r); });
  const del = useSave(() => api(`/tacacs/clients/${x.id}`, { method: "DELETE" }), ["tac-clients"], onClose);
  const srv = servers.data?.items || [];
  return <Modal title={x.id ? `Edit ${x.name}` : "Add device client"} onClose={onClose}>
    <div className="grid gap-2 sm:grid-cols-2">
      <Field label="Device name (letters, digits, . _ -)"><input className="input w-full" value={f.name} onChange={set("name")} /></Field>
      <Field label="Management IP (or approved CIDR)"><input className="input w-full" value={f.address} onChange={set("address")} placeholder="10.20.0.11" /></Field>
      <Field label="Vendor"><select className="input w-full" value={f.vendor} onChange={set("vendor")}>{["fortinet", "cisco", "ruckus", "other"].map((v) => <option key={v}>{v}</option>)}</select></Field>
      <Field label="Model"><input className="input w-full" value={f.model} onChange={set("model")} /></Field>
      <Field label="Firmware"><input className="input w-full" value={f.firmware} onChange={set("firmware")} /></Field>
      <Field label="Site / warehouse"><input className="input w-full" value={f.site} onChange={set("site")} /></Field>
      <Field label="Device group"><input className="input w-full" value={f.device_group} onChange={set("device_group")} placeholder="core / access" /></Field>
      <Field label="Device role"><input className="input w-full" value={f.role} onChange={set("role")} /></Field>
      <Field label="Primary server"><select className="input w-full" value={f.primary_server_id} onChange={set("primary_server_id")}><option value="">—</option>
        {srv.map((s: any) => <option key={s.id} value={s.id}>{s.name}</option>)}</select></Field>
      <Field label="Secondary server"><select className="input w-full" value={f.secondary_server_id} onChange={set("secondary_server_id")}><option value="">—</option>
        {srv.map((s: any) => <option key={s.id} value={s.id}>{s.name}</option>)}</select></Field>
      {f.address.includes("/") && <div className="sm:col-span-2"><Field label="Justification for an address range (recorded as an approved exception)">
        <input className="input w-full" value={f.wide_cidr_justification} onChange={set("wide_cidr_justification")} /></Field></div>}
      <label className="text-sm flex items-center gap-2"><input type="checkbox" checked={f.enabled} onChange={set("enabled")} />Enabled</label>
    </div>
    <p className="text-2xs text-muted mt-2">A unique 32-character secret is generated on creation and shown once. The device is accepted by the server only after a
      configuration version containing it is approved and deployed.</p>
    <ErrorText e={save.error || del.error} />
    <div className="flex gap-2 mt-3"><button className="btn btn-primary" disabled={save.isPending || !f.name || !f.address} onClick={() => save.mutate(null)}>Save</button>
      {x.id && <button className="btn btn-danger ml-auto" onClick={() => confirm(`Remove ${x.name}? It stays on the server until the next deployed version.`) && del.mutate(null)}>Remove</button>}</div>
  </Modal>;
}
