import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { Card, Empty, Loading, Modal, TableWrap, Time } from "../../components/ui";
import { ErrorText, Field, Pager, Status, list, useCan, useSave } from "./common";

const SRC = { name: "", kind: "ad", enabled: true, hosts: "", base: "", group_base: "", filter: "", memberof_regex: "^CN=tac_([^,]+),.*", bind_dn: "", bind_password: "",
  starttls: false, pam_service: "" };
const USR = { username: "", source_id: "", display_name: "", enabled: true, emergency: false, groups: "", valid_until: "", disabled_reason: "", password: "" };

export function Identity() {
  const can = useCan();
  const [q, setQ] = useState("");
  const [offset, setOffset] = useState(0);
  const [src, setSrc] = useState<any>(null);
  const [usr, setUsr] = useState<any>(null);
  const sources = useQuery({ queryKey: ["tac-sources"], queryFn: () => api<any>("/tacacs/identity-sources") });
  const users = useQuery({ queryKey: ["tac-users", q, offset], placeholderData: (p) => p, queryFn: () => api<any>("/tacacs/users", { params: { q: q || undefined, offset, limit: 100 } }) });
  const test = useSave((id: number) => api<any>("/tacacs/tests/identity", { method: "POST", body: { source_id: id } }), ["tac-sources"]);
  return <div className="space-y-4">
    <Card title="Identity sources" bodyClass="p-0" right={can("policy_admin") && <button className="btn btn-primary" onClick={() => setSrc({ ...SRC })}>+ Add source</button>}>
      <Loading q={sources} />
      {sources.data && (!sources.data.items.length ? <Empty text="No identity sources. Add 'local' for break-glass / local accounts and your AD or LDAP directory." /> :
        <TableWrap><table className="tbl"><thead><tr><th>Name</th><th>Kind</th><th>Hosts</th><th>Base DN</th><th>Bind</th><th>Last test</th><th className="w-full">Detail</th><th /></tr></thead>
          <tbody>{sources.data.items.map((x: any) => <tr key={x.id}><td className="font-medium">{x.name}{!x.enabled && <span className="text-muted"> (disabled)</span>}</td>
            <td>{x.kind}</td><td className="font-mono text-xs">{(x.settings.hosts || []).join(" ") || "—"}</td><td className="text-xs">{x.settings.base || "—"}</td>
            <td className="text-xs">{x.settings.bind_dn ? `${x.settings.bind_dn} ${x.has_bind_password ? "(password stored)" : ""}` : "—"}</td>
            <td>{x.last_test_ok == null ? "—" : <><Status s={x.last_test_ok ? "passed" : "failed"} /> <Time v={x.last_test_at} /></>}</td>
            <td className="text-xs">{x.last_test_detail}</td>
            <td className="whitespace-nowrap">{can("operator") && ["ldap", "ad"].includes(x.kind) && <button className="btn" disabled={test.isPending} onClick={() => test.mutate(x.id)}>Bind test</button>}{" "}
              {can("policy_admin") && <button className="btn" onClick={() => setSrc({ ...SRC, ...x, ...x.settings, hosts: (x.settings.hosts || []).join(", "), bind_password: "" })}>Edit</button>}</td></tr>)}
          </tbody></table></TableWrap>)}
      <ErrorText e={test.error} />
      {test.data && <div className="p-2 text-xs">{(test.data as any).steps.map((st: any) => <div key={st.name}><Status s={st.ok ? "passed" : "failed"} /> {st.name}: {st.detail}
        {st.help && <span className="text-muted"> — {st.help}</span>}</div>)}</div>}
    </Card>
    <Card title={`Users${users.data ? ` (${users.data.total})` : ""}`} bodyClass="p-0" right={<>
      <input aria-label="Search users" className="input py-1 w-44" placeholder="User name" value={q} onChange={(e) => { setQ(e.target.value); setOffset(0); }} />
      {can("policy_admin") && <button className="btn btn-primary" onClick={() => setUsr({ ...USR })}>+ Add user</button>}</>}>
      <p className="text-2xs text-muted p-2">Directory users do not need to be listed: they authenticate against their directory and get roles from group mappings. List them here
        only to disable them or map roles to them individually. Local passwords are stored only as SHA-512-crypt hashes.</p>
      <Loading q={users} />
      {users.data && (!users.data.items.length ? <Empty text="No users." /> :
        <TableWrap><table className="tbl"><thead><tr><th>User</th><th>Source</th><th>Status</th><th>Groups</th><th>Roles</th><th>Last login</th><th>Last failure</th><th>Valid until</th><th /></tr></thead>
          <tbody>{users.data.items.map((u: any) => <tr key={u.id} className={u.enabled ? "" : "opacity-60"}>
            <td className="font-medium">{u.username}{u.emergency && <span className="pill bg-red-500/15 text-red-300 ml-1">emergency</span>}<div className="text-2xs text-muted">{u.display_name}</div></td>
            <td className="text-xs">{u.source?.name} ({u.source?.kind})</td><td>{u.enabled ? <span className="text-emerald-300">enabled</span> : <span className="text-red-300" title={u.disabled_reason}>disabled</span>}</td>
            <td className="text-xs">{u.groups.join(", ") || "—"}</td><td className="text-xs">{u.roles.join(", ") || <span className="text-amber-300">none (denied)</span>}</td>
            <td><Time v={u.last_login} /></td><td><Time v={u.last_failure} /></td><td><Time v={u.valid_until} /></td>
            <td>{can("policy_admin") && <button className="btn" onClick={() => setUsr({ ...USR, ...u, groups: u.groups.join(", "), valid_until: u.valid_until?.slice(0, 10) || "", password: "" })}>Edit</button>}</td></tr>)}
          </tbody></table></TableWrap>)}
      {users.data && <Pager total={users.data.total} limit={100} offset={offset} onChange={setOffset} />}
    </Card>
    {src && <SourceForm x={src} onClose={() => setSrc(null)} />}
    {usr && <UserForm x={usr} sources={sources.data?.items || []} onClose={() => setUsr(null)} />}
  </div>;
}

function SourceForm({ x, onClose }: { x: any; onClose: () => void }) {
  const [f, setF] = useState<any>(x);
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value });
  const body = () => ({ ...f, hosts: list(f.hosts), bind_password: f.bind_password || null, id: undefined, settings: undefined });
  const save = useSave(() => api(x.id ? `/tacacs/identity-sources/${x.id}` : "/tacacs/identity-sources", { method: x.id ? "PUT" : "POST", body: body() }), ["tac-sources"], onClose);
  const del = useSave(() => api(`/tacacs/identity-sources/${x.id}`, { method: "DELETE" }), ["tac-sources"], onClose);
  const dir = ["ldap", "ad"].includes(f.kind);
  return <Modal title={x.id ? `Edit ${x.name}` : "Add identity source"} onClose={onClose}>
    <div className="grid gap-2 sm:grid-cols-2">
      <Field label="Name"><input className="input w-full" value={f.name} onChange={set("name")} /></Field>
      <Field label="Kind"><select className="input w-full" value={f.kind} onChange={set("kind")} disabled={!!x.id}>
        <option value="local">local (tac_plus-ng users)</option><option value="ad">Active Directory (MAVIS LDAP)</option><option value="ldap">LDAP (MAVIS LDAP)</option>
        <option value="pam">PAM (on the TACACS+ host)</option></select></Field>
      {dir && <>
        <div className="sm:col-span-2"><Field label="Hosts (comma-separated; ldaps://dc1.example.net:636 or ldap:// with StartTLS)"><input className="input w-full" value={f.hosts} onChange={set("hosts")} /></Field></div>
        <Field label="User base DN"><input className="input w-full" value={f.base} onChange={set("base")} placeholder="dc=example,dc=net" /></Field>
        <Field label="Group base DN"><input className="input w-full" value={f.group_base} onChange={set("group_base")} /></Field>
        <Field label="Bind DN (service account, read-only)"><input className="input w-full" value={f.bind_dn} onChange={set("bind_dn")} /></Field>
        <Field label={`Bind password${x.id ? " (leave empty to keep)" : ""}`}><input type="password" autoComplete="new-password" className="input w-full" value={f.bind_password} onChange={set("bind_password")} /></Field>
        <Field label="memberOf → group regex"><input className="input w-full font-mono text-xs" value={f.memberof_regex} onChange={set("memberof_regex")} /></Field>
        <Field label="User filter (optional)"><input className="input w-full font-mono text-xs" value={f.filter} onChange={set("filter")} /></Field>
        <label className="text-sm flex items-center gap-2"><input type="checkbox" checked={f.starttls} onChange={set("starttls")} />StartTLS (for ldap://)</label></>}
      {f.kind === "pam" && <Field label="PAM service"><input className="input w-full" value={f.pam_service} onChange={set("pam_service")} placeholder="tac_plus" /></Field>}
      <label className="text-sm flex items-center gap-2"><input type="checkbox" checked={f.enabled} onChange={set("enabled")} />Enabled</label>
    </div>
    <p className="text-2xs text-muted mt-2">The directory is queried by the TACACS+ server at login; the SIEM does not copy the directory. Clear-text LDAP is refused and TLS is always verified.</p>
    <ErrorText e={save.error || del.error} />
    <div className="flex gap-2 mt-3"><button className="btn btn-primary" disabled={save.isPending || !f.name} onClick={() => save.mutate(null)}>Save</button>
      {x.id && <button className="btn btn-danger ml-auto" onClick={() => confirm(`Delete ${x.name}?`) && del.mutate(null)}>Delete</button>}</div>
  </Modal>;
}

function UserForm({ x, sources, onClose }: { x: any; sources: any[]; onClose: () => void }) {
  const [f, setF] = useState<any>({ ...x, source_id: x.source_id || sources[0]?.id || "" });
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value });
  const local = sources.find((s) => s.id === Number(f.source_id))?.kind === "local";
  const body = () => ({ username: f.username, source_id: Number(f.source_id), display_name: f.display_name, enabled: f.enabled, emergency: f.emergency, groups: list(f.groups),
    valid_until: f.valid_until ? `${f.valid_until}T23:59:59Z` : null, disabled_reason: f.disabled_reason, password: f.password || null });
  const save = useSave(() => api(x.id ? `/tacacs/users/${x.id}` : "/tacacs/users", { method: x.id ? "PUT" : "POST", body: body() }), ["tac-users"], onClose);
  const del = useSave(() => api(`/tacacs/users/${x.id}`, { method: "DELETE" }), ["tac-users"], onClose);
  return <Modal title={x.id ? `Edit ${x.username}` : "Add user"} onClose={onClose}>
    <div className="grid gap-2 sm:grid-cols-2">
      <Field label="User name"><input className="input w-full" value={f.username} onChange={set("username")} disabled={!!x.id} /></Field>
      <Field label="Identity source"><select className="input w-full" value={f.source_id} onChange={set("source_id")} disabled={!!x.id}>
        {sources.map((s) => <option key={s.id} value={s.id}>{s.name} ({s.kind})</option>)}</select></Field>
      <Field label="Display name"><input className="input w-full" value={f.display_name} onChange={set("display_name")} /></Field>
      <Field label="Local groups (comma-separated)"><input className="input w-full" value={f.groups} onChange={set("groups")} /></Field>
      {local && <Field label={`Password${x.id ? " (leave empty to keep)" : ""} — 12+ characters`}><input type="password" autoComplete="new-password" className="input w-full" value={f.password} onChange={set("password")} /></Field>}
      <Field label="Valid until"><input type="date" className="input w-full" value={f.valid_until} onChange={set("valid_until")} /></Field>
      <label className="text-sm flex items-center gap-2"><input type="checkbox" checked={f.enabled} onChange={set("enabled")} />Enabled</label>
      <label className="text-sm flex items-center gap-2"><input type="checkbox" checked={f.emergency} onChange={set("emergency")} />Emergency (break-glass) account</label>
      {!f.enabled && <div className="sm:col-span-2"><Field label="Reason for disabling"><input className="input w-full" value={f.disabled_reason} onChange={set("disabled_reason")} /></Field></div>}
    </div>
    <p className="text-2xs text-muted mt-2">Disabling takes effect on the devices when the next configuration version is deployed (the disabled user is denied first in the ruleset).</p>
    <ErrorText e={save.error || del.error} />
    <div className="flex gap-2 mt-3"><button className="btn btn-primary" disabled={save.isPending || !f.username} onClick={() => save.mutate(null)}>Save</button>
      {x.id && <button className="btn btn-danger ml-auto" onClick={() => confirm(`Delete ${x.username}?`) && del.mutate(null)}>Delete</button>}</div>
  </Modal>;
}
