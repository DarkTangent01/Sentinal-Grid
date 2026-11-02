import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { Card, Empty, Loading, Modal, TableWrap, Time } from "../../components/ui";
import { ErrorText, Field, Status, list, useCan, useSave, useTacMeta } from "./common";

const PBLANK = { name: "", device_groups: "", local: true, directory: true, allow_emergency: true, failure_alert_threshold: 5, priority: 100, enabled: true, description: "" };

export function AuthPolicies() {
  const can = useCan();
  const q = useQuery({ queryKey: ["tac-policies"], queryFn: () => api<any>("/tacacs/auth-policies") });
  const [edit, setEdit] = useState<any>(null);
  return <div className="space-y-4">
    <Card title="How results are classified">
      <div className="grid gap-2 sm:grid-cols-3 text-xs">
        {[["Authentication success", "AUTHC-PASS: credentials accepted"], ["Authentication failure", "AUTHC-FAIL / -DENY: wrong or missing credentials"],
          ["Backend unavailable", "AUTHC-FAIL-BACKEND: LDAP / AD / PAM did not answer — never counted as a wrong password"],
          ["Policy denial", "AUTHC-FAIL-ACL: credentials may be fine, the ruleset denied the user on this device"],
          ["Authorization denial", "AUTHZ-FAIL: exec or command authorization refused"], ["Protocol error", "undecodable request, usually a shared-secret mismatch"],
          ["Accounting failure", "ACCT-UNKNOWN / missing accounting: non-compliant or absent records"]].map(([a, b]) =>
          <div key={a} className="border border-line rounded p-2"><b>{a}</b><div className="text-muted">{b}</div></div>)}</div>
      <p className="text-2xs text-muted mt-2">No account lockout is configured by this module: failure thresholds raise alerts only, so a burst of failures cannot lock administrators out
        of the network. Users without a role mapping are always denied (default deny).</p>
    </Card>
    <Card title="Authentication policies" bodyClass="p-0" right={can("policy_admin") && <button className="btn btn-primary" onClick={() => setEdit({ ...PBLANK })}>+ Add policy</button>}>
      <Loading q={q} />
      {q.data && (!q.data.items.length ? <Empty text="No policies: local and directory users are accepted on every device (subject to role mappings)." /> :
        <TableWrap><table className="tbl"><thead><tr><th className="num">Priority</th><th>Policy</th><th>Device groups</th><th>Allowed sources</th><th>Emergency accounts</th>
          <th className="num">Failure alert threshold</th><th>Enabled</th><th /></tr></thead>
          <tbody>{q.data.items.map((p: any) => <tr key={p.id}><td className="num">{p.priority}</td><td className="font-medium">{p.name}<div className="text-2xs text-muted">{p.description}</div></td>
            <td className="text-xs">{p.device_groups.join(", ") || "all devices"}</td><td className="text-xs">{p.allowed_sources.join(", ")}</td>
            <td>{p.allow_emergency ? "allowed" : <span className="text-amber-300">denied</span>}</td><td className="num">{p.failure_alert_threshold}</td><td>{p.enabled ? "yes" : "no"}</td>
            <td>{can("policy_admin") && <button className="btn" onClick={() => setEdit({ ...PBLANK, ...p, device_groups: p.device_groups.join(", "),
              local: p.allowed_sources.includes("local"), directory: p.allowed_sources.includes("directory") })}>Edit</button>}</td></tr>)}</tbody></table></TableWrap>)}
    </Card>
    {edit && <PolicyForm x={edit} onClose={() => setEdit(null)} />}
  </div>;
}

function PolicyForm({ x, onClose }: { x: any; onClose: () => void }) {
  const [f, setF] = useState<any>(x);
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value });
  const body = () => ({ name: f.name, device_groups: list(f.device_groups), allowed_sources: [f.local && "local", f.directory && "directory"].filter(Boolean),
    allow_local_users: f.local, require_group_mapping: true, allow_emergency: f.allow_emergency, failure_alert_threshold: Number(f.failure_alert_threshold),
    priority: Number(f.priority), enabled: f.enabled, description: f.description });
  const save = useSave(() => api(x.id ? `/tacacs/auth-policies/${x.id}` : "/tacacs/auth-policies", { method: x.id ? "PUT" : "POST", body: body() }), ["tac-policies"], onClose);
  const del = useSave(() => api(`/tacacs/auth-policies/${x.id}`, { method: "DELETE" }), ["tac-policies"], onClose);
  return <Modal title={x.id ? `Edit ${x.name}` : "Add authentication policy"} onClose={onClose}>
    <div className="grid gap-2 sm:grid-cols-2">
      <Field label="Name"><input className="input w-full" value={f.name} onChange={set("name")} /></Field>
      <Field label="Device groups (comma-separated; empty = all)"><input className="input w-full" value={f.device_groups} onChange={set("device_groups")} /></Field>
      <label className="text-sm flex items-center gap-2"><input type="checkbox" checked={f.local} onChange={set("local")} />Allow local accounts</label>
      <label className="text-sm flex items-center gap-2"><input type="checkbox" checked={f.directory} onChange={set("directory")} />Allow directory accounts</label>
      <label className="text-sm flex items-center gap-2"><input type="checkbox" checked={f.allow_emergency} onChange={set("allow_emergency")} />Allow emergency accounts</label>
      <Field label="Alert after N failures"><input type="number" className="input w-full" value={f.failure_alert_threshold} onChange={set("failure_alert_threshold")} /></Field>
      <Field label="Priority (lower first)"><input type="number" className="input w-full" value={f.priority} onChange={set("priority")} /></Field>
      <label className="text-sm flex items-center gap-2"><input type="checkbox" checked={f.enabled} onChange={set("enabled")} />Enabled</label>
      <div className="sm:col-span-2"><Field label="Description"><input className="input w-full" value={f.description} onChange={set("description")} /></Field></div>
    </div>
    <ErrorText e={save.error || del.error} />
    <div className="flex gap-2 mt-3"><button className="btn btn-primary" disabled={save.isPending || !f.name || (!f.local && !f.directory)} onClick={() => save.mutate(null)}>Save</button>
      {x.id && <button className="btn btn-danger ml-auto" onClick={() => confirm(`Delete ${x.name}?`) && del.mutate(null)}>Delete</button>}</div>
  </Modal>;
}

export function Authorization() {
  const can = useCan();
  const meta = useTacMeta();
  const roles = useQuery({ queryKey: ["tac-roles"], queryFn: () => api<any>("/tacacs/roles") });
  const maps = useQuery({ queryKey: ["tac-mappings"], queryFn: () => api<any>("/tacacs/mappings") });
  const rules = useQuery({ queryKey: ["tac-rules"], queryFn: () => api<any>("/tacacs/command-rules") });
  const conf = useQuery({ queryKey: ["tac-conflicts"], queryFn: () => api<any>("/tacacs/policy/conflicts") });
  const seed = useSave(() => api("/tacacs/roles/templates", { method: "POST" }), ["tac-roles"]);
  const [role, setRole] = useState<any>(null);
  const [map, setMap] = useState<any>(null);
  const [rule, setRule] = useState<any>(null);
  const [explain, setExplain] = useState<any>(null);
  const rname = (id: number) => roles.data?.items.find((r: any) => r.id === id)?.name || id;
  return <div className="space-y-4">
    <Card title="Authentication vs. authorization">
      <p className="text-xs text-muted">Authentication proves who the administrator is. Authorization then decides what they get on each device: exec authorization returns the
        privilege (Cisco priv-lvl, Ruckus foundry-privlvl, FortiGate admin profile), and command authorization checks each command — only on vendors that send per-command
        requests (Cisco, Ruckus). FortiGates receive a profile and cannot be restricted per command.</p>
    </Card>
    <Card title={`Roles${roles.data ? ` (${roles.data.items.length})` : ""}`} bodyClass="p-0" right={can("policy_admin") && <>
      <button className="btn" disabled={seed.isPending} onClick={() => seed.mutate(null)}>Add built-in roles</button>
      <button className="btn btn-primary" onClick={() => setRole({ name: "", description: "", privileged: false, cisco: 1, ruckus: 5, fortinet: "prof_readonly", default_command_action: "deny",
        command_categories: ["read_only"] })}>+ Add role</button></>}>
      <Loading q={roles} />
      {roles.data && (!roles.data.items.length ? <Empty text="No roles yet. Add the built-in roles as a starting point." /> :
        <TableWrap><table className="tbl"><thead><tr><th>Role</th><th>Cisco</th><th>Ruckus</th><th>FortiGate</th><th>Permitted categories</th><th>Default</th><th /></tr></thead>
          <tbody>{roles.data.items.map((r: any) => <tr key={r.id}><td className="font-medium">{r.name}{r.privileged && <span className="pill bg-amber-500/15 text-amber-300 ml-1">privileged</span>}
            <div className="text-2xs text-muted">{r.description}</div></td>
            <td className="text-xs">{r.explain.vendors.cisco.privilege}</td><td className="text-xs">{r.explain.vendors.ruckus.privilege}</td><td className="text-xs">{r.explain.vendors.fortinet.privilege}</td>
            <td className="text-xs">{r.command_categories.join(", ")}</td><td>{r.default_command_action}</td>
            <td className="whitespace-nowrap"><button className="btn" onClick={() => setExplain(r)}>Effective access</button>{" "}
              {can("policy_admin") && <button className="btn" onClick={() => setRole({ ...r, cisco: r.vendor_profiles.cisco?.priv_lvl ?? "", ruckus: r.vendor_profiles.ruckus?.priv_lvl ?? "",
                fortinet: r.vendor_profiles.fortinet?.admin_profile ?? "" })}>Edit</button>}</td></tr>)}</tbody></table></TableWrap>)}
      <ErrorText e={seed.error} />
    </Card>
    <Card title={`Role mappings${maps.data ? ` (${maps.data.items.length})` : ""}`} bodyClass="p-0" right={can("policy_admin") &&
      <button className="btn btn-primary" onClick={() => setMap({ principal_type: "group", principal: "", role_id: roles.data?.items[0]?.id || "", scope_sites: "", scope_device_groups: "",
        scope_vendors: "", scope_clients: "", time_window: "", priority: 100, justification: "", expires_at: "", enabled: true })}>+ Add mapping</button>}>
      <p className="text-2xs text-muted p-2">Evaluated in this order: disabled users and policy denials first, then mappings by priority (lower first) and specificity (device &gt; device
        group &gt; site &gt; vendor &gt; all). The first matching mapping decides; no match means deny.</p>
      <Loading q={maps} />
      {maps.data && (!maps.data.items.length ? <Empty text="No mappings: everyone is denied." /> :
        <TableWrap><table className="tbl"><thead><tr><th className="num">Priority</th><th>Who</th><th>Role</th><th>Scope</th><th>Time</th><th>Expires</th><th>Justification</th><th /></tr></thead>
          <tbody>{maps.data.items.map((m: any) => <tr key={m.id} className={m.enabled ? "" : "opacity-60"}><td className="num">{m.priority}</td><td>{m.principal_type} <b>{m.principal}</b></td>
            <td>{m.role}</td><td className="text-xs">{[m.scope_clients.length && `devices ${m.scope_clients.join(", ")}`, m.scope_device_groups.length && `groups ${m.scope_device_groups.join(", ")}`,
              m.scope_sites.length && `sites ${m.scope_sites.join(", ")}`, m.scope_vendors.length && `vendors ${m.scope_vendors.join(", ")}`].filter(Boolean).join("; ") || "all devices"}</td>
            <td className="font-mono text-xs">{m.time_window || "any"}</td><td><Time v={m.expires_at} /></td><td className="text-xs">{m.justification}</td>
            <td>{can("policy_admin") && <button className="btn" onClick={() => setMap({ ...m, scope_sites: m.scope_sites.join(", "), scope_device_groups: m.scope_device_groups.join(", "),
              scope_vendors: m.scope_vendors.join(", "), scope_clients: m.scope_clients.join(", "), expires_at: m.expires_at?.slice(0, 10) || "" })}>Edit</button>}</td></tr>)}</tbody></table></TableWrap>)}
    </Card>
    <Card title={`Command rules${rules.data ? ` (${rules.data.items.length})` : ""}`} bodyClass="p-0" right={can("policy_admin") &&
      <button className="btn btn-primary" onClick={() => setRule({ role_id: roles.data?.items[0]?.id || "", vendor: "cisco", action: "deny", match: "category", pattern: "", category: "reload_reset",
        priority: 100, exception: false, owner: "", justification: "", expires_at: "", enabled: true, description: "" })}>+ Add rule</button>}>
      <Loading q={rules} />
      {rules.data && (!rules.data.items.length ? <Empty text="No explicit rules: roles permit their categories and apply their default action." /> :
        <TableWrap><table className="tbl"><thead><tr><th>Role</th><th>Vendor</th><th className="num">Priority</th><th>Action</th><th>Match</th><th>Exception</th><th>Expires</th><th /></tr></thead>
          <tbody>{rules.data.items.map((r: any) => <tr key={r.id} className={r.enabled && !r.expired ? "" : "opacity-60"}><td>{rname(r.role_id)}</td><td>{r.vendor}</td><td className="num">{r.priority}</td>
            <td><Status s={r.action} /></td><td className="font-mono text-xs">{r.match === "regex" ? `/${r.pattern}/` : `category ${r.category}`}<div className="text-muted not-italic">{r.description}</div></td>
            <td className="text-xs">{r.exception ? `${r.owner}: ${r.justification}` : "—"}</td><td><Time v={r.expires_at} />{r.expired && <span className="text-red-300"> expired</span>}</td>
            <td>{can("policy_admin") && <button className="btn" onClick={() => setRule({ ...r, expires_at: r.expires_at?.slice(0, 10) || "" })}>Edit</button>}</td></tr>)}</tbody></table></TableWrap>)}
    </Card>
    <Card title="Conflicts and validation" bodyClass="p-0">
      {conf.data && (!conf.data.items.length && !conf.data.validation.warnings.length ? <Empty text="No conflicts detected." /> :
        <ul className="p-3 text-xs space-y-1">{conf.data.items.map((c: any, i: number) => <li key={i} className={c.type === "exception_incomplete" ? "text-red-300" : "text-amber-300"}>
          {c.type.replace(/_/g, " ")}: {c.detail} ({c.role})</li>)}{conf.data.validation.warnings.filter((w: string) => !w.includes(":")).map((w: string) => <li key={w} className="text-muted">{w}</li>)}</ul>)}
    </Card>
    <Simulator />
    {role && <RoleForm x={role} categories={meta.data?.categories || {}} onClose={() => setRole(null)} />}
    {map && <MappingForm x={map} roles={roles.data?.items || []} onClose={() => setMap(null)} />}
    {rule && <RuleForm x={rule} roles={roles.data?.items || []} categories={meta.data?.categories || {}} onClose={() => setRule(null)} />}
    {explain && <Modal wide title={`Effective access · ${explain.name}`} onClose={() => setExplain(null)}>
      <div className="grid gap-3 sm:grid-cols-2">{Object.entries(explain.explain.vendors).map(([v, x]: [string, any]) => <div key={v} className="border border-line rounded p-3 text-xs space-y-1">
        <b>{x.label}</b><div>Privilege: {x.privilege}</div><div>Enforcement: <span className={x.enforcement === "per-command" ? "text-emerald-300" : "text-amber-300"}>{x.enforcement}</span> — {x.note}</div>
        {x.enforcement === "per-command" && <><div>Permitted categories: {x.permitted_categories.join(", ") || "none"}</div>
          <div>Explicit rules: {x.explicit_rules.map((r: any) => `${r.action} /${r.regex.slice(0, 60)}/`).join("; ") || "none"}</div><div>Anything else: {x.default}</div></>}</div>)}</div>
    </Modal>}
  </div>;
}

function RoleForm({ x, categories, onClose }: { x: any; categories: Record<string, string>; onClose: () => void }) {
  const [f, setF] = useState<any>(x);
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value });
  const vp: any = {};
  if (f.cisco !== "") vp.cisco = { priv_lvl: Number(f.cisco) };
  if (f.ruckus !== "") vp.ruckus = { priv_lvl: Number(f.ruckus) };
  if (f.fortinet) vp.fortinet = { admin_profile: f.fortinet };
  const save = useSave(() => api(x.id ? `/tacacs/roles/${x.id}` : "/tacacs/roles", { method: x.id ? "PUT" : "POST", body: { name: f.name, description: f.description, privileged: f.privileged,
    vendor_profiles: vp, default_command_action: f.default_command_action, command_categories: f.command_categories } }), ["tac-roles", "tac-conflicts"], onClose);
  const del = useSave(() => api(`/tacacs/roles/${x.id}`, { method: "DELETE" }), ["tac-roles"], onClose);
  const toggle = (c: string) => setF({ ...f, command_categories: f.command_categories.includes(c) ? f.command_categories.filter((x: string) => x !== c) : [...f.command_categories, c] });
  return <Modal wide title={x.id ? `Edit ${x.name}` : "Add role"} onClose={onClose}>
    <div className="grid gap-2 sm:grid-cols-3">
      <Field label="Name"><input className="input w-full" value={f.name} onChange={set("name")} /></Field>
      <div className="sm:col-span-2"><Field label="Description"><input className="input w-full" value={f.description} onChange={set("description")} /></Field></div>
      <Field label="Cisco priv-lvl (0-15; 1 user, 15 full)"><input type="number" className="input w-full" value={f.cisco} onChange={set("cisco")} /></Field>
      <Field label="Ruckus foundry-privlvl"><select className="input w-full" value={f.ruckus} onChange={set("ruckus")}><option value="">— not set —</option>
        <option value="0">0 super-user</option><option value="4">4 port-config</option><option value="5">5 read-only</option></select></Field>
      <Field label="FortiGate admin profile (accprofile)"><input className="input w-full" value={f.fortinet} onChange={set("fortinet")} /></Field>
      <Field label="Default for unmatched commands"><select className="input w-full" value={f.default_command_action} onChange={set("default_command_action")}><option>deny</option><option>permit</option></select></Field>
      <label className="text-sm flex items-center gap-2"><input type="checkbox" checked={f.privileged} onChange={set("privileged")} />Privileged (enable allowed; mappings need a justification)</label>
    </div>
    <div className="mt-2"><div className="label">Permitted command categories (Cisco / Ruckus)</div><div className="flex flex-wrap gap-2">
      {Object.entries(categories).map(([c, d]) => <label key={c} className="text-xs flex items-center gap-1" title={d}><input type="checkbox" checked={f.command_categories.includes(c)} onChange={() => toggle(c)} />{c}</label>)}</div></div>
    <ErrorText e={save.error || del.error} />
    <div className="flex gap-2 mt-3"><button className="btn btn-primary" disabled={save.isPending || !f.name} onClick={() => save.mutate(null)}>Save</button>
      {x.id && <button className="btn btn-danger ml-auto" onClick={() => confirm(`Delete ${x.name} and its mappings / rules?`) && del.mutate(null)}>Delete</button>}</div>
  </Modal>;
}

function MappingForm({ x, roles, onClose }: { x: any; roles: any[]; onClose: () => void }) {
  const [f, setF] = useState<any>(x);
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value });
  const body = () => ({ principal_type: f.principal_type, principal: f.principal, role_id: Number(f.role_id), scope_sites: list(f.scope_sites), scope_device_groups: list(f.scope_device_groups),
    scope_vendors: list(f.scope_vendors), scope_clients: list(f.scope_clients), time_window: f.time_window, priority: Number(f.priority), justification: f.justification,
    expires_at: f.expires_at ? `${f.expires_at}T23:59:59Z` : null, enabled: f.enabled });
  const save = useSave(() => api(x.id ? `/tacacs/mappings/${x.id}` : "/tacacs/mappings", { method: x.id ? "PUT" : "POST", body: body() }), ["tac-mappings", "tac-conflicts", "tac-users"], onClose);
  const del = useSave(() => api(`/tacacs/mappings/${x.id}`, { method: "DELETE" }), ["tac-mappings"], onClose);
  const priv = roles.find((r) => r.id === Number(f.role_id))?.privileged;
  return <Modal title={x.id ? "Edit mapping" : "Add role mapping"} onClose={onClose}>
    <div className="grid gap-2 sm:grid-cols-2">
      <Field label="Type"><select className="input w-full" value={f.principal_type} onChange={set("principal_type")}><option>group</option><option>user</option></select></Field>
      <Field label={f.principal_type === "group" ? "Group (from memberOf regex or local group)" : "User name"}><input className="input w-full" value={f.principal} onChange={set("principal")} /></Field>
      <Field label="Role"><select className="input w-full" value={f.role_id} onChange={set("role_id")}>{roles.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}</select></Field>
      <Field label="Priority (lower first)"><input type="number" className="input w-full" value={f.priority} onChange={set("priority")} /></Field>
      <Field label="Sites (comma-separated)"><input className="input w-full" value={f.scope_sites} onChange={set("scope_sites")} /></Field>
      <Field label="Device groups"><input className="input w-full" value={f.scope_device_groups} onChange={set("scope_device_groups")} /></Field>
      <Field label="Vendors (fortinet, cisco, ruckus, other)"><input className="input w-full" value={f.scope_vendors} onChange={set("scope_vendors")} /></Field>
      <Field label="Specific devices (client names)"><input className="input w-full" value={f.scope_clients} onChange={set("scope_clients")} /></Field>
      <Field label="Time window (cron: min hour dom month dow)"><input className="input w-full font-mono" value={f.time_window} onChange={set("time_window")} placeholder="* 8-19 * * 1-5" /></Field>
      <Field label="Expires"><input type="date" className="input w-full" value={f.expires_at} onChange={set("expires_at")} /></Field>
      <div className="sm:col-span-2"><Field label={`Justification${priv ? " (required: privileged role)" : ""}`}><input className="input w-full" value={f.justification} onChange={set("justification")} /></Field></div>
      <label className="text-sm flex items-center gap-2"><input type="checkbox" checked={f.enabled} onChange={set("enabled")} />Enabled</label>
    </div>
    <ErrorText e={save.error || del.error} />
    <div className="flex gap-2 mt-3"><button className="btn btn-primary" disabled={save.isPending || !f.principal} onClick={() => save.mutate(null)}>Save</button>
      {x.id && <button className="btn btn-danger ml-auto" onClick={() => confirm("Delete this mapping?") && del.mutate(null)}>Delete</button>}</div>
  </Modal>;
}

function RuleForm({ x, roles, categories, onClose }: { x: any; roles: any[]; categories: Record<string, string>; onClose: () => void }) {
  const [f, setF] = useState<any>(x);
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value });
  const body = () => ({ ...f, role_id: Number(f.role_id), priority: Number(f.priority), expires_at: f.expires_at ? `${f.expires_at}T23:59:59Z` : null, id: undefined, expired: undefined,
    created_by: undefined, created_at: undefined });
  const save = useSave(() => api(x.id ? `/tacacs/command-rules/${x.id}` : "/tacacs/command-rules", { method: x.id ? "PUT" : "POST", body: body() }), ["tac-rules", "tac-conflicts", "tac-roles"], onClose);
  const del = useSave(() => api(`/tacacs/command-rules/${x.id}`, { method: "DELETE" }), ["tac-rules"], onClose);
  return <Modal title={x.id ? "Edit command rule" : "Add command rule"} onClose={onClose}>
    <div className="grid gap-2 sm:grid-cols-2">
      <Field label="Role"><select className="input w-full" value={f.role_id} onChange={set("role_id")}>{roles.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}</select></Field>
      <Field label="Vendor"><select className="input w-full" value={f.vendor} onChange={set("vendor")}>{["cisco", "ruckus", "other", "any"].map((v) => <option key={v}>{v}</option>)}</select></Field>
      <Field label="Action"><select className="input w-full" value={f.action} onChange={set("action")}><option>deny</option><option>permit</option></select></Field>
      <Field label="Priority (lower first; deny wins ties)"><input type="number" className="input w-full" value={f.priority} onChange={set("priority")} /></Field>
      <Field label="Match"><select className="input w-full" value={f.match} onChange={set("match")}><option value="category">category</option><option value="regex">regular expression</option></select></Field>
      {f.match === "regex" ? <Field label="Pattern (no lookaround / backrefs)"><input className="input w-full font-mono" value={f.pattern} onChange={set("pattern")} placeholder="^debug " /></Field>
        : <Field label="Category"><select className="input w-full" value={f.category} onChange={set("category")}>{Object.keys(categories).map((c) => <option key={c}>{c}</option>)}</select></Field>}
      <label className="text-sm flex items-center gap-2"><input type="checkbox" checked={f.exception} onChange={set("exception")} />Exception (owner, justification and expiry required)</label>
      <Field label="Expires"><input type="date" className="input w-full" value={f.expires_at} onChange={set("expires_at")} /></Field>
      {f.exception && <><Field label="Owner"><input className="input w-full" value={f.owner} onChange={set("owner")} /></Field>
        <Field label="Justification"><input className="input w-full" value={f.justification} onChange={set("justification")} /></Field></>}
      <div className="sm:col-span-2"><Field label="Description"><input className="input w-full" value={f.description} onChange={set("description")} /></Field></div>
    </div>
    <p className="text-2xs text-amber-300 mt-2">Command rules are not enforced on FortiGates. Test permitted, denied and unmatched commands in the simulator before deploying.</p>
    <ErrorText e={save.error || del.error} />
    <div className="flex gap-2 mt-3"><button className="btn btn-primary" disabled={save.isPending} onClick={() => save.mutate(null)}>Save</button>
      {x.id && <button className="btn btn-danger ml-auto" onClick={() => confirm("Delete this rule?") && del.mutate(null)}>Delete</button>}</div>
  </Modal>;
}

export function Simulator() {
  const clients = useQuery({ queryKey: ["tac-clients-all"], queryFn: () => api<any>("/tacacs/clients", { params: { limit: 1000 } }) });
  const [f, setF] = useState({ username: "", groups: "", client_id: "", commands: "show running-config\nconfigure terminal\nreload", at: "" });
  const run = useSave(() => api<any>("/tacacs/policy/simulate", { method: "POST", body: { username: f.username, groups: list(f.groups), client_id: Number(f.client_id),
    commands: f.commands.split("\n").map((x) => x.trim()).filter(Boolean), at: f.at ? new Date(f.at).toISOString() : null } }), []);
  const r: any = run.data;
  return <Card title="Policy simulator (permitted, denied and unmatched commands)">
    <div className="grid gap-2 sm:grid-cols-4">
      <Field label="User"><input className="input w-full" value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} /></Field>
      <Field label="Groups (directory users)"><input className="input w-full" value={f.groups} onChange={(e) => setF({ ...f, groups: e.target.value })} /></Field>
      <Field label="Device"><select className="input w-full" value={f.client_id} onChange={(e) => setF({ ...f, client_id: e.target.value })}><option value="">—</option>
        {(clients.data?.items || []).map((c: any) => <option key={c.id} value={c.id}>{c.name} ({c.vendor})</option>)}</select></Field>
      <Field label="At (optional)"><input type="datetime-local" className="input w-full" value={f.at} onChange={(e) => setF({ ...f, at: e.target.value })} /></Field>
      <div className="sm:col-span-4"><Field label="Commands (one per line)"><textarea className="input w-full font-mono text-xs h-24" value={f.commands} onChange={(e) => setF({ ...f, commands: e.target.value })} /></Field></div>
    </div>
    <button className="btn btn-primary mt-2" disabled={!f.username || !f.client_id || run.isPending} onClick={() => run.mutate(null)}>Simulate</button>
    <ErrorText e={run.error} />
    {r && <div className="mt-3 space-y-2 text-sm">
      <div>Exec authorization: <Status s={r.exec.decision} /> — {r.exec.reason}{r.exec.vendor_profile && Object.keys(r.exec.vendor_profile).length > 0 &&
        <span className="text-muted"> · returns {JSON.stringify(r.exec.vendor_profile)}</span>}{!r.known_user && <span className="text-amber-300"> (user not in the registry: directory user assumed)</span>}</div>
      <TableWrap><table className="tbl"><thead><tr><th>Command</th><th>Category</th><th>Decision</th><th className="w-full">Why</th></tr></thead>
        <tbody>{r.commands.map((c: any, i: number) => <tr key={i}><td className="font-mono text-xs">{c.command}</td><td className="text-xs">{c.category}</td><td><Status s={c.decision} /></td>
          <td className="text-xs">{c.reason}</td></tr>)}</tbody></table></TableWrap>
      <p className="text-2xs text-muted">{r.note}</p></div>}
  </Card>;
}
