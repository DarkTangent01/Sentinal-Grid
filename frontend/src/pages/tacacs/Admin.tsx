import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { Card, Empty, Loading, Sev, TableWrap, Time } from "../../components/ui";
import { Denied, ErrorText, Field, Pager, Status, useCan, useSave, useTacMeta } from "./common";

export function Health() {
  const q = useQuery({ queryKey: ["tac-health"], queryFn: () => api<any>("/tacacs/health"), refetchInterval: 30_000 });
  const [sel, setSel] = useState<number | null>(null);
  const hist = useQuery({ queryKey: ["tac-health-hist", sel], enabled: sel != null, queryFn: () => api<any>(`/tacacs/servers/${sel}/health`, { params: { limit: 200 } }) });
  const d = q.data;
  return <div className="space-y-4">
    <Loading q={q} />
    {d && <>
      <Card title="Servers" bodyClass="p-0">{!d.servers.length ? <Empty text="No servers registered." /> :
        <TableWrap><table className="tbl"><thead><tr><th>Server</th><th>Role</th><th>Status</th><th className="num">Availability 24 h</th><th>Last check</th><th>Agent</th>
          <th className="num">Clients (primary / secondary)</th><th>Ingestion</th><th /></tr></thead>
          <tbody>{d.servers.map((x: any) => <tr key={x.id}><td className="font-medium">{x.name}<div className="text-2xs text-muted">{x.management_address}:{x.port}</div></td><td>{x.role}</td>
            <td><Status s={x.status} /><div className="text-2xs text-red-300">{x.last_error}</div></td><td className="num">{x.availability_24h == null ? "—" : `${x.availability_24h}%`}</td>
            <td><Time v={x.last_check_at} /></td>
            <td className="text-xs">{x.kind !== "managed" ? "external" : x.agent?.time ? <>{x.agent.running ? "running" : "stopped"} · {x.agent.listening ? "listening" : "not listening"} · restarts {x.agent.restarts}</> : "no status"}</td>
            <td className="num">{x.clients_primary} / {x.clients_secondary}</td>
            <td className="text-xs">{x.kind === "managed" ? Object.entries(x.ingestion || {}).map(([k, v]: [string, any]) => <div key={k} className={v.missing || v.parse_errors ? "text-amber-300" : ""}>
              {k}: {v.missing ? "file missing" : `${v.lines || 0} lines, ${v.parse_errors || 0} errors, ${v.duplicates || 0} duplicates`}</div>) : "—"}</td>
            <td><button className="btn" onClick={() => setSel(x.id)}>History</button></td></tr>)}</tbody></table></TableWrap>}</Card>
      {sel != null && <Card title="Health checks" bodyClass="p-0" right={hist.data && <span className="text-xs text-muted">availability {hist.data.availability_pct ?? "—"}% over {hist.data.items.length} checks</span>}>
        <Loading q={hist} />{hist.data && <TableWrap maxH="max-h-80"><table className="tbl"><thead><tr><th>Time</th><th>Status</th><th>TCP</th><th className="num">Latency</th><th>Agent</th><th className="w-full">Detail</th></tr></thead>
          <tbody>{hist.data.items.map((h: any, i: number) => <tr key={i}><td><Time v={h.at} /></td><td><Status s={h.status} /></td><td>{h.tcp_ok ? "ok" : "fail"}</td>
            <td className="num">{h.latency_ms != null ? `${h.latency_ms} ms` : "—"}</td><td>{h.agent_ok == null ? "n/a" : h.agent_ok ? "ok" : "fail"}</td><td className="text-xs">{h.detail}</td></tr>)}</tbody></table></TableWrap>}</Card>}
      <Card title="Failover">
        {d.clients_without_secondary.length ? <p className="text-sm text-amber-300">{d.clients_without_secondary.length} client(s) have no secondary server: {d.clients_without_secondary.slice(0, 20).join(", ")}</p>
          : <p className="text-sm text-emerald-300">Every enabled client has a secondary server.</p>}
        <ul className="list-disc ml-5 text-xs text-muted mt-2">{d.notes.map((n: string) => <li key={n}>{n}</li>)}</ul>
        <p className="text-xs mt-2">Test reachability of a client's primary and secondary server in the Testing center. Never remove a device's local emergency fallback while testing failover.</p>
      </Card>
    </>}
  </div>;
}

export function AlertsTab() {
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState("");
  const q = useQuery({ queryKey: ["tac-alerts", page, status], refetchInterval: 30_000, placeholderData: (p) => p,
    queryFn: () => api<any>("/alerts", { params: { rule_prefix: "tacacs_", size: 100, page, status: status || undefined } }) });
  const items = q.data?.items || [];
  return <Card title={`TACACS+ security alerts${q.data ? ` (${q.data.total})` : ""}`} bodyClass="p-0" right={<>
    <select aria-label="Status" className="input py-1" value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }}><option value="">Any status</option>
      {["new", "investigating", "resolved", "suppressed"].map((x) => <option key={x}>{x}</option>)}</select>
    <Link className="btn" to="/detections">Tune detection rules</Link></>}>
    <Loading q={q} />
    {q.data && (!items.length ? <Empty text="No TACACS+ alerts." /> :
      <TableWrap><table className="tbl"><thead><tr><th>Severity</th><th>Alert</th><th>Status</th><th>User / device</th><th>First seen</th><th>Last seen</th><th className="w-full">Detail</th></tr></thead>
        <tbody>{items.map((a: any) => <tr key={a.id}><td><Sev s={a.severity} /></td><td><Link className="link" to={`/alerts?id=${a.id}`}>{a.name}</Link><div className="text-2xs text-muted">{a.rule_key}</div></td>
          <td>{a.status}</td><td className="text-xs">{a.evidence?.user}{a.evidence?.device && <div className="text-muted">{a.evidence.device}</div>}</td>
          <td><Time v={a.first_seen} /></td><td><Time v={a.last_seen} /></td><td className="text-xs">{a.explanation}
            {a.evidence?.investigation?.length > 0 && <ul className="list-disc ml-4 text-muted">{a.evidence.investigation.map((s: string) => <li key={s}>{s}</li>)}</ul>}</td></tr>)}</tbody></table></TableWrap>)}
    {q.data && <Pager total={q.data.total} limit={100} offset={(page - 1) * 100} onChange={(o) => setPage(o / 100 + 1)} />}
    <p className="text-2xs text-muted p-2">Detections run in the SIEM alert engine: de-duplicated per user / device, thresholds and windows editable under Detections, notifications via the existing
      channels (subscribe to alert.resolved for recoveries), and correlated into incidents by user.</p>
  </Card>;
}

export function Audit() {
  const can = useCan();
  const [q, setQ] = useState("");
  const [offset, setOffset] = useState(0);
  const ok = can("auditor") || can("policy_admin") || can("approver");
  const r = useQuery({ queryKey: ["tac-audit", q, offset], enabled: ok, placeholderData: (p) => p, queryFn: () => api<any>("/tacacs/audit", { params: { q: q || undefined, limit: 200, offset } }) });
  if (!ok) return <Denied role="auditor" what="read the TACACS+ change history" />;
  return <Card title={`Audit and change history${r.data ? ` (${r.data.total})` : ""}`} bodyClass="p-0"
    right={<input aria-label="Filter" className="input py-1 w-48" placeholder="action, target, user" value={q} onChange={(e) => { setQ(e.target.value); setOffset(0); }} />}>
    <Loading q={r} />
    {r.data && (!r.data.items.length ? <Empty text="No entries." /> :
      <TableWrap><table className="tbl"><thead><tr><th>Time</th><th>User</th><th>Action</th><th>Target</th><th>Client IP</th><th className="w-full">Detail</th></tr></thead>
        <tbody>{r.data.items.map((a: any, i: number) => <tr key={i} className={a.success ? "" : "bg-red-500/5"}><td><Time v={a.ts} /></td><td>{a.user}</td>
          <td className={a.success ? "" : "text-red-300"}>{a.action}{!a.success && " (refused)"}</td><td className="text-xs">{a.target}</td><td className="font-mono text-xs">{a.client_ip}</td>
          <td className="font-mono text-2xs break-all">{JSON.stringify(a.detail)}</td></tr>)}</tbody></table></TableWrap>)}
    {r.data && <Pager total={r.data.total} limit={200} offset={offset} onChange={setOffset} />}
  </Card>;
}

export function SettingsTab() {
  const can = useCan();
  const meta = useTacMeta();
  const q = useQuery({ queryKey: ["tac-settings"], queryFn: () => api<any>("/tacacs/settings") });
  const [f, setF] = useState<any>(null);
  useEffect(() => { if (q.data && !f) setF({ ...q.data, client_networks: q.data.client_networks.join("\n"), redaction_rules: q.data.redaction_rules.join("\n"), rotate_tester_secret: false }); }, [q.data]);  // eslint-disable-line react-hooks/exhaustive-deps
  const save = useSave(() => api("/tacacs/settings", { method: "PUT", body: { ...f, client_networks: f.client_networks.split("\n").map((x: string) => x.trim()).filter(Boolean),
    redaction_rules: f.redaction_rules.split("\n").map((x: string) => x.trim()).filter(Boolean), max_prefix_without_approval: Number(f.max_prefix_without_approval),
    accounting_gap_hours: Number(f.accounting_gap_hours), tester_secret_set: undefined } }), ["tac-settings", "tac-meta"]);
  return <div className="space-y-4">
    <Card title="Settings">
      <Loading q={q} />
      {f && <div className="grid gap-3 lg:grid-cols-2">
        <Field label="Authorised client networks (one CIDR per line): devices outside them cannot be registered"><textarea className="input w-full font-mono text-xs h-28" value={f.client_networks}
          onChange={(e) => setF({ ...f, client_networks: e.target.value })} disabled={!can("policy_admin")} /></Field>
        <Field label="Extra redaction rules (Python regex, one per line; applied before storage)"><textarea className="input w-full font-mono text-xs h-28" value={f.redaction_rules}
          onChange={(e) => setF({ ...f, redaction_rules: e.target.value })} disabled={!can("policy_admin")} /></Field>
        <Field label="Tester source address (the SIEM worker's IP as seen by the TACACS+ server)"><input className="input w-full font-mono" value={f.tester_address}
          onChange={(e) => setF({ ...f, tester_address: e.target.value })} disabled={!can("policy_admin")} placeholder="172.18.0.5" /></Field>
        <Field label="Address ranges wider than this prefix need a justification"><input type="number" className="input w-full" value={f.max_prefix_without_approval}
          onChange={(e) => setF({ ...f, max_prefix_without_approval: e.target.value })} disabled={!can("policy_admin")} /></Field>
        <label className="text-sm flex items-center gap-2"><input type="checkbox" checked={f.require_approval} onChange={(e) => setF({ ...f, require_approval: e.target.checked })}
          disabled={!can("policy_admin")} />Require approval for every deployment (production servers always require it)</label>
        <label className="text-sm flex items-center gap-2"><input type="checkbox" checked={f.rotate_tester_secret} onChange={(e) => setF({ ...f, rotate_tester_secret: e.target.checked })}
          disabled={!can("policy_admin")} />Rotate the tester key ({q.data?.tester_secret_set ? "set" : "not set"})</label>
        {can("policy_admin") && <div><button className="btn btn-primary" disabled={save.isPending} onClick={() => save.mutate(null)}>Save settings</button><ErrorText e={save.error} /></div>}
      </div>}
    </Card>
    {meta.data?.is_siem_admin ? <RoleAssignment /> : <Card title="TACACS+ roles"><p className="text-sm text-muted">Only SIEM administrators assign TACACS+ roles.</p></Card>}
  </div>;
}

function RoleAssignment() {
  const q = useQuery({ queryKey: ["tac-rbac"], queryFn: () => api<any>("/tacacs/rbac") });
  const save = useSave(({ id, roles }: any) => api(`/tacacs/rbac/${id}`, { method: "PUT", body: { tacacs_roles: roles } }), ["tac-rbac"]);
  return <Card title="Role assignment" bodyClass="p-0">
    <Loading q={q} />
    {q.data && <TableWrap><table className="tbl"><thead><tr><th>User</th><th>SIEM role</th>{Object.keys(q.data.roles).map((r) => <th key={r} title={q.data.roles[r]}>{r}</th>)}</tr></thead>
      <tbody>{q.data.users.map((u: any) => <tr key={u.id}><td>{u.username}</td><td>{u.siem_role}</td>{Object.keys(q.data.roles).map((r) => <td key={r}>
        <input type="checkbox" aria-label={`${r} for ${u.username}`} checked={u.tacacs_roles.includes(r)} disabled={u.siem_role === "admin" || save.isPending}
          onChange={(e) => save.mutate({ id: u.id, roles: e.target.checked ? [...u.tacacs_roles, r] : u.tacacs_roles.filter((x: string) => x !== r) })} /></td>)}</tr>)}</tbody></table></TableWrap>}
    <ErrorText e={save.error} />
    <p className="text-2xs text-muted p-2">SIEM administrators hold every TACACS+ role; separation of duties still applies (nobody approves their own deployment). Changing roles signs the user out.</p>
  </Card>;
}
