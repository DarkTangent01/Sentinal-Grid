import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { Card, Empty, Loading, Modal, TableWrap, Tabs, Time, Trunc } from "../components/ui";

const EVENT_LABEL: Record<string, string> = {
  "alert.created": "New alert", "incident.created": "New incident", "incident.escalated": "Incident escalated",
  "report.ready": "Report ready", "search.threshold": "Saved search threshold",
};

export function Notifications() {
  const [tab, setTab] = useState("channels");
  return (
    <div className="space-y-4 min-w-0">
      <p className="text-xs text-muted">Notifications are queued in an outbox and delivered by the worker with retries (1, 5, 15, 60 min). Webhook URLs, SMTP passwords and signing secrets are encrypted at rest and never shown again after saving.</p>
      <Tabs value={tab} onChange={setTab} tabs={[{ key: "channels", label: "Channels" }, { key: "rules", label: "Routing rules" }, { key: "log", label: "Delivery log" }]} />
      {tab === "channels" && <Channels />}
      {tab === "rules" && <Rules />}
      {tab === "log" && <Log />}
    </div>
  );
}

function Channels() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["n-channels"], queryFn: () => api<any[]>("/notifications/channels") });
  const [edit, setEdit] = useState<any>(null);
  const [test, setTest] = useState<Record<number, string>>({});
  const t = useMutation({ mutationFn: (id: number) => api<any>(`/notifications/channels/${id}/test`, { method: "POST" }),
    onSuccess: (r, id) => setTest((x) => ({ ...x, [id]: r.ok ? "✓ delivered" : `✗ ${r.error}` })) });
  const del = useMutation({ mutationFn: (id: number) => api(`/notifications/channels/${id}`, { method: "DELETE" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["n-channels"] }) });
  return (
    <Card title="Channels" right={<button className="btn btn-primary" onClick={() => setEdit({ type: "slack", name: "", config: {}, enabled: true })}>+ Channel</button>}>
      <Loading q={q} />
      {q.data && !q.data.length && <Empty text="No channels. Add Slack, Microsoft Teams, email (SMTP) or a generic webhook." />}
      {!!q.data?.length && <TableWrap><table className="tbl"><thead><tr><th>Name</th><th>Type</th><th>Target</th><th>Enabled</th><th className="w-full">Test</th><th /></tr></thead>
        <tbody>{q.data.map((c) => <tr key={c.id}><td>{c.name}</td><td className="text-xs">{c.type}</td>
          <td className="text-xs">{c.type === "email" ? (c.config.to || []).join(", ") : c.has_secret ? "URL stored (encrypted)" : <span className="text-red-400">no URL</span>}</td>
          <td className="text-xs">{c.enabled ? "yes" : "no"}</td>
          <td className="text-xs"><button className="btn" disabled={t.isPending} onClick={() => t.mutate(c.id)}>Send test</button> <span className={test[c.id]?.startsWith("✓") ? "text-emerald-400" : "text-red-400"}>{test[c.id]}</span></td>
          <td className="nowrap"><button className="btn" onClick={() => setEdit(c)}>Edit</button><button className="btn btn-danger ml-1" onClick={() => confirm(`Delete ${c.name}?`) && del.mutate(c.id)}>Delete</button></td></tr>)}</tbody></table></TableWrap>}
      {edit && <ChannelForm c={edit} onClose={() => { setEdit(null); qc.invalidateQueries({ queryKey: ["n-channels"] }); }} />}
    </Card>
  );
}

function ChannelForm({ c, onClose }: { c: any; onClose: () => void }) {
  const [f, setF] = useState<any>({ name: c.name, type: c.type, enabled: c.enabled, url: "", password: "", hmac_secret: "",
    host: c.config?.host || "", port: c.config?.port || 587, security: c.config?.security || "starttls", username: c.config?.username || "",
    from_addr: c.config?.from_addr || "", to: (c.config?.to || []).join(", ") });
  const save = useMutation({
    mutationFn: () => {
      const body: any = { name: f.name, type: f.type, enabled: f.enabled, url: f.url || null, password: f.password || null, hmac_secret: f.hmac_secret || null,
        config: f.type === "email" ? { host: f.host, port: Number(f.port), security: f.security, username: f.username, from_addr: f.from_addr,
          to: f.to.split(",").map((x: string) => x.trim()).filter(Boolean) } : {} };
      return c.id ? api(`/notifications/channels/${c.id}`, { method: "PUT", body }) : api("/notifications/channels", { method: "POST", body });
    }, onSuccess: onClose,
  });
  const i = (k: string, l: string, p: any = {}) => <div><label className="label">{l}</label><input className="input w-full" value={f[k]} onChange={(e) => setF({ ...f, [k]: e.target.value })} {...p} /></div>;
  return (
    <Modal title={c.id ? `Edit ${c.name}` : "New channel"} onClose={onClose}>
      <div className="grid gap-2 sm:grid-cols-2">
        {i("name", "Name")}
        <div><label className="label">Type</label><select className="input w-full" value={f.type} disabled={!!c.id} onChange={(e) => setF({ ...f, type: e.target.value })}>
          <option value="slack">Slack (incoming webhook)</option><option value="teams">Microsoft Teams (Workflows webhook)</option><option value="email">Email (SMTP)</option><option value="webhook">Generic webhook (JSON)</option></select></div>
        {f.type !== "email" && <div className="sm:col-span-2">{i("url", c.has_secret ? "Webhook URL (leave blank to keep current)" : "Webhook URL", { type: "password", placeholder: "https://…", autoComplete: "off" })}</div>}
        {f.type === "webhook" && <div className="sm:col-span-2">{i("hmac_secret", "HMAC signing secret (optional) → X-SIEM-Signature header", { type: "password", autoComplete: "off" })}</div>}
        {f.type === "email" && <>{i("host", "SMTP host")}{i("port", "Port", { type: "number" })}
          <div><label className="label">Security</label><select className="input w-full" value={f.security} onChange={(e) => setF({ ...f, security: e.target.value })}><option value="starttls">STARTTLS</option><option value="ssl">SSL/TLS</option><option value="none">None (internal relay only)</option></select></div>
          {i("username", "Username (optional)")}{i("password", c.has_secret ? "Password (leave blank to keep)" : "Password", { type: "password", autoComplete: "new-password" })}
          {i("from_addr", "From address")}<div className="sm:col-span-2">{i("to", "Recipients (comma-separated)")}</div></>}
        <label className="text-sm flex items-center gap-2"><input type="checkbox" checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked })} />Enabled</label>
      </div>
      {save.error && <div role="alert" className="text-sm text-red-400 mt-2">{(save.error as Error).message}</div>}
      <button className="btn btn-primary mt-3" disabled={!f.name} onClick={() => save.mutate()}>Save</button>
    </Modal>
  );
}

function Rules() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["n-rules"], queryFn: () => api<any>("/notifications/rules") });
  const chs = useQuery({ queryKey: ["n-channels"], queryFn: () => api<any[]>("/notifications/channels") });
  const [edit, setEdit] = useState<any>(null);
  const del = useMutation({ mutationFn: (id: number) => api(`/notifications/rules/${id}`, { method: "DELETE" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["n-rules"] }) });
  const chName = (id: number) => chs.data?.find((c) => c.id === id)?.name || id;
  return (
    <Card title="Routing rules" right={<button className="btn btn-primary" disabled={!chs.data?.length} onClick={() => setEdit({ name: "", channel_id: chs.data?.[0]?.id, event_types: ["incident.created", "incident.escalated"], min_severity: "high", rule_keys: [], quiet_start: null, quiet_end: null, quiet_tz: "Asia/Kolkata", dedupe_minutes: 30, enabled: true })}>+ Rule</button>}>
      {!chs.data?.length && <p className="text-xs text-amber-300 mb-2">Create a channel first.</p>}
      <Loading q={q} />
      {q.data && !q.data.rules.length && <Empty text="No routing rules: nothing is sent yet." />}
      {!!q.data?.rules.length && <TableWrap><table className="tbl"><thead><tr><th>Name</th><th>Channel</th><th>Events</th><th>Min severity</th><th>Quiet hours</th><th>De-dup</th><th>Enabled</th><th /></tr></thead>
        <tbody>{q.data.rules.map((r: any) => <tr key={r.id}><td>{r.name}</td><td className="text-xs">{chName(r.channel_id)}</td>
          <td className="text-xs min-w-[10rem]">{r.event_types.map((e: string) => EVENT_LABEL[e] || e).join(", ")}</td><td className="text-xs">{r.min_severity}+</td>
          <td className="text-xs">{r.quiet_start ? `${r.quiet_start}–${r.quiet_end} ${r.quiet_tz} (critical still sent)` : "—"}</td><td className="text-xs">{r.dedupe_minutes} min</td>
          <td className="text-xs">{r.enabled ? "yes" : "no"}</td>
          <td className="nowrap"><button className="btn" onClick={() => setEdit(r)}>Edit</button><button className="btn btn-danger ml-1" onClick={() => del.mutate(r.id)}>Delete</button></td></tr>)}</tbody></table></TableWrap>}
      {edit && <RuleForm r={edit} channels={chs.data || []} events={q.data?.event_types || Object.keys(EVENT_LABEL)} onClose={() => { setEdit(null); qc.invalidateQueries({ queryKey: ["n-rules"] }); }} />}
    </Card>
  );
}

function RuleForm({ r, channels, events, onClose }: { r: any; channels: any[]; events: string[]; onClose: () => void }) {
  const [f, setF] = useState<any>({ ...r, rule_keys: (r.rule_keys || []).join(", ") });
  const save = useMutation({
    mutationFn: () => {
      const body = { ...f, channel_id: Number(f.channel_id), dedupe_minutes: Number(f.dedupe_minutes), quiet_start: f.quiet_start || null, quiet_end: f.quiet_end || null,
        rule_keys: String(f.rule_keys).split(",").map((x) => x.trim()).filter(Boolean) };
      delete body.id;
      return r.id ? api(`/notifications/rules/${r.id}`, { method: "PUT", body }) : api("/notifications/rules", { method: "POST", body });
    }, onSuccess: onClose,
  });
  const toggle = (e: string) => setF({ ...f, event_types: f.event_types.includes(e) ? f.event_types.filter((x: string) => x !== e) : [...f.event_types, e] });
  return (
    <Modal title={r.id ? "Edit rule" : "New rule"} onClose={onClose}>
      <div className="grid gap-2 sm:grid-cols-2">
        <div><label className="label">Name</label><input className="input w-full" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></div>
        <div><label className="label">Channel</label><select className="input w-full" value={f.channel_id} onChange={(e) => setF({ ...f, channel_id: e.target.value })}>{channels.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}</select></div>
        <div className="sm:col-span-2"><label className="label">Events</label><div className="flex flex-wrap gap-3 text-sm">{events.map((e) => <label key={e} className="flex items-center gap-1"><input type="checkbox" checked={f.event_types.includes(e)} onChange={() => toggle(e)} />{EVENT_LABEL[e] || e}</label>)}</div></div>
        <div><label className="label">Minimum severity</label><select className="input w-full" value={f.min_severity} onChange={(e) => setF({ ...f, min_severity: e.target.value })}>{["informational", "low", "medium", "high", "critical"].map((x) => <option key={x}>{x}</option>)}</select></div>
        <div><label className="label">De-duplicate (minutes)</label><input type="number" min={0} className="input w-full" value={f.dedupe_minutes} onChange={(e) => setF({ ...f, dedupe_minutes: e.target.value })} /></div>
        <div className="sm:col-span-2"><label className="label">Only these detection rules (keys, optional)</label><input className="input w-full" value={f.rule_keys} onChange={(e) => setF({ ...f, rule_keys: e.target.value })} placeholder="ti_match, impossible_travel" /></div>
        <div><label className="label">Quiet hours start</label><input type="time" className="input w-full" value={f.quiet_start || ""} onChange={(e) => setF({ ...f, quiet_start: e.target.value })} /></div>
        <div><label className="label">Quiet hours end</label><input type="time" className="input w-full" value={f.quiet_end || ""} onChange={(e) => setF({ ...f, quiet_end: e.target.value })} /></div>
        <div><label className="label">Quiet hours timezone</label><input className="input w-full" value={f.quiet_tz} onChange={(e) => setF({ ...f, quiet_tz: e.target.value })} /></div>
        <label className="text-sm flex items-center gap-2 self-end"><input type="checkbox" checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked })} />Enabled</label>
      </div>
      {save.error && <div role="alert" className="text-sm text-red-400 mt-2">{(save.error as Error).message}</div>}
      <button className="btn btn-primary mt-3" disabled={!f.name || !f.event_types.length} onClick={() => save.mutate()}>Save</button>
    </Modal>
  );
}

function Log() {
  const q = useQuery({ queryKey: ["n-log"], queryFn: () => api<any[]>("/notifications/log"), refetchInterval: 15_000 });
  const cls: Record<string, string> = { sent: "text-emerald-400", failed: "text-red-400", pending: "text-amber-300", suppressed: "text-slate-400" };
  return (
    <Card title="Delivery log (latest 200)">
      <Loading q={q} />
      {q.data && !q.data.length && <Empty text="Nothing queued yet." />}
      {!!q.data?.length && <TableWrap><table className="tbl"><thead><tr><th>Queued</th><th>Event</th><th className="w-full">Title</th><th>Severity</th><th>Status</th><th className="num">Attempts</th><th>Error</th></tr></thead>
        <tbody>{q.data.map((o) => <tr key={o.id}><td><Time v={o.created_at} /></td><td className="text-xs nowrap">{EVENT_LABEL[o.event_type] || o.event_type}</td><td className="text-sm"><Trunc text={o.title} max="max-w-[28rem]" /></td>
          <td className="text-xs">{o.severity}</td><td className={`text-xs ${cls[o.status]}`}>{o.status}</td><td className="num">{o.attempts}</td><td className="text-xs text-muted"><Trunc text={o.error} /></td></tr>)}</tbody></table></TableWrap>}
    </Card>
  );
}
