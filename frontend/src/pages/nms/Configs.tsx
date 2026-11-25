/** Sentinel NMS → Config Changes: read-only SSH configuration backups (secrets masked), change history with diffs,
 *  device credential assignment and SSH credential profiles. */
import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, downloadUrl } from "../../lib/api";
import { useMe } from "../../lib/context";
import { Card, Empty, Kpi, Loading, Modal, TableWrap, Tabs, Time } from "../../components/ui";

const TABS = [{ key: "changes", label: "Changes" }, { key: "devices", label: "Devices" }, { key: "credentials", label: "SSH credentials" }];

export function ConfigsPage() {
  const [sp, setSp] = useSearchParams();
  const me = useMe();
  const admin = me?.role === "admin";
  const tab = TABS.some((t) => t.key === sp.get("tab")) ? sp.get("tab")! : "changes";
  return <div className="space-y-4 min-w-0">
    <p className="text-xs text-muted">Configurations are read over SSH with fixed, read-only show commands (never configuration mode), once a day and after a
      configuration-change trap. Passwords, secrets, keys, SNMP communities and PSKs are masked before storage. A new version is kept only when the configuration changes.</p>
    <Tabs value={tab} onChange={(t) => setSp({ tab: t })} tabs={TABS.filter((t) => admin || t.key !== "credentials")} />
    {tab === "changes" && <Changes admin={admin} switchId={sp.get("switch")} snapshot={sp.get("snapshot")} />}
    {tab === "devices" && <Devices admin={admin} />}
    {tab === "credentials" && admin && <Credentials />}
  </div>;
}

function Changes({ admin, switchId, snapshot }: { admin: boolean; switchId: string | null; snapshot: string | null }) {
  const [days, setDays] = useState(30);
  const [open, setOpen] = useState<number | null>(snapshot ? Number(snapshot) : null);
  const q = useQuery({ queryKey: ["cfg-changes", days, switchId], queryFn: () => api<any>("/nms/config/changes", { params: { days, switch_id: switchId || undefined } }) });
  const items: any[] = q.data?.items || [];
  const changed = items.filter((x) => x.trigger !== "first");
  return <>
    <div className="flex flex-wrap items-center gap-2">
      <div className="kpi-grid flex-1"><Kpi label="Changes" value={changed.length} sub={`last ${days} days`} />
        <Kpi label="Devices changed" value={new Set(changed.map((x) => x.switch_id)).size} />
        <Kpi label="First backups" value={items.length - changed.length} /></div>
      <select aria-label="Days" className="input py-1" value={days} onChange={(e) => setDays(Number(e.target.value))}>{[1, 7, 30, 90, 400].map((d) => <option key={d} value={d}>{d} days</option>)}</select>
    </div>
    <Card bodyClass="p-0"><Loading q={q} />
      {q.data && (!items.length ? <Empty text="No configuration backups yet. Assign an SSH credential to devices on the Devices tab." /> :
        <TableWrap maxH="max-h-[36rem]"><table className="tbl"><thead><tr><th>When</th><th>Device</th><th>Found by</th><th className="num">Added</th><th className="num">Removed</th><th className="num">Size</th><th /></tr></thead>
          <tbody>{items.map((x) => <tr key={x.id}><td className="whitespace-nowrap"><Time v={x.taken_at} /></td><td className="font-medium">{x.switch}</td>
            <td className="text-xs">{x.trigger === "first" ? "first backup" : `${x.trigger} backup`}</td>
            <td className="num text-emerald-300">{x.trigger === "first" ? "—" : `+${x.added}`}</td><td className="num text-red-300">{x.trigger === "first" ? "—" : `-${x.removed}`}</td>
            <td className="num text-xs">{(x.size / 1024).toFixed(1)} kB</td>
            <td>{admin && <button className="btn py-0.5 text-xs" onClick={() => setOpen(x.id)}>{x.trigger === "first" ? "View" : "Diff"}</button>}</td></tr>)}</tbody></table></TableWrap>)}
    </Card>
    {open != null && admin && <Snapshot id={open} onClose={() => setOpen(null)} />}
  </>;
}

function Snapshot({ id, onClose }: { id: number; onClose: () => void }) {
  const [full, setFull] = useState(false);
  const q = useQuery({ queryKey: ["cfg-snap", id], queryFn: () => api<any>(`/nms/config/snapshots/${id}`) });
  const d = q.data;
  return <Modal title={d ? `${d.switch} — ${d.trigger === "first" ? "first backup" : `+${d.added} / -${d.removed}`}` : "Configuration"} onClose={onClose} wide>
    <Loading q={q} />
    {d && <div className="space-y-2">
      <div className="flex gap-2 items-center"><span className="text-xs text-muted flex-1"><Time v={d.taken_at} /> · {d.note}</span>
        {d.diff && <button className="btn py-0.5 text-xs" onClick={() => setFull(!full)}>{full ? "Show diff" : "Show full configuration"}</button>}
        <a className="btn py-0.5 text-xs" href={downloadUrl(`/nms/config/snapshots/${id}/download`)}>Download</a></div>
      <pre className="text-xs font-mono bg-slate-900 text-slate-100 rounded p-3 max-h-[60vh] overflow-auto whitespace-pre">{(d.diff && !full ? d.diff : d.text).split("\n").map((l: string, i: number) =>
        <div key={i} className={!full && d.diff ? (l.startsWith("+") && !l.startsWith("+++") ? "text-emerald-300" : l.startsWith("-") && !l.startsWith("---") ? "text-red-300" : l.startsWith("@@") ? "text-sky-300" : "") : ""}>{l || " "}</div>)}</pre>
    </div>}
  </Modal>;
}

function Devices({ admin }: { admin: boolean }) {
  const qc = useQueryClient();
  const [err, setErr] = useState("");
  const q = useQuery({ queryKey: ["cfg-devices"], queryFn: () => api<any>("/nms/config/devices") });
  const creds = useQuery({ queryKey: ["cfg-creds"], queryFn: () => api<any>("/nms/config/credentials"), enabled: admin });
  const done = { onSuccess: () => { setErr(""); qc.invalidateQueries({ queryKey: ["cfg-devices"] }); }, onError: (e: Error) => setErr(e.message) };
  const assign = useMutation({ mutationFn: ({ id, cid }: { id: number; cid: number | null }) => api(`/nms/config/devices/${id}`, { method: "PUT", body: { ssh_credential_id: cid } }), ...done });
  const now = useMutation({ mutationFn: (id: number) => api(`/nms/config/devices/${id}/backup`, { method: "POST" }), ...done });
  const accept = useMutation({ mutationFn: (id: number) => api(`/nms/config/devices/${id}/accept-host-key`, { method: "POST" }), ...done });
  const items: any[] = q.data?.items || [];
  return <Card bodyClass="p-0"><Loading q={q} />
    {err && <div role="alert" className="text-sm text-red-300 p-3">{err}</div>}
    {q.data && <TableWrap maxH="max-h-[40rem]"><table className="tbl"><thead><tr><th>Device</th><th>Vendor</th><th>SSH credential</th><th>Command</th><th>Host key</th>
      <th>Last backup</th><th className="num">Versions</th><th>Status</th><th /></tr></thead>
      <tbody>{items.map((x) => <tr key={x.id}><td className="font-medium">{x.name}<div className="text-2xs text-muted">{x.address}</div></td><td>{x.vendor || "—"}</td>
        <td>{!x.supported ? <span className="text-xs text-muted">not supported</span> : admin
          ? <select className="input py-0.5 text-xs" aria-label={`SSH credential for ${x.name}`} value={x.ssh_credential_id ?? ""}
            onChange={(e) => assign.mutate({ id: x.id, cid: e.target.value ? Number(e.target.value) : null })}>
            <option value="">— none —</option>{(creds.data?.items || []).map((c: any) => <option key={c.id} value={c.id}>{c.name}</option>)}</select>
          : x.ssh_credential || "—"}</td>
        <td className="font-mono text-2xs">{x.commands.join("; ") || "—"}</td><td className="text-xs">{x.host_key || "—"}</td>
        <td className="text-xs whitespace-nowrap">{x.last_backup ? <Time v={x.last_backup} /> : "—"}</td><td className="num">{x.snapshots}</td>
        <td className={`text-xs ${x.error ? "text-red-300" : "text-emerald-300"}`}>{x.error || (x.last_backup ? "ok" : x.ssh_credential_id ? "waiting for the worker" : "")}</td>
        <td className="whitespace-nowrap">{admin && x.ssh_credential_id && <button className="btn py-0.5 text-xs" onClick={() => now.mutate(x.id)}>Back up now</button>}
          {admin && x.error?.startsWith("host_key_changed") && <button className="btn py-0.5 text-xs ml-1" onClick={() => { if (confirm("Trust the key the device presents at the next backup? Only do this after confirming the device was replaced or its key regenerated.")) accept.mutate(x.id); }}>Accept new key</button>}</td></tr>)}</tbody></table></TableWrap>}
  </Card>;
}

function Credentials() {
  const qc = useQueryClient();
  const [form, setForm] = useState<any | null>(null);
  const [err, setErr] = useState("");
  const q = useQuery({ queryKey: ["cfg-creds"], queryFn: () => api<any>("/nms/config/credentials") });
  const save = useMutation({ mutationFn: (f: any) => api(f.id ? `/nms/config/credentials/${f.id}` : "/nms/config/credentials", { method: f.id ? "PUT" : "POST", body: f }),
    onSuccess: () => { setForm(null); setErr(""); qc.invalidateQueries({ queryKey: ["cfg-creds"] }); }, onError: (e: Error) => setErr(e.message) });
  const del = useMutation({ mutationFn: (id: number) => api(`/nms/config/credentials/${id}`, { method: "DELETE" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["cfg-creds"] }) });
  return <>
    <div className="flex"><p className="text-xs text-muted flex-1">Use a read-only account on the devices (e.g. Cisco privilege level that can run show running-config, Juniper read-only class).
      Secrets are encrypted at rest and never shown again.</p>
      <button className="btn btn-primary" onClick={() => setForm({ name: "", username: "", password: "", private_key: "", description: "" })}>Add credential</button></div>
    <Card bodyClass="p-0"><Loading q={q} />
      {q.data && (!q.data.items.length ? <Empty text="No SSH credential yet." /> : <TableWrap><table className="tbl"><thead><tr><th>Name</th><th>Username</th><th className="num">Devices</th><th>Description</th><th /></tr></thead>
        <tbody>{q.data.items.map((c: any) => <tr key={c.id}><td className="font-medium">{c.name}</td><td className="font-mono text-xs">{c.username}</td><td className="num">{c.devices}</td>
          <td className="text-xs">{c.description}</td><td className="whitespace-nowrap"><button className="btn py-0.5 text-xs" onClick={() => setForm({ ...c, password: "", private_key: "" })}>Edit</button>
            <button className="btn py-0.5 text-xs ml-1" disabled={c.devices > 0} title={c.devices ? "assigned to devices" : ""} onClick={() => { if (confirm(`Delete ${c.name}?`)) del.mutate(c.id); }}>Delete</button></td></tr>)}</tbody></table></TableWrap>)}
    </Card>
    {form && <Modal title={form.id ? `Edit ${form.name}` : "Add SSH credential"} onClose={() => setForm(null)}>
      <div className="space-y-2 text-sm">
        {(["name", "username", "description"] as const).map((k) => <label key={k} className="block">{k}<input className="input w-full" value={form[k]} onChange={(e) => setForm({ ...form, [k]: e.target.value })} /></label>)}
        <label className="block">password<input className="input w-full" type="password" autoComplete="new-password" value={form.password}
          placeholder={form.id ? "unchanged" : ""} onChange={(e) => setForm({ ...form, password: e.target.value })} /></label>
        <label className="block">private key (optional, OpenSSH / PEM without passphrase)<textarea className="input w-full font-mono text-xs" rows={4} value={form.private_key}
          placeholder={form.id ? "unchanged" : ""} onChange={(e) => setForm({ ...form, private_key: e.target.value })} /></label>
        {err && <div role="alert" className="text-red-300 text-xs">{err}</div>}
        <div className="flex justify-end gap-2"><button className="btn" onClick={() => setForm(null)}>Cancel</button>
          <button className="btn btn-primary" onClick={() => save.mutate(form)}>Save</button></div>
      </div>
    </Modal>}
  </>;
}
