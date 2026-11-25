/** Wireless → Integrations: Ruckus SmartZone / vSZ, Ruckus One, Juniper Mist and Aruba Central as wireless data sources
 *  (GET / POST /api/wireless/integrations). Their APs and clients appear in every wireless page like a polled controller's. */
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { useMe } from "../../lib/context";
import { Card, Empty, Field, Loading, Modal, TableWrap, Time } from "../../components/ui";

const HINT: Record<string, { url: string; org: string; cred: string }> = {
  smartzone: { url: "https://<controller management IP>:8443", org: "", cred: "https (API user and password)" },
  ruckus_one: { url: "https://api.ruckus.cloud (or api.eu / api.asia)", org: "Tenant id", cred: "api_token (username = OAuth client id, token = client secret)" },
  mist: { url: "https://api.mist.com (or your region, e.g. api.eu.mist.com)", org: "Organisation id", cred: "api_token (API token)" },
  aruba_central: { url: "https://apigw-<region>.central.arubanetworks.com", org: "", cred: "api_token (access token; client id / secret / refresh token to renew it)" },
};

export function IntegrationsTab() {
  const qc = useQueryClient();
  const me = useMe();
  const admin = me.role === "admin";
  const [edit, setEdit] = useState<any | null>(null);
  const q = useQuery({ queryKey: ["wl-integrations"], queryFn: () => api<any>("/wireless/integrations"), refetchInterval: 30_000 });
  const sync = useMutation({ mutationFn: (id: number) => api<any>(`/wireless/integrations/${id}/sync`, { method: "POST" }),
    onSettled: () => qc.invalidateQueries({ queryKey: ["wl-integrations"] }) });
  const del = useMutation({ mutationFn: (id: number) => api(`/wireless/integrations/${id}`, { method: "DELETE" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["wl-integrations"] }) });
  const items: any[] = q.data?.items || [];
  return <div className="space-y-4 mt-3">
    <p className="text-xs text-muted">Controllers and clouds read over their public REST APIs (read-only). Their APs, radios, WLANs and clients are stored like a polled controller's,
      so history, roaming, floors, analytics and alerts work the same. Requests go only to the vendor's API hosts (Mist, Ruckus One, Aruba Central) or, for SmartZone, to an address
      inside an authorised management network. Credentials are kept in the Device Access credential vault.</p>
    <Card title="Integrations" bodyClass="p-0" right={admin && <button className="btn btn-primary py-1" onClick={() => setEdit({ kind: "mist", interval_seconds: 300, enabled: true, verify_tls: true, site_filter: [] })}>Add integration</button>}>
      <Loading q={q} />
      {q.data && (!items.length ? <Empty text="No integrations. Cisco Catalyst 9800 controllers are polled over SNMP and need none." /> :
        <TableWrap><table className="tbl"><thead><tr><th>Name</th><th>Kind</th><th>API</th><th>Last sync</th><th>Result</th><th className="num">APs</th><th className="num">Clients</th><th /></tr></thead>
          <tbody>{items.map((i) => <tr key={i.id}><td className="font-medium">{i.name}{!i.enabled && <span className="pill bg-slate-800 text-slate-400 ml-1">disabled</span>}</td>
            <td className="text-xs">{i.kind_label}</td><td className="text-xs font-mono">{i.base_url}</td><td className="text-xs whitespace-nowrap"><Time v={i.last_sync_at} /></td>
            <td className="text-xs">{i.last_error ? <span className="text-red-300">{i.last_error}</span> : i.last_ok_at ? <span className="text-emerald-300">ok</span> : "—"}</td>
            <td className="num">{i.stats?.aps ?? ""}</td><td className="num">{i.stats?.clients ?? ""}{i.stats?.truncated ? "+" : ""}</td>
            <td className="whitespace-nowrap space-x-1">{admin && <>
              <button className="btn py-0.5 text-xs" disabled={sync.isPending} onClick={() => sync.mutate(i.id)}>Sync now</button>
              <button className="btn py-0.5 text-xs" onClick={() => setEdit(i)}>Edit</button>
              <button className="btn btn-danger py-0.5 text-xs" onClick={() => confirm(`Remove ${i.name}? Its controller and wireless history stay.`) && del.mutate(i.id)}>Remove</button></>}</td></tr>)}</tbody></table></TableWrap>)}
      {sync.data && <p className={`text-sm p-2 ${sync.data.ok ? "text-emerald-300" : "text-red-300"}`}>{sync.data.ok ? `Synchronised: ${sync.data.aps} APs, ${sync.data.clients} clients` : sync.data.error}</p>}
    </Card>
    {edit && <IntegrationForm i={edit} kinds={q.data?.kinds || {}} onClose={() => { setEdit(null); qc.invalidateQueries({ queryKey: ["wl-integrations"] }); }} />}
  </div>;
}

function IntegrationForm({ i, kinds, onClose }: { i: any; kinds: Record<string, string>; onClose: () => void }) {
  const [f, setF] = useState({ name: i.name || "", kind: i.kind, base_url: i.base_url || "", org_id: i.org_id || "", site_filter: (i.site_filter || []).join(", "),
    api_version: i.api_version || "", credential_id: i.credential_id || 0, verify_tls: i.verify_tls !== false, interval_seconds: i.interval_seconds || 300, enabled: i.enabled !== false });
  const vault = useQuery({ queryKey: ["access-vault"], queryFn: () => api<any>("/nms/access/vault"), retry: false });
  const want = f.kind === "smartzone" ? "https" : "api_token";
  const save = useMutation({ mutationFn: () => api(i.id ? `/wireless/integrations/${i.id}` : "/wireless/integrations", { method: i.id ? "PUT" : "POST",
    body: { ...f, credential_id: f.credential_id || null, site_filter: f.site_filter.split(",").map((x: string) => x.trim()).filter(Boolean) } }), onSuccess: onClose });
  const h = HINT[f.kind];
  return <Modal title={i.id ? `Integration ${i.name}` : "New wireless integration"} onClose={onClose}>
    <div className="space-y-3">
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Name"><input className="input w-full" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
        <Field label="Kind"><select className="input w-full" disabled={!!i.id} value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })}>
          {Object.entries(kinds).map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></Field>
      </div>
      <Field label="API base URL" hint={h.url}><input className="input w-full font-mono" value={f.base_url} onChange={(e) => setF({ ...f, base_url: e.target.value })} /></Field>
      {h.org && <Field label={h.org}><input className="input w-full" value={f.org_id} onChange={(e) => setF({ ...f, org_id: e.target.value })} /></Field>}
      {f.kind === "smartzone" && <Field label="API version" hint="for example v9_1 (empty: v9_1)"><input className="input w-40" value={f.api_version} onChange={(e) => setF({ ...f, api_version: e.target.value })} /></Field>}
      <Field label="Sites / zones / venues (comma-separated; empty = all)"><input className="input w-full" value={f.site_filter} onChange={(e) => setF({ ...f, site_filter: e.target.value })} /></Field>
      <Field label="Credential (vault)" hint={h.cred}>{vault.error ? <span className="text-xs text-amber-300">You need permission to manage the credential vault.</span> :
        <select className="input w-full" value={f.credential_id} onChange={(e) => setF({ ...f, credential_id: Number(e.target.value) })}>
          <option value={0}>—</option>{(vault.data?.items || []).filter((c: any) => c.kind === want).map((c: any) => <option key={c.id} value={c.id}>{c.name}</option>)}</select>}</Field>
      <div className="flex flex-wrap gap-4 items-end">
        <Field label="Interval (seconds)"><input type="number" min={60} className="input w-28" value={f.interval_seconds} onChange={(e) => setF({ ...f, interval_seconds: Number(e.target.value) })} /></Field>
        <label className="text-sm flex items-center gap-1"><input type="checkbox" checked={f.verify_tls} onChange={(e) => setF({ ...f, verify_tls: e.target.checked })} />Verify TLS certificate</label>
        <label className="text-sm flex items-center gap-1"><input type="checkbox" checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked })} />Enabled</label>
      </div>
      {save.error && <p role="alert" className="text-sm text-red-300">{(save.error as Error).message}</p>}
      <button className="btn btn-primary" disabled={!f.name || !f.base_url || save.isPending} onClick={() => save.mutate()}>Save</button>
    </div>
  </Modal>;
}
