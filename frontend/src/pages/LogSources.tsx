import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, qs } from "../lib/api";
import { useMe } from "../lib/context";
import { fmtNum } from "../lib/format";
import { Card, Empty, Loading, Modal, TableWrap, Time } from "../components/ui";

const KIND: Record<string, string> = { windows: "Windows Security events", cef: "CEF (any vendor)", syslog: "Plain syslog" };

const NXLOG = `<Extension json>
    Module  xm_json
</Extension>
<Input security>
    Module  im_msvistalog
    Query   <QueryList><Query Id="0"><Select Path="Security">*</Select><Select Path="System">*[System[(EventID=7045 or EventID=104)]]</Select></Query></QueryList>
    Exec    to_json();
</Input>
<Output siem>
    Module  om_tcp
    Host    SIEM_ADDRESS
    Port    514
</Output>
<Route r>
    Path    security => siem
</Route>`;

export function LogSources() {
  const me = useMe();
  const nav = useNavigate();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["log-sources"], queryFn: () => api<any[]>("/log-sources"), refetchInterval: 60_000 });
  const [edit, setEdit] = useState<any>(null);
  const del = useMutation({ mutationFn: (id: number) => api(`/log-sources/${id}`, { method: "DELETE" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["log-sources"] }) });
  const admin = me.role === "admin";
  return (
    <div className="space-y-4 min-w-0">
      <p className="text-xs text-muted">Send logs from systems other than FortiGate — Windows domain controllers and servers, or any device that speaks CEF — to the same syslog
        port (514, TCP or UDP). Register each sender's IP here; its events land in the same store, so Search, hunts, detections, workbooks and reports cover them.
        Built-in Windows detections (brute force, password spraying, lockouts, privileged-group changes, cleared logs, new services) switch on automatically when Windows events arrive.</p>
      <Card title="Log sources" right={admin && <button className="btn btn-primary" onClick={() => setEdit({ name: "", kind: "windows", source_ips: [""], site: "", enabled: true, description: "" })}>+ Add source</button>}>
        <Loading q={q} />
        {q.data && !q.data.length && <Empty text="No non-FortiGate sources yet." />}
        {!!q.data?.length && <TableWrap><table className="tbl"><thead><tr><th>Name</th><th>Type</th><th>Sender IPs</th><th>Site</th><th className="num">Events 24 h</th>
          <th className="num">Total</th><th>Last event</th><th>Enabled</th><th /></tr></thead>
          <tbody>{q.data.map((x) => <tr key={x.id}>
            <td>{x.name}{x.description && <div className="text-2xs text-muted">{x.description}</div>}</td><td className="text-xs">{KIND[x.kind]}</td>
            <td className="font-mono text-xs">{x.source_ips.join(", ")}</td><td className="text-xs">{x.site || "—"}</td>
            <td className="num">{fmtNum(x.events_24h)}</td><td className="num">{fmtNum(x.events_total)}</td>
            <td>{x.last_event_at ? <Time v={x.last_event_at} /> : <span className="text-amber-300 text-xs">nothing received yet</span>}</td>
            <td>{x.enabled ? "yes" : "no"}</td>
            <td className="nowrap"><button className="btn" onClick={() => nav(`/search${qs({ q: `firewall:"${x.name}" | stats count by category, event_type, event_subtype | sort -count` })}`)}>Events</button>
              {admin && <><button className="btn ml-1" onClick={() => setEdit(x)}>Edit</button>
                <button className="btn btn-danger ml-1" onClick={() => confirm(`Remove log source ${x.name}? Its stored events stay.`) && del.mutate(x.id)}>Remove</button></>}</td>
          </tr>)}</tbody></table></TableWrap>}
      </Card>
      <div className="grid gap-4 xl:grid-cols-2 min-w-0">
        <Card title="Windows (NXLog Community Edition)">
          <p className="text-xs text-muted mb-2">Install NXLog on each domain controller / server (or on a Windows Event Collector), use this nxlog.conf section, then register the sender IP above as type
            <b> Windows</b>. Winlogbeat → Logstash JSON over syslog and Snare (MSWinEventLog) also work.</p>
          <pre className="text-2xs bg-panel2 p-3 rounded overflow-x-auto font-mono">{NXLOG}</pre>
          <p className="text-2xs text-muted mt-2">Recommended audit policy: Logon/Logoff, Account Logon (Kerberos, credential validation), Account Management (user & security group), and Security System Extension.</p>
        </Card>
        <Card title="CEF devices">
          <p className="text-xs text-muted">Point the device's syslog / SIEM output at this server on port 514 in CEF format, and register its IP as type <b>CEF</b>.
            Standard keys are mapped: src, dst, spt, dpt, proto, act, suser/duser, dhost, request, in/out, msg, cat, rt. Records with a URL become web events, port 53
            becomes DNS, allow/deny records become traffic, other records with addresses become security events.</p>
        </Card>
      </div>
      {edit && <SourceForm s={edit} onClose={() => { setEdit(null); qc.invalidateQueries({ queryKey: ["log-sources"] }); }} />}
    </div>
  );
}

function SourceForm({ s, onClose }: { s: any; onClose: () => void }) {
  const [f, setF] = useState({ name: s.name, kind: s.kind, ips: (s.source_ips || []).join(", "), site: s.site || "", enabled: s.enabled, description: s.description || "" });
  const m = useMutation({ mutationFn: () => api(s.id ? `/log-sources/${s.id}` : "/log-sources", { method: s.id ? "PUT" : "POST",
    body: { name: f.name, kind: f.kind, source_ips: f.ips.split(/[,\s]+/).filter(Boolean), site: f.site, enabled: f.enabled, description: f.description } }), onSuccess: onClose });
  return (
    <Modal title={s.id ? `Log source: ${s.name}` : "Add log source"} onClose={onClose}>
      <div className="grid gap-2 sm:grid-cols-2">
        <div><label className="label">Name (shown as the device name)</label><input className="input w-full" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="DC01" /></div>
        <div><label className="label">Type</label><select className="input w-full" value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })}>
          {Object.entries(KIND).map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></div>
        <div className="sm:col-span-2"><label className="label">Sender IP address(es) — the address syslog arrives from</label>
          <input className="input w-full font-mono" value={f.ips} onChange={(e) => setF({ ...f, ips: e.target.value })} placeholder="10.0.5.10, 10.0.5.11" /></div>
        <div><label className="label">Site</label><input className="input w-full" value={f.site} onChange={(e) => setF({ ...f, site: e.target.value })} /></div>
        <label className="text-sm flex items-center gap-2 self-end"><input type="checkbox" checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked })} />Accept logs</label>
        <div className="sm:col-span-2"><label className="label">Description</label><input className="input w-full" value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></div>
      </div>
      {m.error && <div role="alert" className="text-sm text-red-400 mt-2">{(m.error as Error).message}</div>}
      <p className="text-2xs text-muted mt-2">Changes apply to the syslog receiver within a minute.</p>
      <button className="btn btn-primary mt-3" disabled={!f.name || !f.ips.trim() || m.isPending} onClick={() => m.mutate()}>Save</button>
    </Modal>
  );
}
