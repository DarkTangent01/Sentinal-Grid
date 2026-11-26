import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, qs } from "../lib/api";
import { useMe } from "../lib/context";
import { fmtNum } from "../lib/format";
import { Card, Empty, Kpi, Loading, Modal, TableWrap, Time } from "../components/ui";

const KIND: Record<string, string> = { windows: "Windows Security events", cef: "CEF (any vendor)",
  netdev: "Network device (Cisco IOS / IOS-XE / NX-OS / C9800, Ruckus ICX, Juniper, Aruba)", syslog: "Plain syslog (Cisco, Juniper, Aruba, Linux auth, CEF, LEEF auto-detected)",
  zeek: "Zeek sensor (JSON logs)", json: "JSON (ECS / flat keys / AWS CloudTrail)", leef: "LEEF 1.0 / 2.0", linux: "Linux (sshd, sudo, su, PAM, account changes)" };

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
  const [tok, setTok] = useState<any>(null);
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
              {admin && <><button className="btn ml-1" onClick={() => setTok(x)}>{x.http_ingest ? "HTTP token" : "HTTP ingest…"}</button>
                <button className="btn ml-1" onClick={() => setEdit(x)}>Edit</button>
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
      {tok && <TokenModal s={tok} onClose={() => { setTok(null); qc.invalidateQueries({ queryKey: ["log-sources"] }); qc.invalidateQueries({ queryKey: ["ingest-health"] }); }} />}
      <IngestHealth />
      {admin && <ParseTest />}
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
        <label className="block min-w-0"><span className="label">Name (shown as the device name)</span><input className="input w-full" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="DC01" /></label>
        <label className="block min-w-0"><span className="label">Type</span><select className="input w-full" value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })}>
          {Object.entries(KIND).map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></label>
        <label className="sm:col-span-2 block min-w-0"><span className="label">Sender IP address(es) — the address syslog arrives from</span>
          <input className="input w-full font-mono" value={f.ips} onChange={(e) => setF({ ...f, ips: e.target.value })} placeholder="10.0.5.10, 10.0.5.11" /></label>
        <label className="block min-w-0"><span className="label">Site</span><input className="input w-full" value={f.site} onChange={(e) => setF({ ...f, site: e.target.value })} /></label>
        <label className="text-sm flex items-center gap-2 self-end"><input type="checkbox" checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked })} />Accept logs</label>
        <label className="sm:col-span-2 block min-w-0"><span className="label">Description</span><input className="input w-full" value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></label>
      </div>
      {m.error && <div role="alert" className="text-sm text-red-400 mt-2">{(m.error as Error).message}</div>}
      <p className="text-2xs text-muted mt-2">Changes apply to the syslog receiver within a minute.</p>
      <button className="btn btn-primary mt-3" disabled={!f.name || !f.ips.trim() || m.isPending} onClick={() => m.mutate()}>Save</button>
    </Modal>
  );
}

const STATUS: Record<string, string> = { ok: "text-emerald-300", degraded: "text-amber-300", silent: "text-red-300",
  never: "text-slate-300", disabled: "text-slate-300" };

/** Per-source ingestion health and an account of everything that did not become an event (with the reason and a
 *  sample line): nothing is dropped without a record of who sent it and why. */
function IngestHealth() {
  const q = useQuery({ queryKey: ["ingest-health"], queryFn: () => api<any>("/log-sources/health"), refetchInterval: 60_000 });
  const d = q.data;
  return <Card title="Ingestion health (last 24 hours)" bodyClass="p-0"><Loading q={q} />
    {d && <>
      <div className="kpi-grid p-4">
        <Kpi label="Stored events" value={fmtNum(d.stored_24h)} />
        {Object.entries(d.not_stored_24h as Record<string, number>).map(([k, v]) => <Kpi key={k} label={k.replace("_", " ")} value={fmtNum(v)} sub={d.reasons[k]}
          tone={k === "buffer_full" || k === "parse_error" ? "bad" : k === "duplicate" ? undefined : "warn"} />)}
        {!Object.keys(d.not_stored_24h).length && <Kpi label="Not stored" value={0} sub="every received line became an event" tone="ok" />}
      </div>
      <TableWrap><table className="tbl"><thead><tr><th>Source</th><th>Type</th><th>Status</th><th className="num">1 h</th><th className="num">24 h</th><th className="num">Lag p50 / p95</th>
        <th className="num">Duplicates</th><th className="num">Parse errors</th><th className="num">Bad time</th><th className="num">Dropped</th><th>Last event</th></tr></thead>
        <tbody>{d.sources.map((x: any) => <tr key={`${x.firewall_id}`}><td>{x.name}{x.http_ingest && <span className="pill text-sky-300 ml-1.5">HTTP</span>}</td>
          <td className="text-xs">{x.kind}</td><td><span className={`pill ${STATUS[x.status]}`}>{x.status}</span></td><td className="num">{fmtNum(x.events_1h)}</td><td className="num">{fmtNum(x.events_24h)}</td>
          <td className="num">{x.lag_p50_s == null ? "—" : `${x.lag_p50_s} / ${x.lag_p95_s} s`}</td><td className="num">{fmtNum(x.duplicates_24h)}</td>
          <td className={`num ${x.parse_errors_24h ? "text-amber-300" : ""}`}>{fmtNum(x.parse_errors_24h)}</td><td className={`num ${x.bad_timestamps_24h ? "text-amber-300" : ""}`}>{fmtNum(x.bad_timestamps_24h)}</td>
          <td className={`num ${x.dropped_24h ? "text-red-400 font-semibold" : ""}`}>{fmtNum(x.dropped_24h)}</td><td>{x.last_event_at ? <Time v={x.last_event_at} /> : "—"}</td></tr>)}</tbody></table></TableWrap>
      {d.unknown_senders.length > 0 && <div className="p-4"><div className="label">Senders that are not registered (their lines are not stored)</div>
        <TableWrap><table className="tbl"><thead><tr><th>Sender</th><th>Claims to be</th><th>Reason</th><th className="num">Lines</th><th>Last</th><th>Sample</th></tr></thead>
          <tbody>{d.unknown_senders.map((u: any) => <tr key={`${u.sender}${u.reason}${u.claims_to_be}`}><td className="font-mono text-xs">{u.sender || "—"}</td><td className="text-xs">{u.claims_to_be || "—"}</td>
            <td className="text-xs">{u.reason.replace("_", " ")}</td><td className="num">{fmtNum(u.count)}</td><td><Time v={u.last_seen} /></td><td className="font-mono text-2xs cell-wrap">{u.sample}</td></tr>)}</tbody></table></TableWrap></div>}
      {d.samples.length > 0 && <div className="p-4"><div className="label">Sample lines that were not parsed or had a bad timestamp</div>
        <ul className="space-y-1">{d.samples.map((x: any, i: number) => <li key={i} className="text-xs"><b>{x.source || x.sender}</b> · {x.reason.replace("_", " ")} ×{x.count}
          <pre className="font-mono text-2xs bg-panel2 border border-line rounded p-1.5 mt-0.5 overflow-x-auto">{x.sample}</pre></li>)}</ul></div>}
    </>}
  </Card>;
}

function TokenModal({ s, onClose }: { s: any; onClose: () => void }) {
  const [tok, setTok] = useState<any>(null);
  const create = useMutation({ mutationFn: () => api<any>(`/log-sources/${s.id}/token`, { method: "POST" }), onSuccess: setTok });
  const revoke = useMutation({ mutationFn: () => api(`/log-sources/${s.id}/token`, { method: "DELETE" }), onSuccess: onClose });
  const url = `${location.origin}/api/ingest/${s.id}`;
  return <Modal title={`HTTP ingestion: ${s.name}`} onClose={onClose}>
    <div className="space-y-3 text-sm">
      <p>Send records with <code>POST {url}</code> and <code>Authorization: Bearer &lt;token&gt;</code>. The body is newline-separated records (JSON lines, CEF, LEEF, syslog
        lines, Zeek JSON) or a JSON array, at most 2,000 records and 1 MB. A 200 response means the batch is stored; on any other status, retry the same batch (re-sent records
        are not stored twice).</p>
      {tok ? <><div className="label">Token (shown once: copy it now)</div><pre className="font-mono text-xs bg-panel2 border border-line rounded p-2 overflow-x-auto">{tok.token}</pre>
        <pre className="font-mono text-2xs bg-panel2 border border-line rounded p-2 overflow-x-auto">{`curl -sS -X POST ${url} \\
  -H "Authorization: Bearer ${tok.token}" \\
  --data-binary @events.jsonl`}</pre></>
        : <p className="text-muted">{s.http_ingest ? "A token exists. Creating a new one replaces it (the old one stops working)." : "HTTP ingestion is off for this source until a token is created."}</p>}
      {(create.error || revoke.error) && <div role="alert" className="text-red-400">{String(((create.error || revoke.error) as Error).message)}</div>}
      <div className="flex justify-end gap-2">{s.http_ingest && !tok && <button type="button" className="btn btn-danger" onClick={() => revoke.mutate()}>Revoke token</button>}
        {!tok && <button type="button" className="btn btn-primary" onClick={() => create.mutate()}>{s.http_ingest ? "Replace token" : "Create token"}</button>}
        <button type="button" className="btn" onClick={onClose}>Close</button></div>
    </div>
  </Modal>;
}

/** Paste a line and see how it is parsed and normalized (nothing is stored). */
function ParseTest() {
  const [kind, setKind] = useState("syslog");
  const [line, setLine] = useState("");
  const m = useMutation({ mutationFn: () => api<any>("/log-sources/parse-test", { method: "POST", body: { kind, line } }) });
  return <Card title="Parser test">
    <div className="grid gap-2 sm:grid-cols-[14rem_1fr_auto] items-end">
      <label className="block min-w-0"><span className="label">Source type</span><select className="input w-full" value={kind} onChange={(e) => setKind(e.target.value)}>
        {Object.entries(KIND).map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></label>
      <label className="block min-w-0"><span className="label">Log line</span><input className="input w-full font-mono" value={line} onChange={(e) => setLine(e.target.value)} /></label>
      <button type="button" className="btn btn-primary" disabled={!line.trim() || m.isPending} onClick={() => m.mutate()}>Parse</button>
    </div>
    {m.error && <div role="alert" className="text-sm text-red-400 mt-2">{String((m.error as Error).message)}</div>}
    {m.data && <div className="grid gap-3 lg:grid-cols-2 mt-3">
      <div><div className="label">Normalized ({m.data.parser_version}){m.data.fell_back_to_plain && <span className="text-amber-300"> · not recognised: stored as plain syslog</span>}</div>
        <pre className="text-xs bg-panel2 border border-line rounded p-2 overflow-x-auto max-h-96">{JSON.stringify(m.data.normalized, null, 2)}</pre></div>
      <div><div className="label">Common schema view (ECS / OCSF)</div><pre className="text-xs bg-panel2 border border-line rounded p-2 overflow-x-auto max-h-96">{JSON.stringify(m.data.ecs, null, 2)}</pre></div>
    </div>}
  </Card>;
}
