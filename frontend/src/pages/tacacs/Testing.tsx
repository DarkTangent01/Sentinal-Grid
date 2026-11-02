import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { Card, Empty, Loading, TableWrap, Time } from "../../components/ui";
import { Denied, ErrorText, Field, Status, useCan, useSave, useTacMeta } from "./common";
import { Simulator } from "./Policies";

export function Testing() {
  const can = useCan();
  const meta = useTacMeta();
  const servers = useQuery({ queryKey: ["tac-servers"], queryFn: () => api<any>("/tacacs/servers") });
  const clients = useQuery({ queryKey: ["tac-clients-all"], queryFn: () => api<any>("/tacacs/clients", { params: { limit: 1000 } }) });
  const sources = useQuery({ queryKey: ["tac-sources"], queryFn: () => api<any>("/tacacs/identity-sources") });
  const hist = useQuery({ queryKey: ["tac-tests"], queryFn: () => api<any>("/tacacs/tests") });
  const [sid, setSid] = useState("");
  const [cid, setCid] = useState("");
  const [src, setSrc] = useState("");
  const [user, setUser] = useState("");
  const [pw, setPw] = useState("");
  const run = useSave(({ kind, body }: any) => api<any>(`/tacacs/tests/${kind}`, { method: "POST", body }), ["tac-tests", "tac-clients", "tac-sources"], () => setPw(""));
  const server = Number(sid || servers.data?.items[0]?.id);
  const r: any = run.data;
  if (!can("operator")) return <div className="space-y-4"><Denied role="operator" what="run AAA tests" /><Simulator /></div>;
  return <div className="space-y-4">
    {!meta.data?.tester_configured && <div role="alert" className="card p-3 text-sm text-amber-300">Authentication and accounting tests need the tester device: set the SIEM worker's source
      address under Settings, then deploy a configuration version (it adds the sentinel_grid_tester device, which can authenticate but never opens a shell).</div>}
    <Card title="Run a test">
      <div className="grid gap-3 lg:grid-cols-2">
        <div className="space-y-2">
          <Field label="Server"><select className="input w-full" value={sid} onChange={(e) => setSid(e.target.value)}>{(servers.data?.items || []).map((s: any) => <option key={s.id} value={s.id}>{s.name} ({s.kind})</option>)}</select></Field>
          <div className="flex flex-wrap gap-2">
            <button className="btn" disabled={!server || run.isPending} onClick={() => run.mutate({ kind: "tcp", body: { server_id: server } })}>TCP/49 connectivity</button>
            <button className="btn" disabled={!server || run.isPending} onClick={() => run.mutate({ kind: "accounting", body: { server_id: server } })}>Accounting round trip</button>
            <button className="btn" disabled={!server || run.isPending} onClick={() => run.mutate({ kind: "validate", body: { server_id: server } })}>Validate latest version</button>
          </div>
          <div className="grid gap-2 sm:grid-cols-2">
            <Field label="Test user"><input className="input w-full" autoComplete="off" value={user} onChange={(e) => setUser(e.target.value)} /></Field>
            <Field label="Password (used once, never stored)"><input type="password" autoComplete="new-password" className="input w-full" value={pw} onChange={(e) => setPw(e.target.value)} /></Field>
          </div>
          <button className="btn btn-primary" disabled={!server || !user || !pw || run.isPending} onClick={() => run.mutate({ kind: "auth", body: { server_id: server, username: user, password: pw } })}>
            Test authentication</button>
        </div>
        <div className="space-y-2">
          <Field label="Identity source"><select className="input w-full" value={src} onChange={(e) => setSrc(e.target.value)}><option value="">—</option>
            {(sources.data?.items || []).filter((x: any) => ["ldap", "ad"].includes(x.kind)).map((x: any) => <option key={x.id} value={x.id}>{x.name}</option>)}</select></Field>
          <button className="btn" disabled={!src || run.isPending} onClick={() => run.mutate({ kind: "identity", body: { source_id: Number(src) } })}>LDAP / AD bind test</button>
          <Field label="Device client"><select className="input w-full" value={cid} onChange={(e) => setCid(e.target.value)}><option value="">—</option>
            {(clients.data?.items || []).map((c: any) => <option key={c.id} value={c.id}>{c.name}</option>)}</select></Field>
          <button className="btn" disabled={!cid || run.isPending} onClick={() => run.mutate({ kind: "failover", body: { client_id: Number(cid) } })}>Primary / secondary reachability</button>
          <p className="text-2xs text-muted">A device's own shared secret is verified by its real logins: see Last authentication on the clients page, or protocol errors in alerts.</p>
        </div>
      </div>
      {run.isPending && <p className="text-sm text-muted mt-2 animate-pulse">Running…</p>}
      <ErrorText e={run.error} />
      {r && (r.queued_job ? <p className="text-sm mt-2">Validation job #{r.queued_job} queued ({r.status}). {r.note}</p> : <TestResult r={r} />)}
    </Card>
    <Simulator />
    <Card title="Test history" bodyClass="p-0">
      <Loading q={hist} />
      {hist.data && (!hist.data.items.length ? <Empty text="No tests run yet." /> :
        <TableWrap maxH="max-h-96"><table className="tbl"><thead><tr><th>Started</th><th>Finished</th><th>Test</th><th>Target</th><th>Result</th><th>Category</th><th>By</th><th className="w-full">Detail</th></tr></thead>
          <tbody>{hist.data.items.map((t: any) => <tr key={t.id}><td><Time v={t.started_at} /></td><td><Time v={t.finished_at} /></td><td>{t.kind}</td><td>{t.target}</td><td><Status s={t.status} /></td>
            <td className="text-xs">{t.category}</td><td>{t.requested_by}</td><td className="text-xs">{t.detail}{t.help && <div className="text-muted">{t.help}</div>}</td></tr>)}</tbody></table></TableWrap>)}
    </Card>
  </div>;
}

function TestResult({ r }: { r: any }) {
  return <div className="mt-3 space-y-1 text-sm">
    <div><Status s={r.status} /> {r.kind} · {r.target}{r.category && <span className="text-muted"> · {r.category}</span>}</div>
    {r.steps.map((s: any, i: number) => <div key={i} className="text-xs"><Status s={s.ok ? "passed" : "failed"} /> {s.name}: {s.detail}
      <span className="text-muted"> ({new Date(s.started_at).toLocaleTimeString()}–{new Date(s.finished_at).toLocaleTimeString()})</span>
      {s.help && <div className="text-muted ml-4">{s.help}</div>}</div>)}
  </div>;
}
