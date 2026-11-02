import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { useMe } from "../../lib/context";
import { Card, Empty, Loading, Modal, TableWrap, Time } from "../../components/ui";
import { Denied, ErrorText, Field, Status, useCan, useSave } from "./common";

function Diff({ text }: { text: string }) {
  if (!text) return <Empty text="No differences." />;
  return <pre className="input w-full font-mono text-xs whitespace-pre overflow-auto max-h-[28rem]">{text.split("\n").map((l, i) =>
    <div key={i} className={l.startsWith("+") && !l.startsWith("+++") ? "text-emerald-300" : l.startsWith("-") && !l.startsWith("---") ? "text-red-300" : l.startsWith("@@") ? "text-sky-300" : ""}>{l || " "}</div>)}</pre>;
}

export function Studio() {
  const can = useCan();
  const me = useMe();
  const [msg, setMsg] = useState("");
  const [show, setShow] = useState<"diff" | "full">("diff");
  const [cmp, setCmp] = useState<{ a: string; b: string }>({ a: "", b: "" });
  const [deploy, setDeploy] = useState<any>(null);
  const [view, setView] = useState<any>(null);
  const preview = useQuery({ queryKey: ["tac-preview"], enabled: can("policy_admin"), queryFn: () => api<any>("/tacacs/config/preview") });
  const versions = useQuery({ queryKey: ["tac-versions"], queryFn: () => api<any>("/tacacs/config/versions") });
  const jobs = useQuery({ queryKey: ["tac-jobs"], queryFn: () => api<any>("/tacacs/deployments"),
    // fast only while a job can still change state; idle history does not need a 5 s poll
    refetchInterval: (q) => q.state.data?.items?.some((j: any) => ["pending_approval", "queued", "running"].includes(j.status)) ? 3000 : 30_000 });
  const diff = useQuery({ queryKey: ["tac-diff", cmp.a, cmp.b], enabled: !!cmp.a && !!cmp.b && can("policy_admin"), queryFn: () => api<any>("/tacacs/config/diff", { params: cmp }) });
  const commit = useSave(() => api<any>("/tacacs/config/versions", { method: "POST", body: { message: msg } }), ["tac-versions", "tac-preview"], () => setMsg(""));
  const decide = useSave(({ id, decision, hash }: any) => api(`/tacacs/deployments/${id}/decision`, { method: "POST", body: { decision, approval_hash: hash, comment: "" } }), ["tac-jobs"]);
  const cancel = useSave((id: number) => api(`/tacacs/deployments/${id}/cancel`, { method: "POST" }), ["tac-jobs"]);
  const p = preview.data;
  return <div className="space-y-4">
    {!can("policy_admin") ? <Denied role="policy_admin" what="preview and commit configuration versions" /> : <Card title="Draft configuration (tac_plus-ng)" right={<>
      <button className={`btn ${show === "diff" ? "btn-primary" : ""}`} onClick={() => setShow("diff")}>Changes vs. deployed</button>
      <button className={`btn ${show === "full" ? "btn-primary" : ""}`} onClick={() => setShow("full")}>Full preview</button></>}>
      <Loading q={preview} />
      {p && <>
        <div className="text-xs mb-2">{p.validation.ok ? <span className="text-emerald-300">valid</span> : <span className="text-red-300">invalid</span>} · base: {p.base_version ? `v${p.base_version}` : "nothing deployed"}
          {p.validation.errors.map((e: string) => <div key={e} className="text-red-300">✕ {e}</div>)}
          {p.validation.warnings.map((w: string) => <div key={w} className="text-amber-300">! {w}</div>)}</div>
        {show === "diff" ? <Diff text={p.diff} /> : <pre className="input w-full font-mono text-xs whitespace-pre overflow-auto max-h-[28rem]">{p.content}</pre>}
        <p className="text-2xs text-muted mt-1">Secrets are shown as ***. The deploy agent parses every version with tac_plus-ng -P before activating it and keeps the previous file as a backup.</p>
        <div className="flex flex-wrap gap-2 mt-2 items-end"><div className="flex-1 min-w-[16rem]"><Field label="Version message"><input className="input w-full" value={msg} onChange={(e) => setMsg(e.target.value)} /></Field></div>
          <button className="btn btn-primary" disabled={msg.length < 3 || !p.validation.ok || commit.isPending} onClick={() => commit.mutate(null)}>Commit version</button></div>
        <ErrorText e={commit.error} />
      </>}
    </Card>}
    <Card title={`Versions${versions.data ? ` (${versions.data.items.length})` : ""}`} bodyClass="p-0" right={can("policy_admin") && <>
      <select aria-label="Compare from" className="input py-1" value={cmp.a} onChange={(e) => setCmp({ ...cmp, a: e.target.value })}><option value="">compare…</option>
        {(versions.data?.items || []).map((v: any) => <option key={v.id} value={v.id}>v{v.number}</option>)}</select>
      <select aria-label="Compare to" className="input py-1" value={cmp.b} onChange={(e) => setCmp({ ...cmp, b: e.target.value })}><option value="">…with</option>
        {(versions.data?.items || []).map((v: any) => <option key={v.id} value={v.id}>v{v.number}</option>)}</select></>}>
      <Loading q={versions} />
      {versions.data && (!versions.data.items.length ? <Empty text="No versions committed yet." /> :
        <TableWrap><table className="tbl"><thead><tr><th>Version</th><th>Message</th><th>By</th><th>Created</th><th>Validation</th><th>SHA-256</th><th /></tr></thead>
          <tbody>{versions.data.items.map((v: any) => <tr key={v.id}><td className="font-medium">v{v.number}{v.deployed && <span className="pill bg-emerald-500/15 text-emerald-300 ml-1">deployed</span>}</td>
            <td className="text-xs">{v.message}</td><td>{v.created_by}</td><td><Time v={v.created_at} /></td><td className="text-xs">{v.validation.warnings?.length || 0} warning(s)</td>
            <td className="font-mono text-2xs">{v.sha256.slice(0, 16)}…</td>
            <td className="whitespace-nowrap">{can("policy_admin") && <><button className="btn" onClick={() => api(`/tacacs/config/versions/${v.id}`).then(setView)}>View</button>{" "}
              <button className="btn" onClick={() => setDeploy({ version: v, action: "validate" })}>Validate on server</button>{" "}
              <button className="btn btn-primary" onClick={() => setDeploy({ version: v, action: "deploy" })}>Request deployment</button></>}</td></tr>)}</tbody></table></TableWrap>)}
      {diff.data && <div className="p-3"><Diff text={diff.data.diff} /></div>}
    </Card>
    <Card title="Deployments and approvals" bodyClass="p-0">
      <Loading q={jobs} />
      {jobs.data && (!jobs.data.items.length ? <Empty text="No deployment jobs." /> :
        <TableWrap><table className="tbl"><thead><tr><th>Job</th><th>Version</th><th>Action</th><th>Status</th><th>Requested by</th><th>Approved by</th><th>Created</th><th>Finished</th>
          <th className="w-full">Result</th><th /></tr></thead>
          <tbody>{jobs.data.items.map((j: any) => <tr key={j.id}><td>#{j.id}</td><td>v{j.version}</td><td>{j.action}</td><td><Status s={j.status} /></td><td>{j.requested_by}</td>
            <td>{j.approved_by || "—"}</td><td><Time v={j.created_at} /></td><td><Time v={j.finished_at} /></td>
            <td className="text-xs">{j.result?.reason || j.result?.status || ""}{j.result?.output && <details><summary className="cursor-pointer text-muted">parser output</summary>
              <pre className="font-mono text-2xs whitespace-pre-wrap">{j.result.output}</pre></details>}{j.result?.backup && <div className="text-muted">backup {j.result.backup}</div>}</td>
            <td className="whitespace-nowrap">{j.status === "pending_approval" && can("approver") && j.requested_by !== me.username && <>
              <button className="btn btn-primary" onClick={() => confirm(`Approve deploying v${j.version}? The agent validates, backs up, activates and health-checks; it rolls back automatically if TCP/49 does not come back.`)
                && decide.mutate({ id: j.id, decision: "approve", hash: j.approval_hash })}>Approve</button>{" "}
              <button className="btn" onClick={() => decide.mutate({ id: j.id, decision: "reject", hash: j.approval_hash })}>Reject</button></>}
              {j.status === "pending_approval" && j.requested_by === me.username && <span className="text-2xs text-muted">needs another approver</span>}
              {["pending_approval", "queued"].includes(j.status) && can("policy_admin") && <> <button className="btn" onClick={() => cancel.mutate(j.id)}>Cancel</button></>}</td></tr>)}</tbody></table></TableWrap>)}
      <ErrorText e={decide.error || cancel.error} />
      <p className="text-2xs text-muted p-2">Recovery: every deployment keeps the previous configuration in the agent's backups; to roll back, request deployment of the previous version (or
        follow docs/TACACS.md → Recovery if the SIEM cannot reach the server). Devices keep their local emergency access throughout.</p>
    </Card>
    {deploy && <DeployDialog x={deploy} onClose={() => setDeploy(null)} />}
    {view && <Modal wide title={`Version v${view.number}`} onClose={() => setView(null)}><pre className="input w-full font-mono text-xs whitespace-pre overflow-auto max-h-[32rem]">{view.content}</pre></Modal>}
  </div>;
}

function DeployDialog({ x, onClose }: { x: any; onClose: () => void }) {
  const servers = useQuery({ queryKey: ["tac-servers"], queryFn: () => api<any>("/tacacs/servers") });
  const managed = (servers.data?.items || []).filter((s: any) => s.kind === "managed");
  const [sid, setSid] = useState("");
  const [comment, setComment] = useState("");
  const run = useSave(() => api(`/tacacs/config/versions/${x.version.id}/deploy`, { method: "POST", body: { server_id: Number(sid || managed[0]?.id), action: x.action, comment } }),
    ["tac-jobs"], onClose);
  return <Modal title={`${x.action === "deploy" ? "Request deployment" : "Validate"} · v${x.version.number}`} onClose={onClose}>
    {!managed.length ? <Empty text="No managed server registered." /> : <>
      <Field label="Server"><select className="input w-full" value={sid} onChange={(e) => setSid(e.target.value)}>{managed.map((s: any) => <option key={s.id} value={s.id}>{s.name} ({s.environment})</option>)}</select></Field>
      <div className="mt-2"><Field label="Change reference / comment"><input className="input w-full" value={comment} onChange={(e) => setComment(e.target.value)} placeholder="CHG-1234" /></Field></div>
      <p className="text-2xs text-muted mt-2">{x.action === "deploy" ? "A second person with the approver role must approve. The approval is bound to this version and to the server's current configuration; if either changes, the request is cancelled."
        : "The agent parses the version with tac_plus-ng -P without activating it."}</p>
      <ErrorText e={run.error} />
      <button className="btn btn-primary mt-3" disabled={run.isPending} onClick={() => run.mutate(null)}>{x.action === "deploy" ? "Request deployment" : "Validate"}</button></>}
  </Modal>;
}
