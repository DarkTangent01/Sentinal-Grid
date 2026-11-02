import { Fragment, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { fmtNum } from "../../lib/format";
import { Card, Drawer, Empty, Kpi, Loading, TableWrap, Time, Trunc, rowProps } from "../../components/ui";
import { Action, Confirm, ErrorBox, FieldDiff, Note, Pager, SevBadge, SideBySide, Status, can, useAct, useMeta } from "./common";

const PLAN_STATUSES = ["validation_failed", "ready_for_review", "pending_approval", "approved", "rejected", "queued", "running", "succeeded", "failed",
  "rolled_back", "cancelled", "stale"];

export function Plans({ projectId, status, onOpen, onJob }: { projectId: number | null; status: string; onOpen: (id: number) => void; onJob: (id: number) => void }) {
  const [st, setSt] = useState(status);
  const [page, setPage] = useState(1);
  const q = useQuery({ queryKey: ["iac-plans", projectId, st, page], queryFn: () => api<any>("/iac/plans", { params: { project_id: projectId || undefined, status: st ? [st] : [], page, size: 25 } }),
    refetchInterval: 15_000, placeholderData: (p) => p });
  void onJob;
  return <Card title="Plans" bodyClass="p-0" right={<select aria-label="Plan status" className="input py-0.5 text-xs" value={st} onChange={(e) => { setSt(e.target.value); setPage(1); }}>
    <option value="">All statuses</option>{PLAN_STATUSES.map((s) => <option key={s} value={s}>{s.replace(/_/g, " ")}</option>)}</select>}>
    <Loading q={q} />
    {q.data?.items?.length ? <><TableWrap><table className="tbl"><thead><tr><th>#</th><th>Project</th><th>Env</th><th>Kind</th><th>Version</th><th>Status</th>
      <th className="num">+ / ~ / − / move</th><th>Worst finding</th><th>Created</th><th>By</th></tr></thead>
      <tbody>{q.data.items.map((p: any) => <tr key={p.id} {...rowProps(() => onOpen(p.id))}><td className="font-mono">{p.id}</td><td className="text-sm">{p.project}</td>
        <td className="text-xs">{p.environment}</td><td className="text-xs">{p.kind}</td><td className="font-mono text-xs">{p.version ? `v${p.version}` : "backup"}</td>
        <td><Status s={p.status} />{p.blocking && <span className="text-2xs text-red-300 ml-1">blocked</span>}{p.destructive && <span className="text-2xs text-amber-300 ml-1">destructive</span>}</td>
        <td className="num text-xs">{p.summary?.create ?? 0} / {p.summary?.update ?? 0} / {p.summary?.delete ?? 0} / {p.summary?.move ?? 0}</td>
        <td>{p.summary?.worst_finding && p.summary.worst_finding !== "info" ? <SevBadge s={p.summary.worst_finding} /> : <span className="text-muted text-xs">—</span>}</td>
        <td><Time v={p.created_at} /></td><td className="text-xs">{p.created_by}</td></tr>)}</tbody></table></TableWrap>
      <Pager page={page} size={25} total={q.data.total} onPage={setPage} /></> : !q.isLoading && <Empty text="No plans yet. Commit a valid version in the Studio, then generate a plan." />}
  </Card>;
}

export function PlanDrawer({ id, onClose, onJob }: { id: number; onClose: () => void; onJob: (id: number) => void }) {
  const meta = useMeta().data;
  const q = useQuery({ queryKey: ["iac-plan", id], queryFn: () => api<any>(`/iac/plans/${id}`), refetchInterval: (qq) => ["queued", "running"].includes(qq.state.data?.status) ? 3000 : false });
  const [dev, setDev] = useState<number | "all">("all");
  const [risk, setRisk] = useState("");
  const [open, setOpen] = useState<number | null>(null);
  const [modal, setModal] = useState<null | "approve" | "reject" | "deploy" | "dry">(null);
  const [comment, setComment] = useState("");
  const [ack, setAck] = useState(false);
  const [typed, setTyped] = useState("");
  const p = q.data;
  const submit = useAct(() => api(`/iac/plans/${id}/submit`, { method: "POST" }));
  const decide = useAct((d: string) => api(`/iac/plans/${id}/decision`, { method: "POST", body: { decision: d, comment, plan_hash: p.plan_hash, acknowledge_destructive: ack } }),
    () => { setModal(null); setComment(""); setAck(false); });
  const job = useAct((dry: boolean) => api<any>(`/iac/plans/${id}/jobs`, { method: "POST", body: { dry_run: dry, acknowledge_destructive: ack } }),
    (r) => { setModal(null); setAck(false); setTyped(""); onJob(r.id); });
  const refresh = useAct(() => api(`/iac/plans/${id}/refresh`, { method: "POST" }));
  const cancel = useAct(() => api(`/iac/plans/${id}/cancel`, { method: "POST" }));
  const changes = useMemo(() => (p?.changes || []).filter((c: any) => (dev === "all" || c.firewall_id === dev) && (!risk || c.risk === risk)), [p, dev, risk]);
  const err = submit.error || refresh.error || cancel.error;
  return <Drawer title={p ? `Plan #${p.id} · ${p.kind === "recovery" ? "recovery" : `v${p.version?.number}`} · ${p.environment}` : "Plan"} onClose={onClose}>
    <Loading q={q} />
    {p && <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2 text-sm"><Status s={p.status} /><span className="text-muted text-xs font-mono" title="plan hash: approvals and deployments are bound to it">#{p.plan_hash.slice(0, 16)}</span>
        <span className="text-muted text-xs">by {p.created_by} · <Time v={p.created_at} /></span></div>
      {p.stale_reason && <Note tone="warn">Stale: {p.stale_reason}. Generate a new plan; a stale plan can't be approved or deployed.</Note>}
      {p.errors?.length > 0 && <Note tone="bad">{p.errors.map((e: any, i: number) => <div key={i}>{e.firewall_name ? `${e.firewall_name}: ` : ""}{e.message}</div>)}</Note>}
      <div className="kpi-grid">
        <Kpi label="Create" value={fmtNum(p.summary.create)} /><Kpi label="Update" value={fmtNum(p.summary.update)} />
        <Kpi label="Delete" value={fmtNum(p.summary.delete)} tone={p.summary.delete ? "warn" : undefined} /><Kpi label="Move" value={fmtNum(p.summary.move)} />
        <Kpi label="Disruptive" value={fmtNum(p.summary.disruptive)} tone={p.summary.disruptive ? "warn" : undefined} />
        <Kpi label="Blocking findings" value={fmtNum(p.summary.blocking_findings)} tone={p.summary.blocking_findings ? "bad" : "ok"} />
      </div>
      <div className="flex flex-wrap gap-2">
        {p.status === "ready_for_review" && <button className="btn btn-primary" disabled={!can(meta, "editor") || submit.isPending} onClick={() => submit.mutate(undefined)}>Submit for approval</button>}
        {p.status === "pending_approval" && <><button className="btn btn-primary" disabled={!can(meta, "approver")} title={can(meta, "approver") ? "" : "approver role required"} onClick={() => setModal("approve")}>Approve</button>
          <button className="btn btn-danger" disabled={!can(meta, "approver")} onClick={() => setModal("reject")}>Reject</button></>}
        {["ready_for_review", "pending_approval", "approved"].includes(p.status) && <button className="btn" disabled={!can(meta, "editor")} onClick={() => setModal("dry")}>Dry run</button>}
        {p.status === "approved" && <button className="btn btn-primary" disabled={!can(meta, "deployer")} title={can(meta, "deployer") ? "" : "deployer role required"} onClick={() => setModal("deploy")}>Deploy…</button>}
        {["ready_for_review", "pending_approval", "approved"].includes(p.status) && <button className="btn" disabled={refresh.isPending} onClick={() => refresh.mutate(undefined)}>{refresh.isPending ? "Checking devices…" : "Check staleness"}</button>}
        {["ready_for_review", "pending_approval", "approved", "validation_failed"].includes(p.status) && <button className="btn" disabled={!can(meta, "editor")} onClick={() => cancel.mutate(undefined)}>Cancel plan</button>}
      </div>
      {!meta?.writes_effective && p.status === "approved" && <Note tone="warn">Deployment is disabled: {meta?.writes_reason}</Note>}
      <ErrorBox error={err} />
      {p.findings?.length > 0 && <Card title={`Validation findings (${p.findings.length})`} bodyClass="p-0">
        <TableWrap maxH="max-h-72"><table className="tbl"><thead><tr><th>Severity</th><th>Rule</th><th>Device</th><th>Resource</th><th className="w-full">Explanation · remediation</th><th>Blocks</th></tr></thead>
          <tbody>{p.findings.map((f: any, i: number) => <tr key={i}><td><SevBadge s={f.severity} /></td><td className="font-mono text-xs">{f.rule_id}</td><td className="text-xs">{f.firewall_name || "—"}</td>
            <td className="font-mono text-xs">{f.resource}</td><td className="text-xs">{f.explanation}<div className="text-muted">{f.remediation}</div>
              {f.evidence && Object.keys(f.evidence).length > 0 && <div className="text-2xs text-muted font-mono break-all">{JSON.stringify(f.evidence)}</div>}
              {f.exception && <div className="text-sky-300">exception by {f.exception.owner} until {f.exception.expires_at.slice(0, 10)}: {f.exception.justification}</div>}</td>
            <td className="text-xs">{f.blocks ? <span className="text-red-300 font-semibold">yes</span> : "no"}</td></tr>)}</tbody></table></TableWrap></Card>}
      <Card title={`Changes (${changes.length})`} bodyClass="p-0" right={<>
        <select aria-label="Device" className="input py-0.5 text-xs" value={dev} onChange={(e) => setDev(e.target.value === "all" ? "all" : Number(e.target.value))}>
          <option value="all">All devices</option>{p.targets.map((t: any) => <option key={t.id} value={t.id}>{t.name}</option>)}</select>
        <select aria-label="Risk" className="input py-0.5 text-xs" value={risk} onChange={(e) => setRisk(e.target.value)}><option value="">Any risk</option>
          {["critical", "high", "medium", "low", "info"].map((r) => <option key={r} value={r}>{r}</option>)}</select></>}>
        {changes.length ? <TableWrap maxH="max-h-[34rem]"><table className="tbl"><thead><tr><th>#</th><th>Device</th><th>Action</th><th>Resource</th><th>Risk</th><th className="w-full">Impact</th><th>Depends on</th></tr></thead>
          <tbody>{changes.map((c: any) => <Fragment key={c.id}>
            <tr {...rowProps(() => setOpen(open === c.id ? null : c.id))}><td className="font-mono text-xs">{c.seq + 1}</td><td className="text-xs whitespace-nowrap">{c.firewall_name}</td>
              <td><Action a={c.action} />{c.disruptive && <span className="text-2xs text-amber-300 ml-1" title="may interrupt traffic">⚠</span>}</td>
              <td className="font-mono text-xs whitespace-nowrap">{c.type}{c.key ? `:${c.key}` : ""}</td><td><SevBadge s={c.risk} /></td>
              <td className="text-xs"><Trunc text={c.impact} max="max-w-[26rem]" /></td><td className="font-mono text-2xs">{(c.depends_on || []).join(", ") || "—"}</td></tr>
            {open === c.id && <tr><td colSpan={7} className="bg-white/5">
              <div className="space-y-2 p-1"><FieldDiff fields={c.fields} /><SideBySide left={c.current} right={c.desired} leftLabel="current (device)" rightLabel="desired" />
                <div className="text-2xs text-muted">Rule {c.rule_id}</div></div></td></tr>}</Fragment>)}</tbody></table></TableWrap>
          : <Empty text={p.summary.no_op_devices?.length ? `No changes: ${p.summary.no_op_devices.join(", ")} already match the desired state.` : "No changes."} />}
      </Card>
      <Card title="Approvals and jobs"><ul className="text-xs space-y-1">
        {p.approvals.map((a: any, i: number) => <li key={i}><b className={a.decision === "approve" ? "text-emerald-300" : "text-red-300"}>{a.decision}</b> by {a.username} · <Time v={a.at} />
          {a.acknowledged_destructive && " · acknowledged destructive changes"}{a.comment && ` · “${a.comment}”`} <span className="font-mono text-muted">#{a.plan_hash.slice(0, 12)}</span></li>)}
        {p.jobs.map((j: any) => <li key={j.id}><button className="hover:underline" onClick={() => onJob(j.id)}>{j.kind} job #{j.id}</button> <Status s={j.status} /> by {j.requested_by} · <Time v={j.created_at} /></li>)}
        {!p.approvals.length && !p.jobs.length && <li className="text-muted">none yet</li>}</ul></Card>
    </div>}
    {modal === "approve" && p && <Confirm title={`Approve plan #${p.id}`} confirmLabel="Approve" busy={decide.isPending} disabled={p.destructive && !ack}
      onClose={() => setModal(null)} onConfirm={() => decide.mutate("approve")}>
      <p className="text-xs text-muted">Your approval is bound to plan hash <span className="font-mono">{p.plan_hash.slice(0, 16)}</span>, version and targets. Any change to them invalidates it.
        {p.environment === "production" && " Production: you cannot approve a plan or version you authored."}</p>
      {p.destructive && <label className="flex gap-2 items-start text-sm text-amber-200"><input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
        I reviewed the {p.summary.delete} deletion(s) and {p.summary.disruptive} potentially disruptive change(s).</label>}
      <textarea aria-label="Comment" className="input w-full h-16" placeholder="Comment (change ticket, conditions)…" value={comment} onChange={(e) => setComment(e.target.value)} />
      <ErrorBox error={decide.error} /></Confirm>}
    {modal === "reject" && p && <Confirm title={`Reject plan #${p.id}`} confirmLabel="Reject" danger busy={decide.isPending} disabled={!comment.trim()} onClose={() => setModal(null)} onConfirm={() => decide.mutate("reject")}>
      <textarea aria-label="Reason" className="input w-full h-20" placeholder="Reason (required)…" value={comment} onChange={(e) => setComment(e.target.value)} />
      <ErrorBox error={decide.error} /></Confirm>}
    {modal === "dry" && p && <Confirm title="Dry run" confirmLabel="Start dry run" busy={job.isPending} onClose={() => setModal(null)} onConfirm={() => job.mutate(true)}>
      <p className="text-sm">Re-reads every target, checks the plan is still current and shows the exact API requests each change would send. Nothing is written to any device.</p>
      <ErrorBox error={job.error} /></Confirm>}
    {modal === "deploy" && p && <Confirm title={`Deploy plan #${p.id} to ${p.targets.length} device(s)`} confirmLabel="Queue deployment" danger busy={job.isPending}
      disabled={(p.destructive && !ack) || (p.environment === "production" && typed !== "deploy")} onClose={() => setModal(null)} onConfirm={() => job.mutate(false)}>
      <p className="text-sm">The worker takes a lock on each device, re-checks the live configuration against the plan, captures a backup, applies {p.summary.create + p.summary.update + p.summary.delete + p.summary.move} change(s)
        in order, then verifies the result. Failures stop the device; nothing is rolled back automatically. Devices are changed one after another, not as one transaction.</p>
      <ul className="text-xs">{p.targets.map((t: any) => <li key={t.id}>• {t.name}</li>)}</ul>
      {p.destructive && <label className="flex gap-2 items-start text-sm text-amber-200"><input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
        I understand this deletes or disrupts configuration.</label>}
      {p.environment === "production" && <label className="text-xs block">Type <b>deploy</b> to confirm a production change
        <input aria-label="Type deploy" className="input w-full mt-1" value={typed} onChange={(e) => setTyped(e.target.value)} /></label>}
      <ErrorBox error={job.error} /></Confirm>}
  </Drawer>;
}

export function Jobs({ projectId, onOpen }: { projectId: number | null; onOpen: (id: number) => void }) {
  const [st, setSt] = useState("");
  const [page, setPage] = useState(1);
  const q = useQuery({ queryKey: ["iac-jobs", projectId, st, page], queryFn: () => api<any>("/iac/jobs", { params: { project_id: projectId || undefined, status: st ? [st] : [], page, size: 25 } }),
    refetchInterval: (qq) => qq.state.data?.items?.some((j: any) => ["queued", "running"].includes(j.status)) ? 2500 : 15_000, placeholderData: (p) => p });
  return <Card title="Deployments, dry runs and drift checks" bodyClass="p-0" right={<select aria-label="Job status" className="input py-0.5 text-xs" value={st} onChange={(e) => { setSt(e.target.value); setPage(1); }}>
    <option value="">All</option>{["queued", "running", "succeeded", "failed", "cancelled"].map((s) => <option key={s} value={s}>{s}</option>)}</select>}>
    <Loading q={q} />
    {q.data?.items?.length ? <><TableWrap><table className="tbl"><thead><tr><th>#</th><th>Kind</th><th>Plan</th><th>Status</th><th>Progress</th><th className="w-full">Current operation / error</th><th>Requested</th><th>By</th></tr></thead>
      <tbody>{q.data.items.map((j: any) => <tr key={j.id} {...rowProps(() => onOpen(j.id))}><td className="font-mono">{j.id}</td><td className="text-xs">{j.kind.replace("_", " ")}</td>
        <td className="font-mono text-xs">{j.plan_id ?? "—"}</td><td><Status s={j.status} />{j.cancel_requested && j.status === "running" && <span className="text-2xs text-amber-300 ml-1">cancelling</span>}</td>
        <td className="text-xs whitespace-nowrap">{j.progress?.done ?? 0}/{j.progress?.devices ?? "?"}</td>
        <td className="text-xs"><Trunc text={j.error || j.current_operation} max="max-w-[28rem]" /></td><td><Time v={j.created_at} /></td><td className="text-xs">{j.requested_by}</td></tr>)}</tbody></table></TableWrap>
      <Pager page={page} size={25} total={q.data.total} onPage={setPage} /></> : !q.isLoading && <Empty text="No jobs yet." />}
  </Card>;
}

export function JobDrawer({ id, onClose, onPlan }: { id: number; onClose: () => void; onPlan: (id: number) => void }) {
  const meta = useMeta().data;
  const q = useQuery({ queryKey: ["iac-job", id], queryFn: () => api<any>(`/iac/jobs/${id}`), refetchInterval: (qq) => ["queued", "running"].includes(qq.state.data?.status) ? 2000 : false });
  const cancel = useAct(() => api<any>(`/iac/jobs/${id}/cancel`, { method: "POST" }));
  const [confirm, setConfirm] = useState(false);
  const j = q.data;
  const pct = j?.progress?.devices ? Math.round(100 * (j.progress.done || 0) / j.progress.devices) : 0;
  return <Drawer title={j ? `${j.kind.replace("_", " ")} job #${j.id}` : "Job"} onClose={onClose}>
    <Loading q={q} />
    {j && <div className="space-y-4">
      <div className="flex flex-wrap gap-3 items-center text-sm"><Status s={j.status} />{j.plan_id && <button className="btn py-0.5 text-xs" onClick={() => onPlan(j.plan_id)}>Plan #{j.plan_id}</button>}
        <span className="text-xs text-muted">by {j.requested_by} · queued <Time v={j.created_at} />{j.finished_at && <> · finished <Time v={j.finished_at} /></>}</span>
        {["queued", "running"].includes(j.status) && <button className="btn btn-danger py-0.5 text-xs ml-auto" disabled={!can(meta, "deployer") || j.cancel_requested} onClick={() => setConfirm(true)}>
          {j.cancel_requested ? "Cancellation requested" : "Cancel"}</button>}</div>
      <div className="h-2 rounded bg-white/10 overflow-hidden" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}><div className="h-2 bg-brand-500" style={{ width: `${pct}%` }} /></div>
      {j.current_operation && <div className="text-xs text-muted">Current: {j.current_operation}</div>}
      {j.error && <Note tone="bad">{j.error}</Note>}
      {j.devices.map((d: any) => <Card key={d.firewall_id} title={<span>{d.firewall_name} <Status s={d.status} /></span>}
        right={d.backup_id && <span className="text-2xs text-muted">backup #{d.backup_id}</span>}>
        {d.error && <Note tone="bad">{d.error}</Note>}
        {d.results?.length > 0 && <TableWrap maxH="max-h-72"><table className="tbl"><thead><tr><th>Action</th><th>Resource</th><th>Request</th><th>Result</th></tr></thead>
          <tbody>{d.results.map((r: any, i: number) => <tr key={i}><td><Action a={r.action} /></td><td className="font-mono text-xs">{r.type}{r.key ? `:${r.key}` : ""}</td>
            <td className="font-mono text-2xs break-all">{r.request ? `${r.request.method} ${r.request.path}${Object.keys(r.request.params || {}).length ? "?" + new URLSearchParams(r.request.params).toString() : ""}` : `${r.method || ""} ${r.path || ""}`}</td>
            <td className="text-xs">{r.dry_run ? <span className="text-muted">not sent (dry run)</span> : r.ok ? <span className="text-emerald-300">ok</span> : <span className="text-red-300">failed {r.http_status || ""} {r.device_error}</span>}</td></tr>)}</tbody></table></TableWrap>}
        {d.verification && Object.keys(d.verification).length > 0 && <div className="text-xs mt-2">Verification: {d.verification.ok ? <span className="text-emerald-300">device matches the applied changes ({d.verification.checked} checked)</span>
          : <span className="text-red-300">mismatch</span>}
          {d.verification.mismatches?.map((m: any, i: number) => <div key={i} className="text-red-200">• {m.resource}: {m.problem}</div>)}</div>}
        {d.health && Object.keys(d.health).length > 0 && <div className="text-xs mt-1 text-muted">Health: before {d.health.before?.reachable ? `ok (CPU ${d.health.before.cpu}%, mem ${d.health.before.mem}%)` : "n/a"}
          {d.health.after && <> · after {d.health.after.reachable ? `ok (CPU ${d.health.after.cpu}%, mem ${d.health.after.mem}%)` : <span className="text-red-300">unreachable</span>}</>}</div>}
      </Card>)}
      <Card title="Log" bodyClass="p-0"><pre className="text-xs max-h-72 overflow-auto p-2">{(j.log || []).map((l: any) => `${l.t.slice(11, 19)}  ${l.msg}`).join("\n") || "—"}</pre></Card>
    </div>}
    {confirm && <Confirm title="Cancel job" confirmLabel="Request cancellation" danger busy={cancel.isPending} onClose={() => setConfirm(false)} onConfirm={() => cancel.mutate(undefined, { onSuccess: () => setConfirm(false) })}>
      <p className="text-sm">A queued job is cancelled immediately. A running job stops before its next change; a request already sent to a device cannot be recalled, so some changes may already be applied.</p>
      <ErrorBox error={cancel.error} /></Confirm>}
  </Drawer>;
}
