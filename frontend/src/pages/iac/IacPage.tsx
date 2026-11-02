import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { fmtNum } from "../../lib/format";
import { Card, Empty, Kpi, Loading, TableWrap, Tabs, Time, rowProps } from "../../components/ui";
import { Audit, Backups, Settings } from "./Admin";
import { Devices, Drift } from "./Devices";
import { JobDrawer, Jobs, PlanDrawer, Plans } from "./Plans";
import { Studio } from "./Studio";
import { Confirm, ErrorBox, Note, SevBadge, Status, can, useAct, useMeta } from "./common";

const TABS = [["overview", "Overview"], ["devices", "Devices"], ["studio", "Configuration studio"], ["drift", "Drift"], ["plans", "Plans & approvals"],
  ["deployments", "Deployments"], ["backups", "Backups & recovery"], ["audit", "Audit"], ["settings", "Settings"]];

export function Iac() {
  const meta = useMeta();
  const [sp, setSp] = useSearchParams();
  const tab = sp.get("tab") || "overview";
  const projectId = sp.get("project") ? Number(sp.get("project")) : null;
  const go = (t: string, extra: Record<string, string | number | null> = {}) => {
    const n = new URLSearchParams(sp);
    n.set("tab", t);
    for (const k of ["status", "severity", "firewall"]) n.delete(k);
    for (const [k, v] of Object.entries(extra)) v === null ? n.delete(k) : n.set(k, String(v));
    setSp(n, { replace: false });
  };
  const projects = useQuery({ queryKey: ["iac-projects"], queryFn: () => api<any[]>("/iac/projects") });
  const [plan, setPlan] = useState<number | null>(null);
  const [job, setJob] = useState<number | null>(null);
  const [newProj, setNewProj] = useState(false);
  const proj = projects.data?.find((p) => p.id === projectId);
  if (meta.error) return <ErrorBox error={meta.error} />;
  return <div className="space-y-4 min-w-0">
    <div className="flex flex-wrap items-center gap-2">
      <p className="text-xs text-muted flex-1 min-w-[18rem]">Firewall configuration as code: versioned desired state, drift against the live FortiGate, reviewed plans, approvals with separation of duties,
        controlled deployments with backups and verification. Roles: <b>{meta.data?.roles?.join(", ")}</b>.</p>
      <select aria-label="Project" className="input py-1" value={projectId ?? ""} onChange={(e) => { const n = new URLSearchParams(sp); e.target.value ? n.set("project", e.target.value) : n.delete("project"); setSp(n); }}>
        <option value="">All projects</option>{projects.data?.map((p) => <option key={p.id} value={p.id}>{p.name} ({p.environment})</option>)}</select>
      <button className="btn py-1" disabled={!can(meta.data, "editor")} title={can(meta.data, "editor") ? "" : "IaC editor role required"} onClick={() => setNewProj(true)}>New project</button>
    </div>
    {meta.data && !meta.data.writes_effective && <Note>Deployments are off: {meta.data.writes_reason}. Plans, drift checks, validation and dry runs work and never change devices.</Note>}
    <Tabs value={tab} onChange={(t) => go(t)} tabs={TABS.map(([key, label]) => ({ key, label }))} />
    {tab === "overview" && <Overview go={go} projects={projects.data || []} />}
    {tab === "devices" && <Devices projects={projects.data || []} projectId={projectId} status={sp.get("status") || ""} onDrift={(fw) => go("drift", { firewall: fw })} />}
    {tab === "studio" && (projectId ? <Studio projectId={projectId} onPlan={(id) => setPlan(id)} />
      : <ProjectPicker projects={projects.data || []} onPick={(id) => { const n = new URLSearchParams(sp); n.set("project", String(id)); setSp(n); }} />)}
    {tab === "drift" && <Drift projectId={projectId} firewallId={sp.get("firewall") ? Number(sp.get("firewall")) : null} severity={sp.get("severity") || ""} />}
    {tab === "plans" && <Plans projectId={projectId} status={sp.get("status") || ""} onOpen={setPlan} onJob={setJob} />}
    {tab === "deployments" && <Jobs projectId={projectId} onOpen={setJob} />}
    {tab === "backups" && <Backups onPlan={setPlan} />}
    {tab === "audit" && <Audit projectId={projectId} />}
    {tab === "settings" && <Settings />}
    {proj && tab === "studio" && <p className="text-2xs text-muted">Project <b>{proj.name}</b> · {proj.environment} · {proj.devices} device(s) · latest v{proj.latest_version ?? "—"}</p>}
    {plan && <PlanDrawer id={plan} onClose={() => setPlan(null)} onJob={(id) => { setPlan(null); setJob(id); }} />}
    {job && <JobDrawer id={job} onClose={() => setJob(null)} onPlan={(id) => { setJob(null); setPlan(id); }} />}
    {newProj && <NewProject onClose={() => setNewProj(false)} onCreated={(id) => { setNewProj(false); const n = new URLSearchParams(sp); n.set("project", String(id)); n.set("tab", "studio"); setSp(n); }} />}
  </div>;
}

function ProjectPicker({ projects, onPick }: { projects: any[]; onPick: (id: number) => void }) {
  if (!projects.length) return <Empty text="No IaC projects yet. Create one with “New project”." />;
  return <Card title="Choose a project" bodyClass="p-0"><TableWrap><table className="tbl"><thead><tr><th>Project</th><th>Environment</th><th className="num">Devices</th><th>Latest version</th><th>Draft</th></tr></thead>
    <tbody>{projects.map((p) => <tr key={p.id} {...rowProps(() => onPick(p.id))}><td className="font-semibold text-sm">{p.name}<div className="text-2xs text-muted">{p.description}</div></td>
      <td className="text-xs">{p.environment}</td><td className="num">{p.devices}</td><td className="font-mono text-xs">{p.latest_version ? `v${p.latest_version}` : "—"}</td>
      <td className="text-xs">{p.draft_updated_by ? <>{p.draft_updated_by} · <Time v={p.draft_updated_at} /></> : "—"}</td></tr>)}</tbody></table></TableWrap></Card>;
}

function NewProject({ onClose, onCreated }: { onClose: () => void; onCreated: (id: number) => void }) {
  const [f, setF] = useState({ name: "", description: "", environment: "development" });
  const m = useAct(() => api<any>("/iac/projects", { method: "POST", body: f }), (r) => onCreated(r.id));
  return <Confirm title="New IaC project" confirmLabel="Create" busy={m.isPending} disabled={!f.name.trim()} onClose={onClose} onConfirm={() => m.mutate(undefined)}>
    <input aria-label="Project name" className="input w-full" placeholder="name (letters, digits, . _ -)" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} />
    <input aria-label="Description" className="input w-full" placeholder="description" value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} />
    <select aria-label="Environment" className="input w-full" value={f.environment} onChange={(e) => setF({ ...f, environment: e.target.value })}>
      {["development", "staging", "production"].map((e) => <option key={e}>{e}</option>)}</select>
    <p className="text-xs text-muted">Production projects enforce separation of duties (configurable) and typed confirmation for deployments. Devices are added by an IaC admin.</p>
    <ErrorBox error={m.error} /></Confirm>;
}

function Overview({ go, projects }: { go: (t: string, extra?: Record<string, string | number | null>) => void; projects: any[] }) {
  const [days, setDays] = useState(7);
  const [env, setEnv] = useState("");
  const [site, setSite] = useState("");
  const [dev, setDev] = useState("");
  const [status, setStatus] = useState("");
  const [sev, setSev] = useState("");
  const q = useQuery({ queryKey: ["iac-overview", days], queryFn: () => api<any>("/iac/overview", { params: { days } }), refetchInterval: 30_000, placeholderData: (p) => p });
  const d = q.data;
  const devices = useMemo(() => (d?.devices || []).filter((x: any) => (!env || x.environment === env) && (!site || x.site === site) && (!dev || x.firewall_name === dev)
    && (!status || x.drift_status === status)), [d, env, site, dev, status]);
  const findings = useMemo(() => (d?.findings || []).filter((f: any) => !sev || f.severity === sev), [d, sev]);
  const t = d?.totals || {};
  const sites = Array.from(new Set((d?.devices || []).map((x: any) => x.site).filter(Boolean))).sort() as string[];
  const names = Array.from(new Set((d?.devices || []).map((x: any) => x.firewall_name))).sort() as string[];
  return <div className="space-y-4">
    <div className="flex flex-wrap gap-2 items-center">
      <select aria-label="Environment" className="input py-1 text-xs" value={env} onChange={(e) => setEnv(e.target.value)}><option value="">All environments</option>{["development", "staging", "production"].map((x) => <option key={x}>{x}</option>)}</select>
      <select aria-label="Site" className="input py-1 text-xs" value={site} onChange={(e) => setSite(e.target.value)}><option value="">All sites</option>{sites.map((x) => <option key={x}>{x}</option>)}</select>
      <select aria-label="Device" className="input py-1 text-xs" value={dev} onChange={(e) => setDev(e.target.value)}><option value="">All devices</option>{names.map((x) => <option key={x}>{x}</option>)}</select>
      <select aria-label="Status" className="input py-1 text-xs" value={status} onChange={(e) => setStatus(e.target.value)}><option value="">Any status</option>{["in_sync", "drift", "unknown", "error"].map((x) => <option key={x} value={x}>{x.replace("_", " ")}</option>)}</select>
      <select aria-label="Severity" className="input py-1 text-xs" value={sev} onChange={(e) => setSev(e.target.value)}><option value="">Any severity</option>{["critical", "high", "medium", "low", "info"].map((x) => <option key={x}>{x}</option>)}</select>
      <select aria-label="Time range" className="input py-1 text-xs" value={days} onChange={(e) => setDays(Number(e.target.value))}>{[1, 7, 30, 90].map((x) => <option key={x} value={x}>Last {x} day{x > 1 ? "s" : ""}</option>)}</select>
    </div>
    <Loading q={q} />
    {d && <>
      <div className="kpi-grid">
        <Kpi label="Managed devices" value={fmtNum(t.managed)} onClick={() => go("devices")} sub={`${projects.length} project(s)`} />
        <Kpi label="In sync" value={fmtNum(t.in_sync)} tone={t.managed && t.in_sync === t.managed ? "ok" : undefined} onClick={() => go("devices", { status: "in_sync" })} />
        <Kpi label="Drifted" value={fmtNum(t.drift)} tone={t.drift ? "bad" : "ok"} onClick={() => go("devices", { status: "drift" })} />
        <Kpi label="Failed validation" value={fmtNum(t.failed_validation)} tone={t.failed_validation ? "warn" : undefined} onClick={() => go("plans", { status: "validation_failed" })} sub="devices in projects with a blocked plan" />
        <Kpi label="Pending approvals" value={fmtNum(t.pending_approvals)} tone={t.pending_approvals ? "warn" : undefined} onClick={() => go("plans", { status: "pending_approval" })} />
        <Kpi label="Deployments / failed" value={`${fmtNum(t.deployments)} / ${fmtNum(t.failed_deployments)}`} tone={t.failed_deployments ? "bad" : undefined} onClick={() => go("deployments")} sub={`last ${days} day(s)`} />
        <Kpi label="Last successful sync" value={t.last_sync ? <Time v={t.last_sync} /> : "never"} onClick={() => go("drift")} />
      </div>
      <div className="grid gap-4 xl:grid-cols-[3fr_2fr] min-w-0">
        <Card title="Device status" bodyClass="p-0">
          {devices.length ? <TableWrap maxH="max-h-96"><table className="tbl"><thead><tr><th>Device</th><th>Site</th><th>Project</th><th>Env</th><th>Sync</th><th>Last check</th><th>Last deployment</th></tr></thead>
            <tbody>{devices.map((x: any) => <tr key={x.device_id} {...rowProps(() => go("drift", { firewall: x.firewall_id }))}><td className="text-sm font-semibold">{x.firewall_name}</td>
              <td className="text-xs">{x.site || "—"}</td><td className="text-xs">{x.project}</td><td className="text-xs">{x.environment}</td>
              <td><Status s={x.drift_status} />{x.integration === "fortimanager" && <span className="text-2xs text-amber-300 ml-1">FMG</span>}{x.validation_failed && <span className="text-2xs text-red-300 ml-1">validation</span>}</td>
              <td><Time v={x.last_drift_check} /></td><td>{x.last_deploy_at ? <><Time v={x.last_deploy_at} /> <Status s={x.last_deploy_status} /></> : "—"}</td></tr>)}</tbody></table></TableWrap>
            : <Empty text="No managed devices match. Add FortiGates to a project on the Devices tab." />}
        </Card>
        <Card title="Recent deployments" bodyClass="p-0">
          {d.jobs.length ? <TableWrap maxH="max-h-96"><table className="tbl"><thead><tr><th>#</th><th>Status</th><th>By</th><th>When</th></tr></thead>
            <tbody>{d.jobs.map((j: any) => <tr key={j.id} {...rowProps(() => go("deployments"))}><td className="font-mono">{j.id}</td><td><Status s={j.status} /></td><td className="text-xs">{j.requested_by}</td>
              <td><Time v={j.created_at} /></td></tr>)}</tbody></table></TableWrap> : <Empty text="No deployments in this period." />}
        </Card>
      </div>
      <div className="grid gap-4 xl:grid-cols-[3fr_2fr] min-w-0">
        <Card title={`Security and drift findings (${findings.length})`} bodyClass="p-0">
          {findings.length ? <TableWrap maxH="max-h-96"><table className="tbl"><thead><tr><th>Severity</th><th>Source</th><th>Rule</th><th>Resource</th><th className="w-full">Explanation</th></tr></thead>
            <tbody>{findings.map((f: any, i: number) => <tr key={i} {...rowProps(() => f.source === "drift" ? go("drift", { firewall: f.firewall_id }) : go("plans"))}>
              <td><SevBadge s={f.severity} /></td><td className="text-xs">{f.source}</td><td className="font-mono text-xs">{f.rule_id}</td>
              <td className="font-mono text-xs">{f.resource || `${f.type}:${f.key}`}</td><td className="text-xs">{f.explanation}</td></tr>)}</tbody></table></TableWrap>
            : <Empty text="No findings in this period." />}
        </Card>
        <Card title="Latest configuration changes" bodyClass="p-0">
          {d.versions.length ? <TableWrap maxH="max-h-96"><table className="tbl"><thead><tr><th>Project</th><th>Version</th><th>By</th><th className="w-full">Message</th><th>When</th></tr></thead>
            <tbody>{d.versions.map((v: any, i: number) => <tr key={i}><td className="text-xs">{v.project}</td><td className="font-mono text-xs">v{v.number}{!v.valid && <span className="text-red-300 ml-1">invalid</span>}</td>
              <td className="text-xs">{v.author}</td><td className="text-xs">{v.message}</td><td><Time v={v.created_at} /></td></tr>)}</tbody></table></TableWrap>
            : <Empty text="No versions committed yet." />}
        </Card>
      </div>
    </>}
  </div>;
}
