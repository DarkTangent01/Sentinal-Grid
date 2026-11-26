/** Administration → Deployments: what each service runs, the version kept for rollback, health at the last deployment
 *  and the deployment history (/api/admin/deployments, administrators only). Read-only: deployments and rollbacks run
 *  on the server (scripts/release.sh, scripts/rollback.sh; docs/deployment-guide.md). */
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useMe } from "../lib/context";
import { Card, Empty, Loading, StatStrip, TableWrap, Time } from "../components/ui";

const LABEL: Record<string, string> = { api: "API", worker: "Worker (alerts, jobs)", poller: "SNMP pollers", access: "Device access gateway",
  syslog: "Syslog processing", traps: "SNMP traps", flows: "Flow collector", ansible: "Playbook runner", edge: "Web proxy (nginx)",
  ingress: "Syslog ingress (buffer)", tacacs: "TACACS+", postgres: "PostgreSQL", clickhouse: "ClickHouse" };
const STRATEGY: Record<string, string> = { api: "rolling, no downtime", poller: "rolling, one at a time", edge: "replaced (1-3 s)",
  worker: "replaced (seconds)", access: "replaced (seconds)", syslog: "replaced; ingress buffers", traps: "replaced (seconds)", flows: "replaced (seconds)",
  ansible: "replaced", ingress: "explicit only", tacacs: "explicit only", postgres: "never by a deployment", clickhouse: "never by a deployment" };
const RESULT: Record<string, string> = { ok: "dot-ok", failed: "dot-bad", "rolled back": "dot-warn", refused: "dot-warn" };

function health(h?: string, st?: string) {
  const c = st !== "running" ? "dot-bad" : h === "healthy" || h === "none" ? "dot-ok" : h === "starting" ? "dot-warn" : h ? "dot-bad" : "dot-unknown";
  return <span className="inline-flex items-center gap-1.5"><span className={`dot ${c}`} aria-hidden />{st || "—"}{h && h !== "none" ? ` · ${h}` : ""}</span>;
}

export function Deployments() {
  const me = useMe();
  const q = useQuery<any>({ queryKey: ["deployments"], queryFn: () => api("/admin/deployments"), refetchInterval: 30_000, enabled: me.role === "admin" });
  if (me.role !== "admin") return <Empty text="Deployment information is available to administrators only." />;
  const d = q.data;
  return <div className="space-y-4 min-w-0">
    <h1 className="page-title">Deployments</h1>
    <Loading q={q} />
    {d && !d.available && <Card><Empty text="No deployment state yet: it appears after the first deployment with scripts/release.sh." /></Card>}
    {d?.available && <>
      <Card><StatStrip items={[["Running API version", <span className="mono">{d.running_api_version}</span>], ["UI release", <span className="mono">{d.ui_release || "—"}</span>],
        ["State captured", d.captured_at ? <Time v={d.captured_at} /> : "—"], ["Deployments recorded", String(d.history.length)]]} /></Card>
      <Card title="Services" bodyClass="p-0">
        <TableWrap><table className="tbl"><thead><tr><th>Service</th><th>Version</th><th>Previous (rollback)</th><th>State at last deployment</th>
          <th className="num">Containers</th><th>Deployed</th><th>Update strategy</th></tr></thead>
          <tbody>{d.services.map((s: any) => <tr key={s.service}><td>{LABEL[s.service] || s.service}</td><td className="mono">{s.tag || "—"}</td>
            <td className="mono text-muted">{s.previous || "—"}</td><td>{health(s.health, s.state)}</td><td className="num">{s.containers ?? "—"}</td>
            <td>{s.deployed_at ? <Time v={s.deployed_at} /> : "—"}</td><td className="text-muted">{STRATEGY[s.service] || "—"}</td></tr>)}</tbody></table></TableWrap>
      </Card>
      <Card title="History" bodyClass="p-0">
        {!d.history.length ? <div className="p-4"><Empty text="No deployments recorded yet." /></div> :
          <TableWrap maxH="max-h-[32rem]"><table className="tbl"><thead><tr><th>When</th><th>Service</th><th>Result</th><th>From</th><th>To</th>
            <th className="num">Duration</th><th>Note</th></tr></thead>
            <tbody>{d.history.map((h: any, i: number) => <tr key={i}><td><Time v={h.ts} /></td><td>{LABEL[h.service] || h.service}{h.kind === "rollback" && <span className="pill text-muted ml-1">rollback</span>}</td>
              <td><span className="inline-flex items-center gap-1.5"><span className={`dot ${RESULT[h.result] || "dot-unknown"}`} aria-hidden />{h.result}</span></td>
              <td className="mono text-muted">{h.from || "—"}</td><td className="mono">{h.to || "—"}</td><td className="num">{h.duration_s != null ? `${h.duration_s} s` : "—"}</td>
              <td className="text-xs text-muted cell-wrap">{h.note}</td></tr>)}</tbody></table></TableWrap>}
      </Card>
      <p className="text-2xs text-subtle">Deploy with <code>./scripts/deploy.sh --apply [service]</code> and roll back with <code>./scripts/rollback.sh &lt;service&gt;</code>
        from the deployment workstation. Database migrations are expand-only and are not reversed by a rollback.</p>
    </>}
  </div>;
}
