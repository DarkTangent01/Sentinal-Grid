/** Sentinel NMS → Monitoring Health: the NMS's own service-level objectives and its processes' figures (app/selfmon.py). */
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../../lib/api";
import { Card, Empty, Kpi, Loading, TableWrap, Time } from "../../components/ui";

const SHOW: [string, string, (v: number) => string][] = [["loop_lag_p95_s", "Loop lag p95", (v) => `${v.toFixed(3)} s`], ["cpu_pct", "CPU", (v) => `${v}%`],
  ["rss_mib", "Memory", (v) => `${v} MiB`], ["polls_in_flight", "Polls in flight", (v) => String(v)], ["wireless_jobs_in_flight", "Wireless jobs", (v) => String(v)],
  ["loop_seconds:alert evaluation", "Alert pass", (v) => `${v.toFixed(1)} s`], ["loop_seconds:wireless client rollup", "Client rollup", (v) => `${v.toFixed(1)} s`]];

export function SelfMonPage() {
  const q = useQuery({ queryKey: ["nms-selfmon"], queryFn: () => api<any>("/nms/selfmon"), refetchInterval: 30_000 });
  const d = q.data;
  return <div className="space-y-4 min-w-0">
    <p className="text-xs text-muted">Is the monitoring itself healthy? Objectives for metric freshness, the worker / pollers' event loops, alerting and the wireless rollup.
      Each worker and poller process reports its own figures once a minute; a missed objective raises the "NMS self-monitoring objective missed" alert.
      The same figures are exported to Prometheus at /api/metrics (administrators).</p>
    <Loading q={q} />
    {d && <>
      <div className="kpi-grid">{d.slos.map((o: any) => <Kpi key={o.key} label={o.label} tone={o.ok == null ? undefined : o.ok ? "ok" : "bad"}
        value={o.value == null ? "—" : `${o.value}${o.unit}`} sub={`objective ${o.comparison} ${o.target}${o.unit}`} />)}</div>
      <Card title="Processes" bodyClass="p-0">{!d.processes.length ? <Empty text="No worker / poller process has reported in the last 10 minutes." /> :
        <TableWrap><table className="tbl"><thead><tr><th>Service</th><th>Instance</th>{SHOW.map(([, l]) => <th key={l} className="num">{l}</th>)}<th>Last report</th></tr></thead>
          <tbody>{d.processes.map((p: any) => <tr key={p.instance}><td>{p.service}</td><td className="font-mono text-xs">{p.instance}</td>
            {SHOW.map(([k, l, f]) => <td key={l} className="num">{p.metrics[k] == null ? "—" : f(p.metrics[k])}</td>)}<td className="text-xs whitespace-nowrap"><Time v={p.last} /></td></tr>)}</tbody></table></TableWrap>}</Card>
      <Card title={`Devices with stale metrics (${d.stale_devices.length})`} bodyClass="p-0">{!d.stale_devices.length ? <Empty text="Every reachable device has fresh metrics." /> :
        <TableWrap><table className="tbl"><thead><tr><th>Device</th><th className="num">Last success</th><th className="num">Stale after</th></tr></thead>
          <tbody>{d.stale_devices.map((x: any) => <tr key={x.id}><td><Link className="link" to={`/switches/${x.id}`}>{x.name}</Link></td>
            <td className="num">{x.age_s == null ? "never" : `${Math.round(x.age_s / 60)} min ago`}</td><td className="num">{Math.round(x.limit_s / 60)} min</td></tr>)}</tbody></table></TableWrap>}</Card>
    </>}
  </div>;
}
