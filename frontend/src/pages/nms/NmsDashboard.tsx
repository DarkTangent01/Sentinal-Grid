import { ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { fmtNum } from "../../lib/format";
import { Card, Empty, Kpi, Sev, TableWrap, Time } from "../../components/ui";
import { availTone, fmtAvail, scoreTone } from "./nms";

/** Sentinel NMS landing page: one row per network domain, built from each module's own overview API (no new data
 *  paths). A module that fails to load shows its own error instead of zeros. */
export function NmsDashboard() {
  const nav = useNavigate();
  const wan = useOverview("wan", "/wan/overview");
  const sw = useOverview("sw", "/switches/overview");
  const fw = useOverview("fw", "/fwhealth/overview");
  const vpn = useOverview("vpn", "/vpn-tunnels/overview");
  const bgp = useOverview("bgp", "/bgp/overview");
  const tac = useOverview("tac", "/tacacs/overview");
  const alerts = useOverview("alerts", "/alerts", { product: "nms", status: ["new", "investigating"], size: 8 });
  const incs = useOverview("incs", "/wan/incidents", { open_only: true, size: 8 });
  const hl = useOverview("health", "/nms/analytics/health", {});
  const av = useOverview("avail", "/nms/analytics/availability", { range: "30d", sla: 99.9 });
  const svc = useOverview("svc", "/nms/services", {});
  const cap = useOverview("cap", "/nms/analytics/capacity", { days: 30 });
  const mw = useOverview("mw", "/nms/maintenance", {});
  const w = wan.data?.totals, s = sw.data?.totals, f = fw.data?.totals, v = vpn.data?.totals, b = bgp.data?.totals;
  const tServers = tac.data?.servers || [];
  return (
    <div className="space-y-4 min-w-0">
      <p className="text-xs text-muted">Network health across ISP / WAN, devices, service checks, firewalls, switches, routing, VPN and AAA (last 24 hours unless a tile says otherwise).
        Every tile opens its module.</p>
      <Section title="ISP / WAN" to="/isp?tab=overview" q={wan}>
        {w && <div className="kpi-grid">
          <Kpi label="Circuits down" value={fmtNum(w.down)} tone={w.down ? "bad" : "ok"} sub={`${fmtNum(w.circuits)} monitored`} onClick={() => nav("/isp?tab=live&state=down")} />
          <Kpi label="Degraded" value={fmtNum(w.degraded)} tone={w.degraded ? "warn" : undefined} onClick={() => nav("/isp?tab=live&state=degraded")} />
          <Kpi label="Open ISP incidents" value={fmtNum(w.open)} tone={w.open ? "bad" : "ok"} onClick={() => nav("/isp?tab=incidents&open_only=1")} />
          <Kpi label="WAN outages (24 h)" value={fmtNum(w.outages)} tone={w.outages ? "warn" : "ok"} onClick={() => nav("/isp?tab=analytics")} />
          <Kpi label="Probe collector" value={wan.data.collector?.status === "ok" ? "OK" : wan.data.collector?.status || "—"}
            tone={wan.data.collector?.status === "ok" ? "ok" : "warn"} sub={wan.data.collector?.detail} />
        </div>}
      </Section>
      <Section title="Network analytics" to="/nms/analytics?tab=health" q={hl}>
        {hl.data && <div className="kpi-grid">
          <Kpi label="Fleet health score" value={hl.data.summary.average ?? "—"} tone={scoreTone(hl.data.summary.average)}
            sub={`${fmtNum((hl.data.summary.grades.poor || 0) + (hl.data.summary.grades.critical || 0))} poor / critical devices`} onClick={() => nav("/nms/analytics?tab=health")} />
          <Kpi label="Availability (30 d)" value={av.data ? fmtAvail(av.data.summary.fleet_availability_pct) : "—"} tone={av.data ? availTone(av.data.summary.fleet_availability_pct, 99.9) : undefined}
            sub={av.data ? `${fmtNum(av.data.summary.sla_breaches)} below 99.9 % SLA` : undefined} onClick={() => nav("/nms/analytics?tab=availability")} />
          <Kpi label="Service checks failing" value={svc.data ? `${fmtNum(svc.data.counts.critical)} / ${fmtNum(svc.data.total)}` : "—"}
            tone={svc.data ? (svc.data.counts.critical ? "bad" : svc.data.counts.warning ? "warn" : "ok") : undefined}
            sub={svc.data?.counts.warning ? `${svc.data.counts.warning} warning` : undefined} onClick={() => nav("/nms/services")} />
          <Kpi label="Capacity risk (≤ 30 days)" value={cap.data ? fmtNum(cap.data.summary.interfaces_at_risk_30d + cap.data.summary.devices_at_risk_30d) : "—"}
            tone={cap.data ? (cap.data.summary.interfaces_at_risk_30d + cap.data.summary.devices_at_risk_30d ? "warn" : "ok") : undefined}
            sub="interfaces + CPU / memory / storage" onClick={() => nav("/nms/analytics?tab=capacity")} />
          <Kpi label="Maintenance active" value={fmtNum(mw.data?.active || 0)} tone={mw.data?.active ? "warn" : undefined} onClick={() => nav("/nms/maintenance")} />
        </div>}
      </Section>
      <div className="grid gap-4 xl:grid-cols-2">
        <Section title="Firewalls" to="/fw-health" q={fw}>
          {f && <div className="kpi-grid">
            <Kpi label="Firewalls" value={fmtNum(f.firewalls)} onClick={() => nav("/fw-health")} />
            <Kpi label="High CPU / memory" value={`${fmtNum(f.high_cpu)} / ${fmtNum(f.high_mem)}`} tone={f.high_cpu || f.high_mem ? "warn" : "ok"} />
            <Kpi label="Reboots" value={fmtNum(f.reboots)} tone={f.reboots ? "bad" : "ok"} />
            <Kpi label="Log feed gaps" value={fmtNum(f.feed_gaps)} tone={f.feed_gaps ? "warn" : "ok"} />
          </div>}
        </Section>
        <Section title="Switches" to="/switches" q={sw}>
          {s && <div className="kpi-grid">
            <Kpi label="Online" value={`${fmtNum(s.online)} / ${fmtNum(s.monitored)}`} tone={s.offline ? "bad" : "ok"} onClick={() => nav("/switches")} />
            <Kpi label="Offline / auth failed" value={`${fmtNum(s.offline)} / ${fmtNum(s.auth_failed)}`} tone={s.offline || s.auth_failed ? "bad" : "ok"} />
            <Kpi label="Interfaces with errors" value={fmtNum(s.interfaces_with_errors)} tone={s.interfaces_with_errors ? "warn" : "ok"} />
            <Kpi label="Polling success" value={s.polling_success_pct == null ? "—" : `${s.polling_success_pct}%`} />
          </div>}
        </Section>
        <Section title="VPN tunnels" to="/vpn-tunnels" q={vpn}>
          {v && <div className="kpi-grid">
            <Kpi label="Tunnels down" value={`${fmtNum(v.down)} / ${fmtNum(v.tunnels)}`} tone={v.down ? "bad" : "ok"} onClick={() => nav("/vpn-tunnels")} />
            <Kpi label="Flaps" value={fmtNum(v.flaps)} tone={v.flaps ? "warn" : "ok"} />
            <Kpi label="Phase-1 errors" value={fmtNum(v.phase1_errors)} tone={v.phase1_errors ? "warn" : "ok"} />
          </div>}
        </Section>
        <Section title="BGP" to="/bgp" q={bgp}>
          {b && <div className="kpi-grid">
            <Kpi label="Peers up" value={`${fmtNum(b.up)} / ${fmtNum(b.peers)}`} tone={b.down ? "bad" : "ok"} onClick={() => nav("/bgp")} />
            <Kpi label="Peers down" value={fmtNum(b.down)} tone={b.down ? "bad" : "ok"} />
            <Kpi label="Flaps" value={fmtNum(b.flaps)} tone={b.flaps ? "warn" : "ok"} />
            <Kpi label="Routes withdrawn" value={fmtNum(b.routes_withdrawn)} />
          </div>}
        </Section>
      </div>
      <Section title="TACACS+ AAA" to="/tacacs" q={tac}>
        {tac.data && (!tServers.length ? <Empty text="No TACACS+ server registered." /> : <div className="kpi-grid">
          {tServers.map((x: any) => <Kpi key={x.id} label={`${x.name} (${x.role})`} value={x.status} tone={x.status === "up" ? "ok" : x.status === "down" ? "bad" : "warn"}
            onClick={() => nav("/tacacs?tab=health")} />)}
          <Kpi label="Authentication failures" value={fmtNum(tac.data.totals?.auth_failure)} tone={tac.data.totals?.auth_failure ? "warn" : "ok"} />
          <Kpi label="Authorization denials" value={fmtNum(tac.data.totals?.authz_deny)} tone={tac.data.totals?.authz_deny ? "warn" : "ok"} />
        </div>)}
      </Section>
      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="Open network alerts" bodyClass="p-0" right={<Link className="link text-xs" to="/alerts?product=nms">All network alerts →</Link>}>
          {alerts.error ? <Empty text={(alerts.error as Error).message} /> : !alerts.data?.items?.length ? <Empty text="No open network alerts." /> :
            <TableWrap><table className="tbl"><tbody>{alerts.data.items.map((a: any) => <tr key={a.id} className="cursor-pointer hover:bg-white/5" onClick={() => nav(`/alerts?product=nms&id=${a.id}`)}>
              <td><Sev s={a.severity} /></td><td className="font-medium">{a.name}</td><td className="text-xs text-muted"><Time v={a.last_seen} /></td></tr>)}</tbody></table></TableWrap>}
        </Card>
        <Card title="Open ISP incidents" bodyClass="p-0" right={<Link className="link text-xs" to="/isp?tab=incidents">All network incidents →</Link>}>
          {incs.error ? <Empty text={(incs.error as Error).message} /> : !incs.data?.items?.length ? <Empty text="No open ISP incidents." /> :
            <TableWrap><table className="tbl"><tbody>{incs.data.items.map((i: any) => <tr key={i.id} className="cursor-pointer hover:bg-white/5" onClick={() => nav(`/isp?tab=incidents&id=${i.id}`)}>
              <td><Sev s={i.severity} /></td><td className="font-medium">{i.title}</td><td className="text-xs text-muted"><Time v={i.first_seen} /></td></tr>)}</tbody></table></TableWrap>}
        </Card>
      </div>
    </div>
  );
}

function useOverview(key: string, path: string, params: Record<string, any> = { range: "24h" }) {
  return useQuery({ queryKey: ["nms-dash", key], queryFn: () => api<any>(path, { params }), refetchInterval: 60_000, retry: 1 });
}

function Section({ title, to, q, children }: { title: string; to: string; q: { isLoading: boolean; error: unknown }; children: ReactNode }) {
  return (
    <Card title={title} right={<Link className="link text-xs" to={to}>Open →</Link>}>
      {q.isLoading ? <div className="text-sm text-muted">Loading…</div> :
        q.error ? <div role="alert" className="text-sm text-red-300">Could not load {title}: {(q.error as Error).message}</div> : children}
    </Card>
  );
}
