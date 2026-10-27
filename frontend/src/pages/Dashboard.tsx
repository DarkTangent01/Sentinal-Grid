import { useData } from "../lib/context";
import { fmtBytes, fmtNum } from "../lib/format";
import { Card, Kpi, Loading, NoData, useExplore } from "../components/ui";
import { Donut, TimeChart, TopBar } from "../components/charts";
import { Chart, SEV_HEX, axisStyle } from "../components/Chart";
import { useNavigate } from "react-router-dom";

export function Dashboard() {
  const k = useData<any>("/analytics/kpis");
  const ts = useData<any>("/analytics/timeseries/traffic");
  const dnsTs = useData<any>("/analytics/timeseries/dns");
  const topSrc = useData<any[]>("/analytics/top/src_ip", { category: "traffic", limit: 10 });
  const topDst = useData<any[]>("/analytics/top/dst_ip", { category: "traffic", limit: 10 });
  const topPort = useData<any[]>("/analytics/top/dst_port", { category: "traffic", limit: 10 });
  const topProto = useData<any[]>("/analytics/top/proto", { category: "traffic", limit: 10 });
  const topApp = useData<any[]>("/analytics/top/app", { category: "traffic", metric: "bytes", limit: 10 });
  const topDom = useData<any[]>("/analytics/top/dns_domain", { category: "dns", limit: 10 });
  const topHost = useData<any[]>("/analytics/top/hostname", { category: "web", limit: 10 });
  const dnsClients = useData<any[]>("/analytics/top/src_ip", { category: "dns", limit: 10 });
  const sec = useData<any>("/analytics/security");
  const explore = useExplore();
  const nav = useNavigate();
  const d = k.data || {};
  const approx = (key: string, v: string) => ((d.approximate || []).includes(key) ? `≈ ${v}` : v);

  const sevTypes = (() => {
    const rows: any[] = sec.data?.by_severity_type || [];
    const sevs = ["critical", "high", "medium", "low", "informational"];
    const types = Array.from(new Set(rows.map((r) => r.event_subtype || "(none)"))).slice(0, 10);
    return { sevs, types, series: sevs.map((s) => ({ name: s, type: "bar", stack: "s",
      data: types.map((t) => rows.filter((r) => r.severity === s && (r.event_subtype || "(none)") === t).reduce((a, r) => a + Number(r.events), 0)) })) };
  })();

  return (
    <div className="space-y-4">
      <Loading q={k} />
      <div className="kpi-grid">
        <Kpi label="Traffic events" value={fmtNum(d.traffic_events)} onClick={() => explore({ category: "traffic" })} />
        <Kpi label="Sessions" value={approx("sessions", fmtNum(d.sessions))} sub="distinct session IDs (≈ ±1%)" />
        <Kpi label="Unique source IPs" value={fmtNum(d.unique_src)} onClick={() => nav("/sources")} />
        <Kpi label="Unique destination IPs" value={fmtNum(d.unique_dst)} onClick={() => nav("/destinations")} />
        <Kpi label="Data transferred" value={fmtBytes(d.bytes_total)} />
        <Kpi label="Allowed sessions" value={approx("allowed_sessions", fmtNum(d.allowed_sessions))} tone="ok" sub={`${fmtNum(d.allowed_events)} events`} onClick={() => explore({ category: "traffic", verdict: "allowed" })} />
        <Kpi label="Denied sessions" value={approx("denied_sessions", fmtNum(d.denied_sessions))} tone="bad" sub={`${fmtNum(d.denied_events)} events`} onClick={() => explore({ category: "traffic", verdict: "denied" })} />
        <Kpi label="DNS queries" value={fmtNum(d.dns_queries)} onClick={() => nav("/dns")} />
        <Kpi label="Unique queried domains" value={approx("unique_domains", fmtNum(d.unique_domains))} />
        <Kpi label="URL filtering blocks" value={fmtNum(d.url_blocks)} tone={d.url_blocks ? "warn" : undefined} onClick={() => explore({ category: "web", action: "block" })} />
        <Kpi label="Security alerts" value={fmtNum(d.security_alerts)} tone={d.security_alerts ? "bad" : undefined} sub={`${fmtNum(d.open_alerts)} open · ${fmtNum(d.security_events)} security events`} onClick={() => nav("/alerts")} />
        <Kpi label="Firewalls (API)" value={<span><span className="text-emerald-400">{d.firewalls_connected ?? 0}</span> / <span className="text-red-400">{d.firewalls_disconnected ?? 0}</span></span>} sub="connected / disconnected" onClick={() => nav("/firewalls")} />
      </div>

      <div className="grid-cards xl:grid-cols-2">
        <Card title="Traffic events over time"><TimeChart data={ts.data} loading={ts.isLoading} series={[{ key: "events", name: "Events" }]} area /></Card>
        <Card title="Allowed vs denied"><TimeChart data={ts.data} loading={ts.isLoading} stack series={[{ key: "allowed", name: "Allowed", color: "primary" }, { key: "denied", name: "Denied", color: "alert" }]} /></Card>
        <Card title="Bandwidth over time"><TimeChart data={ts.data} loading={ts.isLoading} bytes area series={[{ key: "bytes_sent", name: "Sent" }, { key: "bytes_rcvd", name: "Received" }]} /></Card>
        <Card title="DNS query volume"><TimeChart data={dnsTs.data} loading={dnsTs.isLoading} area series={[{ key: "events", name: "Queries", color: "primary" }]} /></Card>
      </div>

      <div className="grid-cards md:grid-cols-2 2xl:grid-cols-3">
        <Card title="Top source IPs">{topSrc.data?.length ? <TopBar rows={topSrc.data} onClick={(ip) => nav(`/investigate/${encodeURIComponent(ip)}`)} /> : <NoData category="traffic" />}</Card>
        <Card title="Top destination IPs">{topDst.data?.length ? <TopBar rows={topDst.data} onClick={(ip) => explore({ dst_ip: ip })} /> : <NoData category="traffic" />}</Card>
        <Card title="Top destination ports">{topPort.data?.length ? <TopBar rows={topPort.data} onClick={(p) => explore({ dst_port: p, category: "traffic" })} /> : <NoData category="traffic" />}</Card>
        <Card title="Top protocols">{topProto.data?.length ? <Donut rows={topProto.data} label="Protocol" /> : <NoData category="traffic" />}</Card>
        <Card title="Top applications (by bytes, as identified by FortiGate)">{topApp.data?.length ? <TopBar rows={topApp.data} bytes onClick={(a) => explore({ app: a })} /> : <NoData category="traffic" what="application-identified traffic" />}</Card>
        <Card title="Top destination domains (web logs)">{topHost.data?.length ? <TopBar rows={topHost.data} onClick={(h) => explore({ domain: h, category: "web" })} /> : <NoData category="web" what="web-filter" />}</Card>
        <Card title="Top queried domains (DNS)">{topDom.data?.length ? <TopBar rows={topDom.data} onClick={(h) => explore({ domain: h, category: "dns" })} /> : <NoData category="dns" what="DNS" />}</Card>
        <Card title="Top DNS clients">{dnsClients.data?.length ? <TopBar rows={dnsClients.data} onClick={(ip) => explore({ src_ip: ip, category: "dns" })} /> : <NoData category="dns" what="DNS" />}</Card>
        <Card title="Security events by severity and type">
          {sevTypes.types.length ? <Chart height={260} onClick={(p) => explore({ category: ["security", "system"], event_subtype: sevTypes.types[p.dataIndex], severity: p.seriesName })} option={{
            color: sevTypes.sevs.map((x) => SEV_HEX[x]), legend: { top: 0 },
            xAxis: { type: "category", data: sevTypes.types, ...axisStyle }, yAxis: { type: "value", ...axisStyle }, series: sevTypes.series,
          }} /> : <NoData category="security" />}
        </Card>
      </div>
    </div>
  );
}
