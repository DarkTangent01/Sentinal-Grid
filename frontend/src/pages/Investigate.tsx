import { useNavigate, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { CRIT_CLS } from "./Assets";
import { useData } from "../lib/context";
import { fmtBytes, fmtNum } from "../lib/format";
import { Card, Empty, IpLink, Kpi, Loading, NoData, Sev, TableWrap, Time, rowProps, useExplore } from "../components/ui";
import { TimeChart } from "../components/charts";
import { EventTable } from "./Explorer";
import { UrlCell } from "./Web";

const STATUS: Record<string, string> = { new: "text-red-300", investigating: "text-amber-300", resolved: "text-emerald-300", suppressed: "text-slate-400" };

export function Investigate() {
  const { ip = "" } = useParams();
  const q = useData<any>(`/investigate/ip/${encodeURIComponent(ip)}`);
  const explore = useExplore();
  const nav = useNavigate();
  const d = q.data;
  const s = d?.summary || {};
  const asset = useQuery({ queryKey: ["asset", ip], queryFn: () => api<any>(`/assets/${encodeURIComponent(ip)}`).catch(() => null), staleTime: 60_000 });
  const ti = useData<any>("/ti/summary", { ip });
  return (
    <div className="space-y-4 min-w-0">
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <h1 className="text-lg font-semibold font-mono break-all">{ip}</h1>
        <button className="btn py-0.5" onClick={() => nav(`/graph?kind=ip&value=${encodeURIComponent(ip)}`)}>Entity graph</button>
        {s.events > 0 && <span className="text-xs text-muted">first seen <Time v={s.first_seen} /> · last seen <Time v={s.last_seen} /> · {(s.firewalls || []).join(", ")}</span>}
      </div>
      <Loading q={q} />
      {(asset.data || ti.data?.totals?.events > 0) && <div className="grid-cards md:grid-cols-2">
        {asset.data && <Card title="Asset">
          <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
            <span className="text-muted">Hostname</span><span className="cell-wrap">{asset.data.hostname || "—"}</span>
            <span className="text-muted">Criticality</span><span><span className={`pill ${CRIT_CLS[asset.data.criticality]}`}>{asset.data.criticality}</span></span>
            <span className="text-muted">User</span><span>{asset.data.last_user || "—"}</span>
            <span className="text-muted">MAC / OS</span><span className="font-mono text-xs">{asset.data.mac || "—"} · {asset.data.os || "—"}</span>
            <span className="text-muted">Owner</span><span>{asset.data.owner || "—"}</span>
            <span className="text-muted">Tags</span><span>{(asset.data.tags || []).join(", ") || "—"}</span>
          </div>
        </Card>}
        {ti.data?.totals?.events > 0 && <Card title={`Threat-intel matches (${ti.data.totals.events})`}>
          <ul className="text-sm space-y-1">{ti.data.indicators.slice(0, 8).map((r: any) => <li key={r.indicator} className="flex gap-2"><span className="pill bg-red-500/15 text-red-300">{r.category}</span>
            <span className="font-mono text-xs cell-wrap">{r.indicator}</span><span className="ml-auto text-muted text-xs">{r.events} · {r.feed}</span></li>)}</ul>
        </Card>}
      </div>}
      <div className="kpi-grid">
        <Kpi label="All events" value={fmtNum(s.events)} onClick={() => explore({ ip })} />
        <Kpi label="Traffic" value={fmtNum(s.traffic)} />
        <Kpi label="Allowed" value={fmtNum(s.allowed)} tone="ok" onClick={() => explore({ src_ip: ip, verdict: "allowed" })} />
        <Kpi label="Denied" value={fmtNum(s.denied)} tone="bad" onClick={() => explore({ ip, verdict: "denied" })} />
        <Kpi label="DNS" value={fmtNum(s.dns)} /><Kpi label="Web" value={fmtNum(s.web)} />
        <Kpi label="Sent (as source)" value={fmtBytes(s.bytes_sent)} /><Kpi label="Received (as source)" value={fmtBytes(s.bytes_rcvd)} />
      </div>
      <div className="grid-cards xl:grid-cols-2">
        <Card title="Traffic events over time (as source)"><TimeChart data={d?.timeseries} loading={q.isLoading} stack series={[{ key: "allowed", name: "Allowed", color: "primary" }, { key: "denied", name: "Denied", color: "alert" }]} /></Card>
        <Card title="Traffic volume over time (as source)"><TimeChart data={d?.timeseries} loading={q.isLoading} bytes area series={[{ key: "bytes_sent", name: "Sent" }, { key: "bytes_rcvd", name: "Received" }]} /></Card>
      </div>

      <div className="grid-cards lg:grid-cols-2">
        <Card title={`Security alerts (${d?.alerts?.length ?? 0})`}>
          {d?.alerts?.length ? <TableWrap maxH="max-h-80"><table className="tbl">
            <thead><tr><th>Severity</th><th>Detection</th><th>Status</th><th>Last seen</th><th className="num">Events</th></tr></thead>
            <tbody>{d.alerts.map((a: any) => (
              <tr key={a.id} {...rowProps(() => nav(`/alerts?id=${a.id}`))} aria-label={`Open alert ${a.name}`}>
                <td className="nowrap"><Sev s={a.severity} /></td>
                <td className="min-w-[12rem]">{a.name}</td>
                <td className={`nowrap capitalize ${STATUS[a.status] || ""}`}>{a.status}</td>
                <td><Time v={a.last_seen} /></td>
                <td className="num">{fmtNum(a.event_count)}</td>
              </tr>))}</tbody></table></TableWrap> : <Empty text="No alerts for this IP." />}
        </Card>

        <Card title="Top destinations">
          {d?.top_destinations?.length ? <TableWrap maxH="max-h-80"><table className="tbl">
            <thead><tr><th>Destination</th><th className="num">Events</th><th className="num">Bytes</th><th className="num">Denied</th></tr></thead>
            <tbody>{d.top_destinations.map((r: any) => <tr key={r.key}><td><IpLink ip={r.key} /></td><td className="num">{fmtNum(r.events)}</td>
              <td className="num">{fmtBytes(r.bytes)}</td><td className="num text-red-400">{fmtNum(r.denied)}</td></tr>)}</tbody></table></TableWrap>
            : <NoData category="traffic" />}
        </Card>

        <Card title="Top destination ports">
          {d?.top_ports?.length ? <TableWrap maxH="max-h-80"><table className="tbl">
            <thead><tr><th>Port</th><th>Proto</th><th className="num">Events</th><th className="num">Denied</th></tr></thead>
            <tbody>{d.top_ports.map((r: any) => <tr key={`${r.key}/${r.proto_name}`} {...rowProps(() => explore({ src_ip: ip, dst_port: r.key }))}>
              <td className="font-mono text-sky-400">{r.key}</td><td>{r.proto_name}</td><td className="num">{fmtNum(r.events)}</td>
              <td className="num text-red-400">{fmtNum(r.denied)}</td></tr>)}</tbody></table></TableWrap>
            : <NoData category="traffic" />}
        </Card>

        <Card title="DNS history">
          {d?.dns_history?.length ? <TableWrap maxH="max-h-80"><table className="tbl">
            <thead><tr><th>Query name</th><th>Type</th><th className="num">Count</th><th className="num">NXDOMAIN</th><th>Last seen</th></tr></thead>
            <tbody>{d.dns_history.map((r: any) => <tr key={r.key} {...rowProps(() => explore({ src_ip: ip, category: "dns", dns_query: r.key }))}>
              <td className="font-mono text-xs cell-wrap min-w-[10rem]">{r.key}</td><td className="nowrap">{r.qtype || "—"}</td>
              <td className="num">{fmtNum(r.events)}</td><td className={`num ${r.nxdomain ? "text-amber-300" : ""}`}>{fmtNum(r.nxdomain)}</td>
              <td><Time v={r.last_seen} /></td></tr>)}</tbody></table></TableWrap>
            : <NoData category="dns" what="DNS" />}
        </Card>

        <Card title="URL history" className="lg:col-span-2">
          {d?.url_history?.length ? <TableWrap maxH="max-h-96"><table className="tbl">
            <thead><tr><th>URL (as logged)</th><th className="num">Count</th><th className="num">Blocked</th><th>Last seen</th></tr></thead>
            <tbody>{d.url_history.map((r: any, i: number) => <tr key={`${r.hostname}|${r.url}|${i}`}><td className="min-w-[14rem]"><UrlCell r={r} /></td>
              <td className="num">{fmtNum(r.events)}</td><td className="num text-red-400">{fmtNum(r.blocked)}</td><td><Time v={r.last_seen} /></td></tr>)}</tbody></table></TableWrap>
            : <NoData category="web" what="web / URL" />}
        </Card>
      </div>
      <Card title="All related events (source or destination)"><EventTable filters={{ ip }} /></Card>
    </div>
  );
}
