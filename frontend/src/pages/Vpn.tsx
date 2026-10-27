import { useData } from "../lib/context";
import { fmtNum } from "../lib/format";
import { Card, Empty, IpLink, Kpi, Loading, TableWrap, Time, useExplore } from "../components/ui";
import { TimeChart } from "../components/charts";

export function Vpn() {
  const q = useData<any>("/vpn/summary");
  const explore = useExplore();
  const d = q.data;
  const t = d?.totals || {};
  return (
    <div className="space-y-4 min-w-0">
      <p className="text-xs text-muted">From FortiGate VPN event logs (<code>type=event subtype=vpn</code>: SSL-VPN and IPsec tunnel up/down and login failures). Locations use FortiGate country fields or GeoIP; without coordinates, impossible travel uses approximate country centroids and says so.</p>
      <Loading q={q} />
      <div className="kpi-grid">
        <Kpi label="Successful logins" value={fmtNum(t.logins)} tone="ok" onClick={() => explore({ category: ["system"], event_subtype: "vpn", ql: "action:other" })} />
        <Kpi label="Failed logins" value={fmtNum(t.failures)} tone={t.failures ? "bad" : undefined} />
        <Kpi label="Users" value={fmtNum(t.users)} />
        <Kpi label="Source IPs" value={fmtNum(t.sources)} />
        <Kpi label="Active sessions" value={fmtNum(d?.active?.length)} sub="last event was tunnel-up" />
        <Kpi label="Impossible travel" value={fmtNum(d?.impossible_travel?.length)} tone={d?.impossible_travel?.length ? "bad" : undefined} />
      </div>
      <Card title="VPN events over time"><TimeChart data={d?.timeseries} loading={q.isLoading} area series={[{ key: "events", name: "VPN + system events", color: "primary" }]} /></Card>
      {d?.impossible_travel?.length > 0 && <Card title="Impossible travel">
        <TableWrap><table className="tbl"><thead><tr><th>User</th><th>From</th><th>To</th><th className="num">Distance</th><th className="num">Minutes</th><th className="num">Speed</th><th>Basis</th></tr></thead>
          <tbody>{d.impossible_travel.map((x: any, n: number) => <tr key={n}><td>{x.user}</td>
            <td className="text-xs">{x.from.place} · <IpLink ip={x.from.ip} /><div className="text-muted"><Time v={x.from.time} /></div></td>
            <td className="text-xs">{x.to.place} · <IpLink ip={x.to.ip} /><div className="text-muted"><Time v={x.to.time} /></div></td>
            <td className="num">{fmtNum(x.km)} km</td><td className="num">{x.minutes}</td><td className="num text-red-400">{fmtNum(x.kmh)} km/h</td>
            <td className="text-xs">{x.approximate ? "country centroids (approx.)" : "GeoIP coordinates"}</td></tr>)}</tbody></table></TableWrap>
      </Card>}
      <div className="grid-cards xl:grid-cols-2">
        <Card title="Users">
          {d?.users?.length ? <TableWrap maxH="max-h-96"><table className="tbl"><thead><tr><th>User</th><th className="num">Logins</th><th className="num">Failures</th><th className="num">Sources</th><th>Countries</th><th>Last</th></tr></thead>
            <tbody>{d.users.map((u: any) => <tr key={u.user} tabIndex={0} onClick={() => explore({ user: u.user, category: ["system"], event_subtype: "vpn" })}>
              <td>{u.user}{d.active.some((a: any) => a.user === u.user) && <span className="pill bg-emerald-500/15 text-emerald-300 ml-1">active</span>}</td>
              <td className="num">{fmtNum(u.logins)}</td><td className={`num ${u.failures ? "text-red-400" : ""}`}>{fmtNum(u.failures)}</td><td className="num">{fmtNum(u.sources)}</td>
              <td className="text-xs">{(u.countries || []).join(", ") || "—"}</td><td><Time v={u.last_seen} /></td></tr>)}</tbody></table></TableWrap>
            : <Empty text="No VPN events in this range. VPN logs need event logging (subtype vpn) forwarded via syslog." />}
        </Card>
        <Card title="Failed logins by source">
          {d?.failures?.length ? <TableWrap maxH="max-h-96"><table className="tbl"><thead><tr><th>Source</th><th>Country</th><th className="num">Failures</th><th className="num">Users tried</th><th>Last</th></tr></thead>
            <tbody>{d.failures.map((f: any) => <tr key={f.src_ip}><td><IpLink ip={f.src_ip} /></td><td className="text-xs">{f.country || "—"}</td><td className="num text-red-400">{fmtNum(f.failures)}</td>
              <td className="num" title={(f.user_list || []).join(", ")}>{fmtNum(f.users)}</td><td><Time v={f.last_seen} /></td></tr>)}</tbody></table></TableWrap>
            : <Empty text="No failed VPN logins in this range." />}
        </Card>
      </div>
    </div>
  );
}
