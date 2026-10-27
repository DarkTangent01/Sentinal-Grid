import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useGlobal } from "../lib/context";
import { useTheme } from "../lib/theme";
import { fmtBytes, fmtDuration, fmtNum, getTimezone } from "../lib/format";
import { Chart, PALETTES, axisStyle } from "../components/Chart";
import { Card, Drawer, Empty, IpLink, Kpi, Loading, TableWrap, Time, rowProps } from "../components/ui";

const ST: Record<string, [string, string]> = { up: ["bg-emerald-400", "Up"], down: ["bg-red-500 animate-pulse", "Down"], stale: ["bg-slate-500", "No recent stats"] };
const bps = (v?: number | null) => (v == null ? "—" : `${fmtBytes(v / 8).replace(/B$/, "B/s")}`);

export function VpnTunnels() {
  const g = useGlobal();
  const [range, setRange] = useState("24h");
  const [sel, setSel] = useState<any>(null);
  const fw = Array.isArray(g.params.firewall_id) ? g.params.firewall_id : [];
  const q = useQuery({ queryKey: ["vpn-tunnels", range, fw], queryFn: () => api<any>("/vpn-tunnels/overview", { params: { range, firewall_id: fw } }), refetchInterval: 60_000, placeholderData: (p) => p });
  const d = q.data;
  const t = d?.totals || {};
  return (
    <div className="space-y-4 min-w-0">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-xs text-muted flex-1 min-w-[16rem]">Site-to-site IPsec tunnels from FortiGate VPN event logs: up/down changes, periodic tunnel statistics (throughput) and
          IKE phase-1 failures. Dial-up (remote-access) sessions are listed separately.</p>
        <select aria-label="Range" className="input py-1" value={range} onChange={(e) => setRange(e.target.value)}>
          {[["1h", "Last hour"], ["24h", "Last 24 h"], ["7d", "Last 7 days"], ["30d", "Last 30 days"]].map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
      </div>
      <Loading q={q} />
      {d && <>
        <div className="kpi-grid">
          <Kpi label="Tunnels" value={fmtNum(t.tunnels)} />
          <Kpi label="Down now" value={fmtNum(t.down)} tone={t.down ? "bad" : "ok"} />
          <Kpi label="No recent stats" value={fmtNum(t.stale)} tone={t.stale ? "warn" : undefined} />
          <Kpi label="Tunnel drops" value={fmtNum(t.flaps)} sub={`in ${range}`} />
          <Kpi label="Phase-1 failures" value={fmtNum(t.phase1_errors)} tone={t.phase1_errors > 1000 ? "warn" : undefined} sub={`${t.failing_peers} peer(s)`} />
          <Kpi label="Dial-up users" value={fmtNum(t.dialup_users)} />
        </div>
        <Card title="Site-to-site tunnels" right={<span className="text-2xs text-muted">click a tunnel for throughput and down periods</span>}>
          {!d.tunnels.length ? <Empty text="No IPsec tunnel logs in this range. Enable VPN event logging in the syslog filter." /> :
            <TableWrap><table className="tbl"><thead><tr><th>Status</th><th>Firewall</th><th>Tunnel</th><th>Peer</th><th>Interface</th><th className="num">Availability</th>
              <th className="num">Drops</th><th className="num">Downtime</th><th>Last drop</th><th className="num">Avg in / out</th><th className="num">Peak in</th><th>Last stats</th></tr></thead>
              <tbody>{d.tunnels.map((x: any) => <tr key={`${x.firewall_id}:${x.tunnel}`} {...rowProps(() => setSel(x))}>
                <td><span className="inline-flex items-center gap-1.5 whitespace-nowrap"><span className={`h-2.5 w-2.5 rounded-full ${ST[x.status][0]}`} aria-hidden />{ST[x.status][1]}</span></td>
                <td className="text-xs nowrap">{x.firewall_name}</td><td className="font-mono text-xs">{x.tunnel}</td><td><IpLink ip={x.remote_ip} /></td>
                <td className="font-mono text-xs">{x.interface || "—"}</td>
                <td className={`num ${x.availability != null && x.availability < 99.9 ? "text-red-300" : "text-emerald-300"}`}>{x.availability == null ? "—" : `${x.availability.toFixed(3)}%`}</td>
                <td className="num">{fmtNum(x.downs)}</td><td className="num">{x.downtime_s ? fmtDuration(x.downtime_s) : "—"}</td><td><Time v={x.last_down} /></td>
                <td className="num text-xs">{bps(x.avg_in_bps)} / {bps(x.avg_out_bps)}</td><td className="num text-xs">{bps(x.peak_in_bps)}</td><td><Time v={x.last_stats} /></td>
              </tr>)}</tbody></table></TableWrap>}
        </Card>
        <div className="grid gap-4 xl:grid-cols-[2fr_1fr] min-w-0">
          <Card title="Failing IKE peers (phase 1)">
            {!d.phase1_failures.length ? <Empty text="No phase-1 failures." /> :
              <TableWrap maxH="max-h-96"><table className="tbl"><thead><tr><th>Peer</th><th>Country</th><th>Firewall · interface</th><th className="w-full">Reason</th><th className="num">Attempts</th><th>Last</th></tr></thead>
                <tbody>{d.phase1_failures.map((f: any, i: number) => <tr key={i}><td><IpLink ip={f.remote_ip} /></td><td className="text-xs">{f.country || "—"}</td>
                  <td className="text-xs nowrap">{f.firewall_name} · <span className="font-mono">{f.interface}</span></td><td className="text-xs">{f.reason}</td>
                  <td className="num">{fmtNum(f.count)}</td><td><Time v={f.last} /></td></tr>)}</tbody></table></TableWrap>}
            <p className="text-2xs text-muted mt-2">A peer retrying thousands of times with "proposal not match" is usually a partner with a stale tunnel configuration (or an unsolicited scanner). Fix or remove the peer to stop the noise.</p>
          </Card>
          <div className="space-y-4 min-w-0">
            <Card title="Failure reasons"><ul className="text-sm space-y-1">{d.failure_reasons.map((r: any) => <li key={r.reason} className="flex gap-2"><span className="flex-1">{r.reason}</span><b className="tabular-nums">{fmtNum(r.count)}</b></li>)}
              {!d.failure_reasons.length && <li className="text-muted">none</li>}</ul></Card>
            <Card title="Dial-up IPsec users"><ul className="text-sm space-y-1">{d.dialup.map((u: any) => <li key={u.user} className="flex gap-2"><span className="flex-1">{u.user}</span>
              <span className="text-muted text-xs">{u.sessions} session(s) · <Time v={u.last} /></span></li>)}{!d.dialup.length && <li className="text-muted">none</li>}</ul></Card>
          </div>
        </div>
      </>}
      {sel && <TunnelDrawer x={sel} range={range} onClose={() => setSel(null)} />}
    </div>
  );
}

function TunnelDrawer({ x, range, onClose }: { x: any; range: string; onClose: () => void }) {
  const { theme } = useTheme();
  const q = useQuery({ queryKey: ["vpn-tunnel", x.firewall_id, x.tunnel, range], queryFn: () => api<any>(`/vpn-tunnels/${x.firewall_id}/${encodeURIComponent(x.tunnel)}`, { params: { range } }) });
  const d = q.data;
  return (
    <Drawer title={`${x.tunnel} · ${x.firewall_name}`} onClose={onClose}>
      <Loading q={q} />
      {d && <div className="space-y-4">
        <div className="text-sm">Peer <span className="font-mono">{d.remote_ip}</span> · local <span className="font-mono">{d.local_ip}</span> via <span className="font-mono">{d.interface}</span>
          {d.uptime_s != null && <> · SA up for {fmtDuration(d.uptime_s)}</>}</div>
        <Card title="Throughput">{d.series.length ? <Chart height={220} option={{
          legend: { top: 0 }, tooltip: { trigger: "axis", confine: true, valueFormatter: (v: number) => bps(v) },
          xAxis: { type: "time", ...axisStyle, axisLabel: { ...axisStyle.axisLabel, formatter: (v: number) => new Date(v).toLocaleString(undefined, { hour: "2-digit", minute: "2-digit", hour12: false, timeZone: getTimezone() }) } },
          yAxis: { type: "value", ...axisStyle, axisLabel: { ...axisStyle.axisLabel, formatter: (v: number) => bps(v) } },
          series: [{ name: "in", type: "line", showSymbol: false, smooth: true, itemStyle: { color: PALETTES[theme][0] }, data: d.series.map((p: any) => [Date.parse(p.t), p.in_bps]) },
            { name: "out", type: "line", showSymbol: false, smooth: true, itemStyle: { color: PALETTES[theme][1] }, data: d.series.map((p: any) => [Date.parse(p.t), p.out_bps]) }],
        }} /> : <Empty text="Not enough statistics samples for a throughput chart." />}</Card>
        <Card title={`Down periods (${d.down_periods.length})`} bodyClass="p-0">
          {d.down_periods.length ? <TableWrap><table className="tbl"><thead><tr><th>Start</th><th>End</th><th className="num">Duration</th></tr></thead>
            <tbody>{[...d.down_periods].reverse().map((p: any, i: number) => <tr key={i}><td><Time v={p.start} /></td><td><Time v={p.end} /></td><td className="num">{fmtDuration(p.duration_s)}</td></tr>)}</tbody></table></TableWrap>
            : <Empty text="The tunnel did not go down in this range." />}
        </Card>
      </div>}
    </Drawer>
  );
}
