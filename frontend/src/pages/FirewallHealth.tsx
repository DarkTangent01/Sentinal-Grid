import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useGlobal } from "../lib/context";
import { useTheme } from "../lib/theme";
import { fmtNum, getTimezone } from "../lib/format";
import { Chart, PALETTES, axisStyle } from "../components/Chart";
import { Card, Empty, Kpi, Loading, TableWrap, Time } from "../components/ui";

const uptime = (s?: number | null) => (s == null ? "—" : s >= 86400 ? `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h` : `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`);
const tone = (v?: number | null) => (v == null ? "" : v >= 85 ? "text-red-300 font-semibold" : v >= 70 ? "text-amber-300" : "");

export function FirewallHealth() {
  const g = useGlobal();
  const [range, setRange] = useState("24h");
  const fw = Array.isArray(g.params.firewall_id) ? g.params.firewall_id : [];
  const q = useQuery({ queryKey: ["fwhealth", range, fw], queryFn: () => api<any>("/fwhealth/overview", { params: { range, firewall_id: fw } }), refetchInterval: 60_000, placeholderData: (p) => p });
  const d = q.data;
  const t = d?.totals || {};
  return (
    <div className="space-y-4 min-w-0">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-xs text-muted flex-1 min-w-[16rem]">Resource use and stability from FortiGate performance-statistics event logs (both HA members), FortiAnalyzer connectivity,
          and whether every firewall is still sending each log type. Reboots are detected when uptime goes backwards.</p>
        <select aria-label="Range" className="input py-1" value={range} onChange={(e) => setRange(e.target.value)}>
          {[["1h", "Last hour"], ["24h", "Last 24 h"], ["7d", "Last 7 days"], ["30d", "Last 30 days"]].map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
      </div>
      <Loading q={q} />
      {d && <div className="kpi-grid">
        <Kpi label="Firewalls" value={fmtNum(t.firewalls)} />
        <Kpi label="High CPU now" value={fmtNum(t.high_cpu)} tone={t.high_cpu ? "bad" : "ok"} />
        <Kpi label="High memory now" value={fmtNum(t.high_mem)} tone={t.high_mem ? "bad" : "ok"} />
        <Kpi label="Reboots" value={fmtNum(t.reboots)} tone={t.reboots ? "warn" : "ok"} sub={`in ${range}`} />
        <Kpi label="Log feeds stopped" value={fmtNum(t.feed_gaps)} tone={t.feed_gaps ? "bad" : "ok"} />
        <Kpi label="FortiAnalyzer disconnects" value={fmtNum(t.faz_disconnects)} tone={t.faz_disconnects > 20 ? "warn" : undefined} />
      </div>}
      {d && !d.firewalls.length && <Empty text="No performance statistics logs yet. Forward FortiGate event logs (system) via syslog." />}
      {d?.firewalls.map((f: any) => <FirewallCard key={f.firewall_id} f={f} range={range} />)}
    </div>
  );
}

function FirewallCard({ f, range }: { f: any; range: string }) {
  const { theme } = useTheme();
  const ts = useQuery({ queryKey: ["fwhealth-ts", f.firewall_id, range], queryFn: () => api<any>(`/fwhealth/${f.firewall_id}/timeseries`, { params: { range } }) });
  const option = useMemo(() => {
    if (!ts.data) return null;
    const members: string[] = Array.from(new Set(ts.data.points.map((p: any) => p.member)));
    const fmt = (v: number) => new Date(v).toLocaleString(undefined, { hour: "2-digit", minute: "2-digit", month: range === "1h" || range === "24h" ? undefined : "short", day: range === "1h" || range === "24h" ? undefined : "2-digit", hour12: false, timeZone: getTimezone() });
    const series = members.flatMap((m, i) => [
      { name: `${m} CPU %`, type: "line", showSymbol: false, smooth: true, yAxisIndex: 0, itemStyle: { color: PALETTES[theme][i * 2 % 8] },
        data: ts.data.points.filter((p: any) => p.member === m).map((p: any) => [Date.parse(p.t), p.cpu]) },
      { name: `${m} memory %`, type: "line", showSymbol: false, smooth: true, yAxisIndex: 0, lineStyle: { type: "dashed" }, itemStyle: { color: PALETTES[theme][(i * 2 + 1) % 8] },
        data: ts.data.points.filter((p: any) => p.member === m).map((p: any) => [Date.parse(p.t), p.mem]) },
      { name: `${m} sessions`, type: "line", showSymbol: false, smooth: true, yAxisIndex: 1, lineStyle: { width: 1, opacity: 0.6 }, itemStyle: { color: "#9c9c9c" },
        data: ts.data.points.filter((p: any) => p.member === m).map((p: any) => [Date.parse(p.t), p.sessions]) },
    ]);
    return {
      legend: { top: 0, type: "scroll" },
      xAxis: { type: "time", ...axisStyle, axisLabel: { ...axisStyle.axisLabel, formatter: fmt } },
      yAxis: [{ type: "value", min: 0, max: 100, ...axisStyle, axisLabel: { ...axisStyle.axisLabel, formatter: "{value}%" } },
        { type: "value", ...axisStyle, splitLine: { show: false }, axisLabel: { ...axisStyle.axisLabel, formatter: (v: number) => fmtNum(v) } }],
      tooltip: { trigger: "axis", confine: true }, series,
    };
  }, [ts.data, theme, range]);
  return (
    <Card title={<span>{f.firewall_name}{f.site && <span className="text-muted font-normal text-xs"> · {f.site}</span>}</span>}
      right={<>{f.feed_gaps.length > 0 && <span className="pill bg-red-500/15 text-red-300">feeds stopped: {f.feed_gaps.join(", ")}</span>}
        {f.reboots.length > 0 && <span className="pill bg-amber-500/15 text-amber-300">{f.reboots.length} reboot(s)</span>}
        {f.faz && <span className={`pill ${f.faz.connected ? "bg-emerald-500/15 text-emerald-300" : "bg-red-500/15 text-red-300"}`}>FortiAnalyzer {f.faz.connected ? "connected" : "disconnected"} · {f.faz.disconnects} drops</span>}</>}>
      <div className="grid gap-4 xl:grid-cols-[1fr_24rem] min-w-0">
        <div className="min-w-0 space-y-3">
          {f.members.length > 0 && <TableWrap><table className="tbl"><thead><tr><th>Member</th><th className="num">CPU</th><th className="num">CPU p95 / max</th><th className="num">Memory</th>
            <th className="num">Mem max</th><th className="num">Sessions</th><th className="num">Setup rate</th><th className="num">Uptime</th><th>Last sample</th></tr></thead>
            <tbody>{f.members.map((m: any) => <tr key={m.member}><td className="font-mono text-xs">{m.member}</td>
              <td className={`num ${tone(m.cpu)}`}>{m.cpu ?? "—"}%</td><td className="num text-xs">{m.cpu_stats.p95 ?? "—"} / {m.cpu_stats.max ?? "—"}</td>
              <td className={`num ${tone(m.mem)}`}>{m.mem ?? "—"}%</td><td className="num text-xs">{m.mem_stats.max ?? "—"}%</td>
              <td className="num">{fmtNum(m.sessions)}</td><td className="num">{fmtNum(m.setuprate)}/s</td><td className="num">{uptime(m.uptime_s)}</td><td><Time v={m.last_sample} /></td></tr>)}</tbody></table></TableWrap>}
          {!f.members.length && <Empty text="No performance statistics from this firewall in the range." />}
          {ts.data?.points.length > 0 && option && <Chart option={option} height={230} ariaLabel={`CPU, memory and sessions for ${f.firewall_name}`} />}
        </div>
        <div className="space-y-3 min-w-0">
          <div><div className="text-2xs font-semibold uppercase tracking-wide text-muted mb-1">Log feeds (last 24 h)</div>
            <ul className="text-xs space-y-0.5">{f.feeds.map((x: any) => <li key={x.category} className="flex items-center gap-2">
              <span className={`h-2 w-2 rounded-full ${x.gap ? "bg-red-500" : x.silent_minutes > 10 ? "bg-amber-400" : "bg-emerald-400"}`} aria-hidden />
              <span className="w-16">{x.category}</span><span className="tabular-nums text-muted">{fmtNum(x.events_24h)}</span>
              <span className="ml-auto text-muted">{x.silent_minutes < 1 ? "live" : `silent ${x.silent_minutes.toFixed(0)} min`}</span></li>)}</ul></div>
          {f.reboots.length > 0 && <div><div className="text-2xs font-semibold uppercase tracking-wide text-muted mb-1">Reboots</div>
            <ul className="text-xs space-y-0.5">{f.reboots.map((b: any, i: number) => <li key={i}><Time v={b.boot_time} /> · {b.member}</li>)}</ul></div>}
          {f.notable.length > 0 && <div><div className="text-2xs font-semibold uppercase tracking-wide text-muted mb-1">Warnings & errors</div>
            <ul className="text-xs space-y-1">{f.notable.map((n: any) => <li key={n.log_id} title={n.sample}><b className="tabular-nums">{fmtNum(n.count)}×</b> {n.logdesc || n.sample}</li>)}</ul></div>}
        </div>
      </div>
    </Card>
  );
}
