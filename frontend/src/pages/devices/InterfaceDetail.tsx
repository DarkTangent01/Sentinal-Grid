/** Interface monitoring page: Device → Interface → bandwidth history → statistics → alerts. Every figure comes from
 *  stored samples (/api/devices/{id}/interfaces/{ifindex}/bandwidth); gaps stay gaps. */
import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { useMe } from "../../lib/context";
import { escHtml, fmtNum, fmtTime, getTimezone } from "../../lib/format";
import { useTheme } from "../../lib/theme";
import { Chart, PALETTES, SERIES_ROLE, axisStyle } from "../../components/Chart";
import { Card, Empty, Loading, Sev, StatStrip, TableWrap, Time } from "../../components/ui";
import { EventTable } from "../switches/SwitchesPage";
import { Bps, Flags, KV, Oper, SeriesChart } from "../switches/common";
import { RANGE_OPTIONS, SOURCE_LABEL, UNITS, Unit, fmtBytesTotal, fmtIn, inUnit, peakOf, resolveUnit, shifted } from "./bandwidth";

const COMPARE: [string, string][] = [["", "No comparison"], ["previous", "Previous period"], ["day", "Same time yesterday"], ["week", "Same time last week"]];

export function InterfaceDetail() {
  const { id, ifindex } = useParams();
  const sid = Number(id), ifx = Number(ifindex);
  const [range, setRange] = useState("24h");
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [unit, setUnit] = useState<Unit>("auto");
  const [compare, setCompare] = useState("");
  const custom = range === "custom";
  const params = custom ? (start && end ? { start: new Date(start).toISOString(), end: new Date(end).toISOString() } : null) : { range };
  const q = useQuery<any>({ queryKey: ["if-bw", sid, ifx, params, compare], enabled: !!params, placeholderData: (p: any) => p, refetchInterval: custom ? false : 60_000,
    queryFn: () => api(`/devices/${sid}/interfaces/${ifx}/bandwidth`, { params: { ...params, compare: compare || undefined } }) });
  // overview, VLANs, LAG, alerts and events of the interface (existing endpoint)
  const info = useQuery<any>({ queryKey: ["switch-ifd", sid, ifx, "1h"], queryFn: () => api(`/switches/${sid}/interfaces/${ifx}`, { params: { range: "1h" } }),
    refetchInterval: 60_000 });
  const d = q.data;
  const x = d?.interface || info.data?.interface;
  const pts = d?.series?.points || [];
  const cmp = d?.compare;
  const cpts = useMemo(() => cmp ? shifted(cmp.series.points, cmp.shift_seconds) : [], [cmp]);
  const u = resolveUnit(unit, Math.max(peakOf(pts), peakOf(cpts)));
  return <div className="space-y-4 min-w-0">
    <nav className="text-xs text-muted flex flex-wrap items-center gap-1.5" aria-label="Breadcrumb">
      <Link to="/switches?tab=inventory" className="link">Devices</Link><span>/</span>
      <Link to={`/switches/${sid}`} className="link">{d?.device?.name || info.data?.switch?.name || `#${sid}`}</Link><span>/</span>
      <Link to={`/switches/${sid}?tab=interfaces`} className="link">Interfaces</Link><span>/</span><span className="text-slate-200">{x?.name || ifx}</span>
    </nav>
    {x && <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
      <h1 className="page-title">{x.name}</h1>{x.alias && <span className="text-muted">{x.alias}</span>}
      <Oper s={x.oper} /><span className="text-xs text-muted">admin {x.admin || "—"} · {x.speed_bps ? <Bps v={x.speed_bps} /> : "speed unknown"} · {x.kind}
        {x.mtu ? ` · MTU ${x.mtu}` : ""} · {x.hc_counters ? "64-bit counters" : "32-bit counters"}</span>
      {d?.current?.stale && <span className="text-xs text-amber-300" title="The device has not been polled successfully for three intervals">stale: last sample <Time v={d.current.at} /></span>}
      {x.monitored === false && <span className="pill text-muted">alerts off</span>}
    </div>}
    <div className="flex flex-wrap items-center gap-2">
      <select aria-label="Time range" className="input py-1" value={range} onChange={(e) => setRange(e.target.value)}>{RANGE_OPTIONS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
      {custom && <><input aria-label="Start" type="datetime-local" className="input py-1" value={start} onChange={(e) => setStart(e.target.value)} />
        <span className="text-subtle">→</span><input aria-label="End" type="datetime-local" className="input py-1" value={end} onChange={(e) => setEnd(e.target.value)} /></>}
      <select aria-label="Compare" className="input py-1" value={compare} onChange={(e) => setCompare(e.target.value)}>{COMPARE.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
      <select aria-label="Unit" className="input py-1" value={unit} onChange={(e) => setUnit(e.target.value as Unit)}>{UNITS.map((k) => <option key={k} value={k}>{k === "auto" ? `Unit: auto (${u})` : k}</option>)}</select>
      {d && <span className="text-xs text-subtle ml-auto">Resolution: {SOURCE_LABEL[d.series.source] || d.series.source} · times in {getTimezone()}</span>}
    </div>
    {custom && !params && <p className="text-xs text-muted">Choose a start and an end.</p>}
    <Loading q={q} />
    {q.error && <div role="alert" className="text-sm text-red-400">{(q.error as Error).message}</div>}
    {d && <>
      <Card title="Bandwidth">
        {!pts.length ? <Empty text="No historical data available yet for this range." /> : <BandwidthChart pts={pts} cpts={cpts} unit={u} bucket={d.series.bucket_seconds} cmpLabel={COMPARE.find(([k]) => k === compare)?.[1]} />}
        <Stats s={d.stats} c={cmp?.stats} cur={d.current} unit={u} speed={x?.speed_bps} />
      </Card>
      <div className="grid gap-3 lg:grid-cols-2">
        <Card title="Utilisation (peak per interval)">{x?.speed_bps ? <SeriesChart points={pts} unit="pct" yMax={100} bucket={d.series.bucket_seconds} height={200}
          series={[{ key: "rx_util", name: "Inbound %" }, { key: "tx_util", name: "Outbound %" }]} /> : <Empty text="No reliable interface speed: utilisation is not calculated." />}</Card>
        <Card title="Errors and discards (per interval)"><SeriesChart points={pts} unit="count" bucket={d.series.bucket_seconds} height={200}
          series={[{ key: "errors", name: "Errors", bar: true, color: "alert" }, { key: "discards", name: "Discards", bar: true, color: "muted" }]} /></Card>
      </div>
    </>}
    <div className="grid gap-3 lg:grid-cols-2 items-start">
      <Card title="Interface">{x && <KV rows={[["Device", d?.device?.name || info.data?.switch?.name], ["Description", x.alias || "—"], ["ifDescr", x.descr || "—"],
        ["Type", `${x.kind} · ifType ${x.type ?? "—"}`], ["Speed", x.speed_bps ? <><Bps v={x.speed_bps} /> <span className="text-subtle">({x.speed_source})</span></> : "unknown"],
        ["Duplex", x.duplex || "—"], ["MTU", x.mtu ?? "—"], ["MAC", <span className="mono">{x.mac || "—"}</span>],
        ["VLANs", info.data ? `${x.mode || "—"}${info.data.vlans.untagged.length ? ` · untagged ${info.data.vlans.untagged.join(", ")}` : ""}${info.data.vlans.tagged.length ? ` · tagged ${info.data.vlans.tagged.slice(0, 20).join(", ")}${info.data.vlans.tagged.length > 20 ? "…" : ""}` : ""}` : "—"],
        ["LAG", info.data?.lag ? `${info.data.lag.name}: ${info.data.lag.up_members}/${info.data.lag.total_members} members in bundle` : x.lag_ifindex ? `member of ifIndex ${x.lag_ifindex}` : "—"],
        ["ifIndex", x.ifindex], ["Last state change", <Time v={x.last_change_at} />], ["Last sample", <><Time v={x.last_sample_at} /> <Flags f={x.flags} /></>]]} />}</Card>
      <Thresholds sid={sid} ifx={ifx} x={x} />
    </div>
    {info.data && <Card title={`Alerts (${info.data.alerts.length})`} bodyClass="p-0">{!info.data.alerts.length ? <div className="p-4"><Empty text="No alerts for this interface." /></div> :
      <TableWrap><table className="tbl"><tbody>{info.data.alerts.map((a: any) => <tr key={a.id}><td className="nowrap"><Sev s={a.severity} /></td><td>{a.name}</td><td>{a.status}</td>
        <td><Time v={a.last_seen} /></td><td className="text-xs cell-wrap">{a.explanation}</td></tr>)}</tbody></table></TableWrap>}</Card>}
    {info.data && <Card title={`State changes and events (${info.data.events.length})`}><EventTable rows={info.data.events} showSwitch={false} /></Card>}
  </div>;
}

function BandwidthChart({ pts, cpts, unit, bucket, cmpLabel }: { pts: any[]; cpts: any[]; unit: Exclude<Unit, "auto">; bucket: number; cmpLabel?: string }) {
  const { theme } = useTheme();
  const option = useMemo(() => {
    const line = (name: string, data: any[], key: string, color: string, dashed = false, area = false) => ({
      name, type: "line", showSymbol: false, connectNulls: false, data: data.map((p) => [Date.parse(p.t), inUnit(p[key], unit)]),
      itemStyle: { color }, lineStyle: { width: dashed ? 1 : 1.5, type: dashed ? "dashed" : "solid" }, areaStyle: area ? { opacity: 0.06 } : undefined });
    const pal = PALETTES[theme];
    const series = [line("Inbound", pts, "rx_bps", SERIES_ROLE[theme].primary, false, true), line("Outbound", pts, "tx_bps", pal[1], false, true)];
    if (cpts.length) series.push(line(`Inbound · ${cmpLabel}`, cpts, "rx_bps", SERIES_ROLE[theme].muted, true), line(`Outbound · ${cmpLabel}`, cpts, "tx_bps", pal[3], true));
    return {
      legend: { top: 0, type: "scroll", itemWidth: 10, itemHeight: 8, textStyle: { fontSize: 11 } }, grid: { left: 64, right: 16, top: 32, bottom: 28 },
      xAxis: { type: "time", ...axisStyle, axisLabel: { ...axisStyle.axisLabel, formatter: (v: number) => new Date(v).toLocaleString(undefined, {
        hour: "2-digit", minute: "2-digit", hour12: false, timeZone: getTimezone(), ...(bucket >= 3600 ? { month: "short", day: "2-digit" } : {}) }) } },
      yAxis: { type: "value", min: 0, ...axisStyle, axisLabel: { ...axisStyle.axisLabel, formatter: (v: number) => `${v} ${unit}` } },
      tooltip: { trigger: "axis", confine: true, formatter: (ps: any[]) => !ps?.length ? "" : `<b>${fmtTime(new Date(ps[0].value[0]))}</b>` +
        ps.map((p) => `<br/>${p.marker}${escHtml(p.seriesName)}: <b>${p.value[1] == null ? "no sample" : `${Number(p.value[1]).toFixed(2)} ${unit}`}</b>`).join("") },
      series,
    };
  }, [pts, cpts, unit, bucket, theme, cmpLabel]);
  return <Chart height={280} option={option} ariaLabel="Inbound and outbound bandwidth over time" />;
}

function Stats({ s, c, cur, unit, speed }: { s: any; c?: any; cur: any; unit: Exclude<Unit, "auto">; speed?: number }) {
  if (!s) return null;
  const f = (v: any) => fmtIn(v, unit);
  const rows: [string, string, string, string?][] = [
    ["Current", f(cur?.rx_bps), f(cur?.tx_bps)], ["Average", f(s.rx.avg), f(s.tx.avg), c ? `${f(c.rx.avg)} / ${f(c.tx.avg)}` : undefined],
    ["Peak", f(s.rx.max), f(s.tx.max), c ? `${f(c.rx.max)} / ${f(c.tx.max)}` : undefined], ["Minimum", f(s.rx.min), f(s.tx.min)],
    ["95th percentile", f(s.rx.p95), f(s.tx.p95), c ? `${f(c.rx.p95)} / ${f(c.tx.p95)}` : undefined],
    ["Data transferred", fmtBytesTotal(s.rx.bytes), fmtBytesTotal(s.tx.bytes), c ? `${fmtBytesTotal(c.rx.bytes)} / ${fmtBytesTotal(c.tx.bytes)}` : undefined],
    ["Peak utilisation", s.rx.util_max != null ? `${s.rx.util_max.toFixed(1)}%` : "—", s.tx.util_max != null ? `${s.tx.util_max.toFixed(1)}%` : "—"],
  ];
  return <div className="mt-3 space-y-2">
    <TableWrap><table className="tbl"><thead><tr><th></th><th className="num">Inbound</th><th className="num">Outbound</th>{c && <th className="num">Comparison (in / out)</th>}</tr></thead>
      <tbody>{rows.map(([k, a, b, cc]) => <tr key={k}><td className="text-muted">{k}</td><td className="num">{a}</td><td className="num">{b}</td>{c && <td className="num text-muted">{cc ?? ""}</td>}</tr>)}</tbody></table></TableWrap>
    <StatStrip items={[["Capacity", speed ? fmtIn(speed, speed >= 1e9 ? "Gbps" : "Mbps") : "unknown"], ["Errors in / out", `${fmtNum(s.errors.in)} / ${fmtNum(s.errors.out)}`],
      ["Discards in / out", `${fmtNum(s.discards.in)} / ${fmtNum(s.discards.out)}`], ["Valid samples", `${fmtNum(s.rated_samples)} of ${fmtNum(s.samples)}`]]} />
    <p className="text-2xs text-subtle">95th percentile over {s.p95_basis}; data transferred {s.bytes_basis}. Samples across a counter reset or device restart are excluded, never estimated.</p>
  </div>;
}

function Thresholds({ sid, ifx, x }: { sid: number; ifx: number; x: any }) {
  const me = useMe();
  const qc = useQueryClient();
  const admin = me.role === "admin";
  const [v, setV] = useState<Record<string, string> | null>(null);
  const cur = v ?? { util_warn_pct: String(x?.thresholds?.util_warn_pct ?? ""), util_high_pct: String(x?.thresholds?.util_high_pct ?? ""),
    util_crit_pct: String(x?.thresholds?.util_crit_pct ?? "") };
  const save = useMutation({ mutationFn: (body: any) => api(`/devices/${sid}/interfaces/${ifx}`, { method: "PATCH", body }),
    onSuccess: () => { setV(null); qc.invalidateQueries({ queryKey: ["if-bw", sid, ifx] }); qc.invalidateQueries({ queryKey: ["switch-ifd", sid, ifx] }); } });
  if (!x) return null;
  const th = Object.fromEntries(Object.entries(cur).filter(([, s]) => s !== "").map(([k, s]) => [k, Number(s)]));
  return <Card title="Alert thresholds">
    <p className="text-xs text-muted mb-3">Utilisation alerts need three consecutive valid samples at or above a level. Empty uses the device, template or global value
      (warning 70%, high 85%, critical 95%).</p>
    <div className="grid grid-cols-3 gap-2">{([["util_warn_pct", "Warning %"], ["util_high_pct", "High %"], ["util_crit_pct", "Critical %"]] as const).map(([k, l]) =>
      <label key={k}><span className="label">{l}</span><input className="input w-full" inputMode="numeric" disabled={!admin} placeholder="inherit" value={cur[k]}
        onChange={(e) => setV({ ...cur, [k]: e.target.value.replace(/[^0-9.]/g, "") })} /></label>)}</div>
    <label className="mt-3 flex items-center gap-2 text-sm"><input type="checkbox" disabled={!admin || save.isPending} checked={x.monitored !== false}
      onChange={(e) => save.mutate({ monitored: e.target.checked })} /> Alert on this interface</label>
    {admin && <div className="mt-3 flex items-center gap-2"><button className="btn btn-primary btn-sm" disabled={save.isPending || v === null}
      onClick={() => save.mutate({ thresholds: th })}>{save.isPending ? "Saving…" : "Save thresholds"}</button>
      {save.error && <span className="text-xs text-red-400">{(save.error as Error).message}</span>}</div>}
  </Card>;
}
