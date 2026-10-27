import { useMemo, useState } from "react";
import { CHART_THEME, Chart, PALETTES, SERIES_ROLE, axisStyle, seriesColor } from "./Chart";
import { useTheme } from "../lib/theme";
import { escHtml, fmtBytes, fmtCompact, fmtTime, getTimezone } from "../lib/format";
import { fmtPct, sumKey, toTimePairs, topNWithOther } from "../lib/chartData";
import { Empty } from "./ui";

function axisTime(ms: number, bucket: number) {
  const opts: Intl.DateTimeFormatOptions = bucket >= 86400 ? { month: "short", day: "2-digit" }
    : bucket >= 3600 ? { month: "short", day: "2-digit", hour: "2-digit", hour12: false }
    : { hour: "2-digit", minute: "2-digit", hour12: false };
  return new Date(ms).toLocaleString(undefined, { ...opts, timeZone: getTimezone() });
}

export interface TimeSeries { bucket_seconds: number; points: any[]; data_start?: string | null }

/** Time-axis chart over zero-filled server buckets. Buckets before the first collected event are shaded as
 *  "not collected" so that a missing collection period is never read as zero activity. */
export function TimeChart({ data, series, stack, bytes, height = 240, area, loading }: {
  /** color: a SeriesRole ("primary" | "alert" | "warn" | "muted") or a hex; omitted = next categorical slot */
  data?: TimeSeries; series: { key: string; name: string; color?: string; dashed?: boolean }[];
  stack?: boolean; bytes?: boolean; height?: number; area?: boolean; loading?: boolean;
}) {
  const { theme } = useTheme();
  const option = useMemo(() => {
    const pts = data?.points || [];
    const b = data?.bucket_seconds || 60;
    const first = pts.length ? toTimePairs(pts, series[0].key)[0][0] : 0;
    const startMs = data?.data_start ? Date.parse(data.data_start) : null;
    const showGap = startMs !== null && pts.length > 0 && startMs > first;
    return {
      legend: { top: 0 },
      xAxis: { type: "time", ...axisStyle, axisLabel: { ...axisStyle.axisLabel, formatter: (v: number) => axisTime(v, b) } },
      yAxis: { type: "value", ...axisStyle, minInterval: bytes ? undefined : 1,
        axisLabel: { ...axisStyle.axisLabel, formatter: (v: number) => (bytes ? fmtBytes(v) : fmtCompact(v)) } },
      tooltip: { trigger: "axis", confine: true,
        formatter: (ps: any[]) => {
          if (!ps?.length) return "";
          const t = ps[0].value[0];
          const head = `<b>${fmtTime(new Date(t))}</b>${b >= 60 ? ` (+${b >= 3600 ? `${b / 3600}h` : `${b / 60}m`})` : ""}`;
          const note = showGap && t < (startMs as number) ? "<br/><i>before collection started</i>" : "";
          return head + ps.map((p) => `<br/>${p.marker}${escHtml(p.seriesName)}: <b>${bytes ? fmtBytes(p.value[1]) : Number(p.value[1]).toLocaleString()}</b>`).join("") + note;
        } },
      series: series.map((s, i) => ({
        name: s.name, type: stack ? "bar" : "line", stack: stack ? "a" : undefined, smooth: !stack, showSymbol: false,
        barMaxWidth: 24, areaStyle: area ? { opacity: 0.12 } : undefined, itemStyle: { color: seriesColor(theme, s.color, i) },
        lineStyle: { width: 2, type: s.dashed ? "dashed" : "solid" },
        data: toTimePairs(pts, s.key),
        markArea: i === 0 && showGap ? { silent: true, itemStyle: { color: "rgba(148,163,184,0.08)" },
          label: { show: true, color: CHART_THEME[theme].text, fontSize: 10, position: "insideTop" },
          data: [[{ name: "not collected", xAxis: first }, { xAxis: startMs }]] } : undefined,
      })),
    };
  }, [data, series, stack, bytes, area, theme]);

  const total = data ? series.reduce((a, s) => a + sumKey(data.points, s.key), 0) : 0;
  if (loading && !data) return <div style={{ height }} className="animate-pulse bg-slate-800/30 rounded" />;
  // zero can be genuine for one metric (e.g. denied sessions carry 0 bytes), so say which metric is empty
  if (data && total === 0) return <div style={{ height }} className="flex items-center justify-center"><Empty text={`No ${bytes ? "bytes" : series.map((s) => s.name.toLowerCase()).join(" / ")} recorded in the selected time range.`} /></div>;
  return <Chart height={height} option={option} />;
}

export function TopBar({ rows, keyField = "key", valueField = "value", height = 260, onClick, bytes, labelFn }: {
  rows?: any[]; keyField?: string; valueField?: string; height?: number; onClick?: (key: any) => void; bytes?: boolean;
  labelFn?: (r: any) => string;
}) {
  const { theme } = useTheme();
  const r = useMemo(() => [...(rows || [])].reverse(), [rows]);
  const option = useMemo(() => ({
    grid: { left: 8, right: 24, top: 8, bottom: 8, containLabel: true },
    tooltip: { trigger: "axis", confine: true, axisPointer: { type: "shadow" }, valueFormatter: (v: number) => (bytes ? fmtBytes(v) : Number(v).toLocaleString()) },
    xAxis: { type: "value", ...axisStyle, axisLabel: { ...axisStyle.axisLabel, formatter: (v: number) => (bytes ? fmtBytes(v) : fmtCompact(v)) } },
    yAxis: { type: "category", data: r.map((x) => (labelFn ? labelFn(x) : String(x[keyField]))), ...axisStyle,
      axisLabel: { color: CHART_THEME[theme].strong, width: 150, overflow: "truncate", fontFamily: "monospace", fontSize: 11 } },
    series: [{ type: "bar", data: r.map((x) => Number(x[valueField] || 0)), itemStyle: { color: SERIES_ROLE[theme].primary, borderRadius: [0, 4, 4, 0] }, barMaxWidth: 16 }],
  }), [r, keyField, valueField, bytes, labelFn, theme]);
  return <Chart height={height} onClick={onClick ? (p) => onClick(r[p.dataIndex]?.[keyField]) : undefined} option={option} />;
}

/** Donut with top-N + "Other" grouping, percentages of the displayed total, and a full breakdown table. */
export function Donut({ rows, keyField = "key", valueField = "events", height = 240, onClick, max = 8, label = "Category" }: {
  rows?: any[]; keyField?: string; valueField?: string; height?: number; onClick?: (k: any) => void; max?: number; label?: string;
}) {
  const [showAll, setShowAll] = useState(false);
  const { theme } = useTheme();
  const all = useMemo(() => (rows || []).map((x) => ({ key: String(x[keyField]), value: Number(x[valueField] || 0) })), [rows, keyField, valueField]);
  const { slices, total } = useMemo(() => topNWithOther(all, max), [all, max]);
  const option = useMemo(() => ({
    tooltip: { trigger: "item", confine: true, formatter: (p: any) => `${p.marker}${escHtml(p.name)}<br/><b>${Number(p.value).toLocaleString()}</b> (${fmtPct(slices[p.dataIndex]?.pct ?? 0)})` },
    legend: { show: false },
    series: [{ type: "pie", radius: ["50%", "78%"], center: ["50%", "50%"], avoidLabelOverlap: true, label: { show: false },
      itemStyle: { borderColor: CHART_THEME[theme].surface, borderWidth: 2 },
      data: slices.map((s) => ({ name: s.name, value: s.value })) }],
    graphic: [{ type: "text", left: "center", top: "middle", style: { text: fmtCompact(total), fill: CHART_THEME[theme].strong, fontSize: 16, fontWeight: 600 } }],
  }), [slices, total, theme]);
  if (!total) return <Empty />;
  const colors = PALETTES[theme];
  const hasOther = slices.some((s) => s.members);
  return (
    <div className="min-w-0 space-y-3">
      <div className="flex flex-col sm:flex-row gap-3 min-w-0">
        <div className="sm:w-2/5 min-w-0"><Chart height={height} ariaLabel={`${label} distribution`} option={option}
          onClick={onClick ? (p) => !slices[p.dataIndex]?.members && onClick(slices[p.dataIndex]?.name) : undefined} /></div>
        <ul className="sm:w-3/5 min-w-0 text-xs space-y-1 self-center">
          {slices.map((s, i) => (
            <li key={s.name} className="flex items-center gap-2 min-w-0" title={s.members ? s.members.join(", ") : s.name}>
              <span className="w-2.5 h-2.5 rounded-sm shrink-0" style={{ background: colors[i % colors.length] }} aria-hidden />
              {onClick && !s.members ? <button className="link truncate min-w-0" onClick={() => onClick(s.name)}>{s.name}</button>
                : <span className="truncate min-w-0">{s.name}</span>}
              <span className="ml-auto tabular-nums text-muted shrink-0">{s.value.toLocaleString()} · {fmtPct(s.pct)}</span>
            </li>
          ))}
          {hasOther && <li><button className="link" onClick={() => setShowAll(!showAll)}>{showAll ? "Hide" : "Show"} all {all.length} values</button></li>}
        </ul>
      </div>
      {showAll && <FullBreakdown all={all} total={total} label={label} onClick={onClick} />}
    </div>
  );
}

function FullBreakdown({ all, total, label, onClick }: { all: { key: string; value: number }[]; total: number; label: string; onClick?: (k: any) => void }) {
  const sorted = [...all].sort((a, b) => b.value - a.value);
  return (
    <div className="tbl-wrap max-h-64 overflow-y-auto sm:w-full">
      <table className="tbl"><thead><tr><th>{label}</th><th className="num">Events</th><th className="num">Share</th></tr></thead>
        <tbody>{sorted.map((r) => <tr key={r.key}><td className="cell-wrap">{onClick ? <button className="link" onClick={() => onClick(r.key)}>{r.key}</button> : r.key}</td>
          <td className="num">{r.value.toLocaleString()}</td><td className="num">{fmtPct(total ? (r.value / total) * 100 : 0)}</td></tr>)}</tbody></table>
    </div>
  );
}
