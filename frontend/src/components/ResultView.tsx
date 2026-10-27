import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { useTheme } from "../lib/theme";
import { escHtml, fmtBytes, fmtCompact, fmtNum, fmtTime, getTimezone } from "../lib/format";
import { Chart, PALETTES, axisStyle } from "./Chart";
import { Donut, TopBar } from "./charts";
import { Empty, IpLink, TableWrap, Time } from "./ui";

/** Result of POST /api/search (pipeline query). */
export interface PipelineResult {
  kind: "events" | "table" | "timechart"; columns: string[]; rows: Record<string, any>[]; elapsed_ms: number; truncated: boolean;
  series?: string[]; span?: number; window?: { start: string; end: string };
}
export type Viz = "auto" | "table" | "line" | "area" | "bar" | "column" | "pie" | "kpi";
export const VIZ_OPTIONS: Viz[] = ["auto", "table", "line", "area", "bar", "column", "pie", "kpi"];

const TIME_COLS = /^(_time|event_time|ingest_time|first_seen|last_seen|earliest.*|latest_event_time)$/;
const BYTE_COLS = /(bytes|^sent$|^rcvd$|^received$|_sent$|_rcvd$|sent_|rcvd_)/;
const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]+:[0-9a-f:]+$/i;

const isNum = (v: unknown) => typeof v === "number" && Number.isFinite(v);
function numericCols(r: PipelineResult) {
  return r.columns.filter((c) => !TIME_COLS.test(c) && r.rows.length > 0 && r.rows.every((x) => x[c] == null || isNum(x[c])) && r.rows.some((x) => isNum(x[c])));
}
function labelCols(r: PipelineResult) {
  const nums = new Set(numericCols(r));
  return r.columns.filter((c) => !nums.has(c) && !TIME_COLS.test(c));
}

/** What "auto" renders: timecharts as lines, single-row aggregates as KPIs, small grouped tables as bars. */
export function autoViz(r: PipelineResult): Exclude<Viz, "auto"> {
  if (r.kind === "timechart") return "line";
  if (r.kind === "table") {
    const nums = numericCols(r);
    if (r.rows.length === 1 && nums.length && nums.length === r.columns.length) return "kpi";
    if (labelCols(r).length >= 1 && nums.length >= 1 && r.rows.length > 1 && r.rows.length <= 25) return "bar";
  }
  return "table";
}

export function Cell({ col, v }: { col: string; v: any }) {
  if (v === null || v === undefined || v === "") return <span className="text-slate-600">—</span>;
  if (Array.isArray(v)) return <span className="cell-wrap text-xs">{v.map((x) => String(x)).join(", ") || "—"}</span>;
  if (TIME_COLS.test(col) && typeof v === "string") return <Time v={v} />;
  if (isNum(v)) return <span title={BYTE_COLS.test(col) ? `${fmtNum(v)} bytes` : undefined}>{BYTE_COLS.test(col) ? fmtBytes(v) : fmtNum(v)}</span>;
  const s = String(v);
  if (/(^|_)ip$|^src$|^dst$|^client$/.test(col) && IP_RE.test(s)) return <IpLink ip={s} />;
  return <span className="cell-wrap">{s.length > 400 ? `${s.slice(0, 400)}…` : s}</span>;
}

export function ResultTable({ r, maxH }: { r: PipelineResult; maxH?: string }) {
  if (!r.rows.length) return <Empty text="The query returned no results." />;
  const nums = new Set(numericCols(r));
  return (
    <TableWrap maxH={maxH}>
      <table className="tbl">
        <thead><tr>{r.columns.map((c) => <th key={c} className={nums.has(c) ? "num" : ""}>{c}</th>)}</tr></thead>
        <tbody>{r.rows.map((row, i) => (
          <tr key={i}>{r.columns.map((c) => <td key={c} className={nums.has(c) ? "num" : c === "msg" ? "min-w-[16rem]" : ""}><Cell col={c} v={row[c]} /></td>)}</tr>
        ))}</tbody>
      </table>
    </TableWrap>
  );
}

function axisTime(ms: number, span: number) {
  const opts: Intl.DateTimeFormatOptions = span >= 86400 ? { month: "short", day: "2-digit" }
    : span >= 3600 ? { month: "short", day: "2-digit", hour: "2-digit", hour12: false } : { hour: "2-digit", minute: "2-digit", hour12: false };
  return new Date(ms).toLocaleString(undefined, { ...opts, timeZone: getTimezone() });
}

function TimeSeriesChart({ r, area, height }: { r: PipelineResult; area?: boolean; height: number }) {
  const { theme } = useTheme();
  const series = r.series?.length ? r.series : numericCols(r);
  const bytes = series.every((s) => BYTE_COLS.test(s));
  const option = useMemo(() => ({
    legend: { top: 0, type: "scroll" },
    xAxis: { type: "time", ...axisStyle, axisLabel: { ...axisStyle.axisLabel, formatter: (v: number) => axisTime(v, r.span || 60) } },
    yAxis: { type: "value", ...axisStyle, axisLabel: { ...axisStyle.axisLabel, formatter: (v: number) => (bytes ? fmtBytes(v) : fmtCompact(v)) } },
    tooltip: { trigger: "axis", confine: true, formatter: (ps: any[]) => !ps?.length ? "" : `<b>${fmtTime(new Date(ps[0].value[0]))}</b>` +
      ps.map((p) => `<br/>${p.marker}${escHtml(p.seriesName)}: <b>${bytes ? fmtBytes(p.value[1]) : Number(p.value[1]).toLocaleString()}</b>`).join("") },
    series: series.map((s, i) => ({
      name: s, type: "line", smooth: true, showSymbol: false, stack: area ? "a" : undefined, areaStyle: area ? { opacity: 0.25 } : undefined,
      itemStyle: { color: s === "OTHER" ? "#8f8f8f" : PALETTES[theme][i % 8] }, lineStyle: { width: 2 },
      data: r.rows.map((row) => [Date.parse(String(row._time).replace(" ", "T") + (/[zZ+]/.test(String(row._time).slice(19)) ? "" : "Z")), Number(row[s] || 0)]),
    })),
  }), [r, series, area, bytes, theme]);
  if (!r.rows.length) return <Empty text="The query returned no results." />;
  return <Chart height={height} option={option} />;
}

function ColumnChart({ r, label, value, height }: { r: PipelineResult; label: string; value: string; height: number }) {
  const { theme } = useTheme();
  const option = useMemo(() => ({
    grid: { left: 8, right: 16, top: 16, bottom: 8, containLabel: true },
    tooltip: { trigger: "axis", confine: true, axisPointer: { type: "shadow" } },
    xAxis: { type: "category", data: r.rows.map((x) => String(x[label] ?? "")), ...axisStyle, axisLabel: { ...axisStyle.axisLabel, rotate: r.rows.length > 8 ? 35 : 0 } },
    yAxis: { type: "value", ...axisStyle, axisLabel: { ...axisStyle.axisLabel, formatter: (v: number) => fmtCompact(v) } },
    series: [{ type: "bar", data: r.rows.map((x) => Number(x[value] || 0)), itemStyle: { color: PALETTES[theme][0], borderRadius: [4, 4, 0, 0] }, barMaxWidth: 28 }],
  }), [r, label, value, theme]);
  return <Chart height={height} option={option} />;
}

/** Renders a pipeline result as the requested visualisation, falling back to a table when the shape does not fit. */
export function ResultView({ r, viz = "auto", height = 260, maxH }: { r: PipelineResult; viz?: Viz; height?: number; maxH?: string }) {
  const nav = useNavigate();
  const v = viz === "auto" ? autoViz(r) : viz;
  if (!r.rows.length) return <Empty text="The query returned no results." />;
  const nums = numericCols(r);
  const labels = labelCols(r);
  if (v === "kpi") {
    const row = r.rows[0];
    const cols = nums.length ? nums : r.columns;
    return (
      <div className="flex flex-wrap gap-x-8 gap-y-2 items-end py-2">
        {cols.slice(0, 4).map((c) => (
          <div key={c} className="min-w-0">
            <div className="text-3xl font-extrabold tracking-tight tabular-nums text-slate-100">{isNum(row[c]) ? (BYTE_COLS.test(c) ? fmtBytes(row[c]) : fmtNum(row[c])) : String(row[c] ?? "—")}</div>
            {cols.length > 1 && <div className="text-2xs uppercase tracking-wide text-muted">{c}</div>}
          </div>
        ))}
      </div>
    );
  }
  if ((v === "line" || v === "area") && (r.kind === "timechart" || r.columns.includes("_time"))) return <TimeSeriesChart r={r} area={v === "area"} height={height} />;
  if ((v === "bar" || v === "column" || v === "pie") && labels.length && nums.length) {
    const label = labels[0];
    const value = nums[0];
    const rows = r.rows.map((x) => ({ ...x, [label]: x[label] === "" || x[label] == null ? "(empty)" : Array.isArray(x[label]) ? x[label].join(", ") : x[label] }));
    const clickIp = (k: any) => typeof k === "string" && IP_RE.test(k) && nav(`/investigate/${encodeURIComponent(k)}`);
    if (v === "pie") return <Donut rows={rows} keyField={label} valueField={value} height={height - 20} label={label} />;
    if (v === "column") return <ColumnChart r={{ ...r, rows }} label={label} value={value} height={height} />;
    return <TopBar rows={rows.slice(0, 30)} keyField={label} valueField={value} height={Math.max(height, Math.min(30, rows.length) * 22)}
      bytes={BYTE_COLS.test(value)} onClick={clickIp} />;
  }
  return <ResultTable r={r} maxH={maxH} />;
}
