// Pure helpers for the WAN pages (unit-tested in wan.test.ts).

/** Seconds → "1d 4h", "1h 38m", "2m 7s", "45s"; null → "—"; 0 → "0s". */
export function dur(s?: number | null): string {
  if (s == null) return "—";
  s = Math.round(s);
  if (s <= 0) return "0s";
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60), r = s % 60;
  if (d) return `${d}d ${h}h${m ? ` ${m}m` : ""}`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m${r ? ` ${r}s` : ""}`;
  return `${r}s`;
}

export const ms = (v?: number | null) => (v == null ? "—" : `${v.toFixed(v < 10 ? 2 : 1)} ms`);
export const pct = (v?: number | null, d = 2) => (v == null ? "—" : `${v.toFixed(d)}%`);
export const availText = (v?: number | null) => (v == null ? "—" : v === 100 ? "100%" : `${v.toFixed(3)}%`);

/** Worst-first order shared by every WAN table so status reads the same everywhere. */
export const STATE_ORDER: Record<string, number> = { down: 0, degraded: 1, unknown: 2, paused: 3, up: 4 };

/** Stacked daily series (one per ISP) → ECharts option parts; zero-incident days stay as 0, so the axis is continuous. */
export function stackedDaily(daily: { days: string[]; series: { isp: string; counts: number[]; sites: string[][] }[] }, colors: string[]) {
  return {
    categories: daily.days,
    series: daily.series.map((s, i) => ({
      name: s.isp, type: "bar", stack: "isp", barMaxWidth: 26, itemStyle: { color: colors[i % colors.length] },
      emphasis: { focus: "series" }, data: s.counts.map((v, j) => ({ value: v, sites: s.sites[j] || [] })),
    })),
    total: daily.series.reduce((a, s) => a + s.counts.reduce((x, y) => x + y, 0), 0),
  };
}

/** Datetime-local input value (viewer's browser time) ↔ ISO string. */
export function toLocalInput(iso?: string | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

export function rangeParams(r: { range: string; start?: string; end?: string }) {
  return r.range === "custom" && r.start && r.end ? { start: new Date(r.start).toISOString(), end: new Date(r.end).toISOString() } : { range: r.range === "custom" ? "24h" : r.range };
}
