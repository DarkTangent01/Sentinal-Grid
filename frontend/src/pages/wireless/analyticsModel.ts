/** Pure helpers for the historical client analytics sections (no React): filter → API params, chart pivots. */

export type Period = "day" | "week" | "month";
export const METRICS: [string, string][] = [["unique_clients", "Unique clients"], ["sessions", "Sessions"], ["peak_clients", "Peak concurrent"],
  ["avg_clients", "Average concurrent"]];

export interface AnalyticsFilters {
  start: string; end: string; period: Period;
  controller?: string; site?: string; ssid?: string; ap?: string; band?: string;
}

/** Calendar date (YYYY-MM-DD) in a timezone, `offsetDays` from today. */
export function dayIn(tz: string, offsetDays = 0, now: Date = new Date()): string {
  const d = new Date(now.getTime() + offsetDays * 86_400_000);
  return d.toLocaleDateString("en-CA", { timeZone: tz || "UTC" });
}

/** Default range per view: 7 days of days, 12 weeks of weeks, 6 months of months (all ending today). */
export function defaultRange(period: Period, tz: string, now: Date = new Date()): { start: string; end: string } {
  const end = dayIn(tz, 0, now);
  const back = period === "week" ? 7 * 12 - 1 : period === "month" ? 183 : 6;
  return { start: dayIn(tz, -back, now), end };
}

export function toParams(f: AnalyticsFilters): Record<string, string | undefined> {
  return { start_date: f.start, end_date: f.end, period: f.period, controller_id: f.controller || undefined, site: f.site || undefined,
    ssid: f.ssid || undefined, ap_id: f.ap || undefined, frequency_band: f.band || undefined };
}

/** Rows {day, <key>, <metric>} → categories (sorted periods) and one series per key (top `max` keys by total). Periods
 *  where a key has no row stay null (not collected / no clients), never a fabricated zero. */
export function pivot(rows: any[], key: string, metric: string, max = 8, label?: (r: any) => string) {
  const days = [...new Set(rows.map((r) => r.day))].sort();
  const tot = new Map<string, number>();
  const names = new Map<string, string>();
  for (const r of rows) {
    const k = String(r[key]);
    tot.set(k, (tot.get(k) || 0) + Number(r[metric] || 0));
    if (label) names.set(k, label(r));
  }
  const keys = [...tot.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, max).map(([k]) => k);
  const series = keys.map((k) => {
    const byDay = new Map(rows.filter((r) => String(r[key]) === k).map((r) => [r.day, r]));
    return { key: k, name: names.get(k) || k, data: days.map((d) => (byDay.has(d) ? Number(byDay.get(d)[metric]) : null)),
      rows: days.map((d) => byDay.get(d) || null) };
  });
  return { days, series };
}

/** "2026-11-10" → short label in the chosen view. */
export function periodLabel(day: string, period: Period): string {
  const d = new Date(`${day}T00:00:00Z`);
  if (period === "month") return d.toLocaleDateString(undefined, { month: "short", year: "numeric", timeZone: "UTC" });
  const s = d.toLocaleDateString(undefined, { month: "short", day: "2-digit", timeZone: "UTC" });
  return period === "week" ? `wk of ${s}` : s;
}

export const hourLabel = (h: number) => `${String(h).padStart(2, "0")}:00`;
