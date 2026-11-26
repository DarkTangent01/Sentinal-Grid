/** Interface bandwidth display helpers (unit-tested in bandwidth.test.ts). Values arrive in bits per second; byte units
 *  divide by 8. Nothing here fills gaps: a null stays null so the chart shows the collection gap. */

export type Unit = "auto" | "Kbps" | "Mbps" | "Gbps" | "MB/s" | "GB/s";
export const UNITS: Unit[] = ["auto", "Kbps", "Mbps", "Gbps", "MB/s", "GB/s"];
const DIV: Record<Exclude<Unit, "auto">, number> = { Kbps: 1e3, Mbps: 1e6, Gbps: 1e9, "MB/s": 8e6, "GB/s": 8e9 };

/** The unit that keeps the largest value readable: Gbps from 1 Gbit/s, Mbps from 1 Mbit/s, else Kbps. */
export function autoUnit(maxBps: number | null | undefined): Exclude<Unit, "auto"> {
  const m = Math.abs(maxBps || 0);
  return m >= 1e9 ? "Gbps" : m >= 1e6 ? "Mbps" : "Kbps";
}

export function resolveUnit(u: Unit, maxBps: number | null | undefined): Exclude<Unit, "auto"> {
  return u === "auto" ? autoUnit(maxBps) : u;
}

export function inUnit(bps: number | null | undefined, u: Exclude<Unit, "auto">): number | null {
  return bps == null || !isFinite(bps) ? null : bps / DIV[u];
}

export function fmtIn(bps: number | null | undefined, u: Exclude<Unit, "auto">): string {
  const v = inUnit(bps, u);
  if (v == null) return "—";
  const a = Math.abs(v);
  return `${a >= 100 ? v.toFixed(0) : a >= 10 ? v.toFixed(1) : v.toFixed(2)} ${u}`;
}

export function fmtBytesTotal(b: number | null | undefined): string {
  if (b == null) return "—";
  const u = ["B", "KB", "MB", "GB", "TB", "PB"];
  let v = b, i = 0;
  while (Math.abs(v) >= 1000 && i < u.length - 1) { v /= 1000; i++; }
  return `${v >= 100 ? v.toFixed(0) : v.toFixed(1)} ${u[i]}`;
}

/** Comparison series moved onto the current window's time axis (so both lines share an x position). */
export function shifted(points: { t: string; [k: string]: unknown }[], shiftSeconds: number): { t: string; [k: string]: unknown }[] {
  return points.map((p) => ({ ...p, t: new Date(Date.parse(p.t) + shiftSeconds * 1000).toISOString() }));
}

/** The largest rate in the series (for the automatic unit). */
export function peakOf(points: any[], keys = ["rx_bps", "tx_bps", "rx_bps_max", "tx_bps_max"]): number {
  let m = 0;
  for (const p of points) for (const k of keys) if (typeof p[k] === "number" && p[k] > m) m = p[k];
  return m;
}

export const RANGE_OPTIONS: [string, string][] = [["15m", "Last 15 minutes"], ["1h", "Last hour"], ["6h", "Last 6 hours"], ["24h", "Last 24 hours"],
  ["7d", "Last 7 days"], ["30d", "Last 30 days"], ["90d", "Last 90 days"], ["365d", "Last year"], ["custom", "Custom…"]];

export const SOURCE_LABEL: Record<string, string> = { raw: "every poll (≈1 min)", "5m": "5-minute rollup", hourly: "hourly rollup" };
