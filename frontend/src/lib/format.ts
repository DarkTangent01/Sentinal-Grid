/** Escape text for ECharts tooltip formatters: a formatter's return value is inserted as HTML, unescaped. */
export function escHtml(v: unknown): string {
  return String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);
}

export function fmtNum(n: unknown): string {
  const v = Number(n ?? 0);
  if (!isFinite(v)) return "—";
  return v.toLocaleString();
}

export function fmtCompact(n: unknown): string {
  const v = Number(n ?? 0);
  return Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(v);
}

export function fmtBytes(n: unknown): string {
  let v = Number(n ?? 0);
  const u = ["B", "KB", "MB", "GB", "TB", "PB"];
  let i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v < 10 && i > 0 ? 2 : v < 100 && i > 0 ? 1 : 0)} ${u[i]}`;
}

let tz = "UTC";
export function setTimezone(z: string) { tz = z || "UTC"; }
export function getTimezone() { return tz; }

export function toDate(v: unknown): Date | null {
  if (!v) return null;
  let s = String(v);
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}/.test(s)) s = s.replace(" ", "T") + "Z";
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d;
}

export function fmtTime(v: unknown, withSeconds = true): string {
  const d = toDate(v);
  if (!d) return "—";
  return d.toLocaleString(undefined, { timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit",
    minute: "2-digit", second: withSeconds ? "2-digit" : undefined, hour12: false });
}

/** Compact table timestamp: time only for today, otherwise date + time. */
export function fmtTimeShort(v: unknown): string {
  const d = toDate(v);
  if (!d) return "—";
  const day = (x: Date) => x.toLocaleDateString("en-CA", { timeZone: tz });
  const sameDay = day(d) === day(new Date());
  return d.toLocaleString(undefined, { timeZone: tz, hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit",
    ...(sameDay ? {} : { month: "short", day: "2-digit" }) });
}

export function fmtAgo(v: unknown): string {
  const d = toDate(v);
  if (!d) return "never";
  const s = Math.round((Date.now() - d.getTime()) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export function fmtDuration(sec: unknown): string {
  const s = Number(sec ?? 0);
  if (s < 60) return `${s.toFixed(0)}s`;
  if (s < 3600) return `${(s / 60).toFixed(1)}m`;
  return `${(s / 3600).toFixed(1)}h`;
}

export const ACTION_COLORS: Record<string, string> = {
  accept: "text-emerald-400", close: "text-emerald-400", timeout: "text-emerald-300", reset: "text-amber-300", allow: "text-emerald-400",
  deny: "text-red-400", block: "text-red-400", monitor: "text-sky-300", other: "text-slate-400",
};

export function fmtPct0(p: number): string {
  if (!isFinite(p)) return "—";
  return `${p.toFixed(p < 10 ? 1 : 0)}%`;
}
