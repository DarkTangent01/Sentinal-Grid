// Pure helpers for the Sentinel NMS analytics and operations pages (tested in nms.test.ts).

export type Tone = "ok" | "warn" | "bad" | undefined;

/** Seconds → "3d 4h", "2h 05m", "45m", "12s"; null → "—". */
export function fmtDur(s: number | null | undefined): string {
  if (s == null || !isFinite(s)) return "—";
  const v = Math.max(0, Math.round(s));
  if (v < 60) return `${v}s`;
  if (v < 3600) return `${Math.floor(v / 60)}m`;
  if (v < 86400) return `${Math.floor(v / 3600)}h ${String(Math.floor((v % 3600) / 60)).padStart(2, "0")}m`;
  return `${Math.floor(v / 86400)}d ${Math.floor((v % 86400) / 3600)}h`;
}

/** Availability with enough decimals to tell 99.9 from 99.99; null (never measured) → "—", never "0%". */
export function fmtAvail(p: number | null | undefined): string {
  if (p == null) return "—";
  if (p >= 99.995) return "100%";
  return `${p >= 99 ? p.toFixed(3) : p.toFixed(2)}%`;
}

export function availTone(p: number | null | undefined, sla: number): Tone {
  if (p == null) return undefined;
  return p >= sla ? "ok" : p >= sla - 0.5 ? "warn" : "bad";
}

/** Capacity forecast: 0 → "now", null → "not on current trend". */
export function fmtDaysLeft(d: number | null | undefined): string {
  if (d == null) return "not on current trend";
  if (d <= 0) return "now (over threshold)";
  if (d < 1) return "< 1 day";
  return d >= 365 ? "> 1 year" : `${Math.round(d)} day${Math.round(d) === 1 ? "" : "s"}`;
}

export function daysTone(d: number | null | undefined): Tone {
  if (d == null) return undefined;
  return d <= 7 ? "bad" : d <= 30 ? "warn" : "ok";
}

export const GRADE_TONE: Record<string, Tone> = { healthy: "ok", fair: "warn", poor: "bad", critical: "bad", paused: undefined };

export function scoreTone(score: number | null | undefined): Tone {
  if (score == null) return undefined;
  return score >= 90 ? "ok" : score >= 70 ? "warn" : "bad";
}

export const TONE_TEXT: Record<string, string> = { ok: "text-emerald-300", warn: "text-amber-300", bad: "text-red-300" };

export const SERVICE_STATE: Record<string, [string, string]> = {
  ok: ["bg-emerald-400", "OK"], warning: ["bg-amber-400", "Warning"], critical: ["bg-red-500 animate-pulse", "Critical"],
  unknown: ["bg-slate-500", "Pending"], paused: ["bg-slate-700", "Paused"],
};

export const WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

/** Human description of a maintenance window's schedule. */
export function describeWindow(m: { kind: string; starts_at?: string | null; ends_at?: string | null; weekdays?: number[]; start_time?: string;
  duration_minutes?: number; timezone?: string }, fmt: (v: unknown) => string = (v) => String(v)): string {
  if (m.kind === "once") return `${fmt(m.starts_at)} → ${fmt(m.ends_at)}`;
  const days = (m.weekdays || []).map((d) => WEEKDAYS[d]).join(", ");
  return `Every ${days || "—"} at ${m.start_time || "—"} ${m.timezone || "UTC"} for ${fmtDur((m.duration_minutes || 0) * 60)}`;
}

/** What a maintenance window covers, in words. */
export function describeScope(m: { all_devices?: boolean; switch_ids?: number[]; sites?: string[]; service_ids?: number[] },
  names: Record<number, string> = {}, svcNames: Record<number, string> = {}): string {
  if (m.all_devices) return "All network alerts";
  const parts: string[] = [];
  if (m.sites?.length) parts.push(`site${m.sites.length > 1 ? "s" : ""} ${m.sites.join(", ")}`);
  if (m.switch_ids?.length) parts.push(m.switch_ids.length <= 3 ? m.switch_ids.map((i) => names[i] || `#${i}`).join(", ") : `${m.switch_ids.length} devices`);
  if (m.service_ids?.length) parts.push(m.service_ids.length <= 3 ? m.service_ids.map((i) => svcNames[i] || `check #${i}`).join(", ") : `${m.service_ids.length} service checks`);
  return parts.join(" · ") || "—";
}

/** Service-check target as shown in tables: URL for HTTP, host:port for TCP / TLS, "A host" for DNS. */
export function serviceTarget(s: { kind: string; target: string; port?: number | null; record?: string }): string {
  if (s.kind === "http") return s.target;
  if (s.kind === "dns") return `${s.record || "A"} ${s.target}`;
  return s.port ? `${s.target}:${s.port}` : s.target;
}
