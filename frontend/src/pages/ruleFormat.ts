// Pure helpers for the YAML rule pack UI (tested in ruleFormat.test.ts).

export function fmtTimeframe(s: number | null | undefined): string {
  if (!s) return "—";
  if (s % 86400 === 0) return `${s / 86400} d`;
  if (s % 3600 === 0) return `${s / 3600} h`;
  if (s % 60 === 0) return `${s / 60} min`;
  return `${s} s`;
}

/** "never run" / "error: …" / "2 match(es) · 14 ms" */
export function fmtStats(st: { last_run?: string; duration_ms?: number; matches?: number; error?: string } | null | undefined): string {
  if (!st || !st.last_run) return "never run";
  if (st.error) return `error: ${st.error.slice(0, 60)}`;
  return `${st.matches ?? 0} match(es) · ${Math.round(st.duration_ms ?? 0)} ms`;
}
