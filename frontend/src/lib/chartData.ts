/** Pure data helpers for charts (unit-tested in chartData.test.ts). */

export interface Slice { name: string; value: number; pct: number; members?: string[] }

/** Keep the largest `max - 1` categories and fold the rest into one "Other" slice. Nothing is dropped:
 *  the Other slice keeps its member names and counts sum exactly to the input total. */
export function topNWithOther(rows: { key: string; value: number }[], max = 8, otherLabel = "Other"): { slices: Slice[]; total: number } {
  const clean = rows.filter((r) => Number.isFinite(r.value) && r.value > 0).sort((a, b) => b.value - a.value);
  const total = clean.reduce((a, r) => a + r.value, 0);
  const pct = (v: number) => (total ? (v / total) * 100 : 0);
  if (clean.length <= max) return { slices: clean.map((r) => ({ name: r.key, value: r.value, pct: pct(r.value) })), total };
  const head = clean.slice(0, max - 1);
  const tail = clean.slice(max - 1);
  const otherVal = tail.reduce((a, r) => a + r.value, 0);
  return {
    slices: [...head.map((r) => ({ name: r.key, value: r.value, pct: pct(r.value) })),
      { name: `${otherLabel} (${tail.length})`, value: otherVal, pct: pct(otherVal), members: tail.map((r) => r.key) }],
    total,
  };
}

export function fmtPct(p: number): string {
  if (p > 0 && p < 0.1) return "<0.1%";
  return `${p.toFixed(p < 10 ? 1 : 0)}%`;
}

/** Convert API time-series points into [epochMs, value] pairs for a time axis, sorted chronologically. */
export function toTimePairs(points: any[], key: string): [number, number][] {
  return points
    .map((p) => [Date.parse(String(p.t).replace(" ", "T") + (/[zZ]|[+-]\d\d:?\d\d$/.test(String(p.t)) ? "" : "Z")), Number(p[key] ?? 0)] as [number, number])
    .filter(([t]) => Number.isFinite(t))
    .sort((a, b) => a[0] - b[0]);
}

export function sumKey(points: any[], key: string): number {
  return points.reduce((a, p) => a + Number(p[key] ?? 0), 0);
}
