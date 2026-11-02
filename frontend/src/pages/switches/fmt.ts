/** Pure formatting helpers for switch monitoring (unit-tested in switches.test.ts). Missing values stay missing ("—" / null). */

export function fmtBps(v: number | null | undefined): string {
  if (v == null || !isFinite(v)) return "—";
  const units: [number, string][] = [[1e12, "Tbit/s"], [1e9, "Gbit/s"], [1e6, "Mbit/s"], [1e3, "kbit/s"]];
  for (const [d, u] of units) if (Math.abs(v) >= d) return `${(v / d).toFixed(v / d < 10 ? 2 : v / d < 100 ? 1 : 0)} ${u}`;
  return `${v.toFixed(0)} bit/s`;
}

export function fmtPctOrDash(v: number | null | undefined, digits = 1): string {
  return v == null || !isFinite(v) ? "—" : `${v.toFixed(digits)}%`;
}

export function fmtWatts(v: number | null | undefined): string {
  return v == null || !isFinite(v) ? "—" : `${v.toFixed(v < 10 ? 1 : 0)} W`;
}

export function fmtUptime(s: number | null | undefined): string {
  if (s == null || !isFinite(s)) return "—";
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`;
}

/** [epochMs, value | null] pairs, sorted; null stays null so charts draw a gap instead of a zero. */
export function pairs(points: any[], key: string): [number, number | null][] {
  return points
    .map((p) => {
      const t = Date.parse(String(p.t).replace(" ", "T") + (/[zZ]|[+-]\d\d:?\d\d$/.test(String(p.t)) ? "" : "Z"));
      const v = p[key];
      return [t, v == null || !isFinite(Number(v)) ? null : Number(v)] as [number, number | null];
    })
    .filter(([t]) => Number.isFinite(t))
    .sort((a, b) => a[0] - b[0]);
}

export function statusTone(pct: number | null | undefined, warn = 70, bad = 90): "ok" | "warn" | "bad" | undefined {
  if (pct == null) return undefined;
  return pct >= bad ? "bad" : pct >= warn ? "warn" : "ok";
}

const RANK: Record<string, number> = { lost: 4, down: 3, degraded: 2, unknown: 1, up: 0 };

export function worstStatus(statuses: string[]): string {
  return statuses.reduce((w, s) => ((RANK[s] ?? 1) > (RANK[w] ?? 1) ? s : w), "up");
}

/** Parallel links between the same two devices (LAG members, redundant cables) drawn as one edge with the worst status. */
export function groupLinks(links: any[]): { a: string; b: string; status: string; links: any[] }[] {
  const by = new Map<string, { a: string; b: string; status: string; links: any[] }>();
  for (const l of links) {
    const [a, b] = [l.a.node, l.b.node].sort();
    const k = `${a}|${b}`;
    const g = by.get(k) || { a, b, status: "up", links: [] as any[] };
    g.links.push(l);
    g.status = worstStatus(g.links.map((x) => x.status));
    by.set(k, g);
  }
  return [...by.values()];
}
