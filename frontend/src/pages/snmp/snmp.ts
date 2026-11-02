// Pure helpers for the SNMP monitoring pages (tested in snmp.test.ts).

export const VENDOR_LABEL: Record<string, string> = { cisco: "Cisco", fortinet: "Fortinet", juniper: "Juniper", ruckus: "Ruckus", other: "Other / unknown" };

/** Group vendor keys the way the overview cards do: the four supported vendors, everything else "other". */
export function vendorKey(v: string | null | undefined): string {
  return v && ["cisco", "fortinet", "juniper", "ruckus"].includes(v) ? v : "other";
}

export const CONFIDENCE: Record<string, string> = {
  exact: "exact (sysObjectID product)", family: "vendor OID + description", vendor: "vendor only", descr: "description only (low)",
  override: "administrator override", unknown: "unknown (standard MIBs)",
};

export const CELL: Record<string, [string, string]> = {
  observed: ["bg-emerald-500/15 text-emerald-300", "observed"], implemented: ["bg-sky-500/15 text-sky-300", "implemented"],
  unsupported: ["bg-slate-700/60 text-slate-400", "unsupported"], failing: ["bg-red-500/15 text-red-300", "failing"],
  not_applicable: ["text-muted", "—"],
};

export function matrixCounts(cells: Record<string, string>): Record<string, number> {
  const out: Record<string, number> = { observed: 0, implemented: 0, unsupported: 0, failing: 0, not_applicable: 0 };
  for (const v of Object.values(cells)) out[v] = (out[v] || 0) + 1;
  return out;
}

export function pctTone(p: number | null | undefined): "ok" | "warn" | "bad" | undefined {
  if (p == null) return undefined;
  return p >= 99 ? "ok" : p >= 90 ? "warn" : "bad";
}
