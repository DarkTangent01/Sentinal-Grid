import { ReactNode, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../../lib/api";

export type Role = "viewer" | "editor" | "approver" | "deployer" | "admin";

export function useMeta() {
  return useQuery({ queryKey: ["iac-meta"], queryFn: () => api<any>("/iac/meta"), staleTime: 60_000 });
}

export function can(meta: any, role: Role) {
  return role === "viewer" || !!meta?.roles?.includes(role);
}

export const SEV_C: Record<string, string> = { critical: "bg-red-600 text-white", high: "bg-red-500/80 text-white", medium: "bg-amber-500/80 text-black",
  low: "bg-sky-600/70 text-white", info: "bg-slate-600/60 text-white" };
export function SevBadge({ s }: { s: string }) {
  return <span className={`inline-block rounded px-1.5 text-2xs font-bold uppercase ${SEV_C[s] || SEV_C.info}`}>{s}</span>;
}

const STATUS_C: Record<string, string> = {
  draft: "text-slate-400", validation_failed: "text-red-300", ready_for_review: "text-sky-300", pending_approval: "text-amber-300", approved: "text-emerald-300",
  rejected: "text-red-300", queued: "text-amber-300", running: "text-sky-300 animate-pulse", succeeded: "text-emerald-300", failed: "text-red-400",
  rolled_back: "text-violet-300", cancelled: "text-slate-400", stale: "text-orange-300", in_sync: "text-emerald-300", drift: "text-red-300",
  unknown: "text-slate-400", error: "text-red-400", unmanaged: "text-slate-500", dry_run_ok: "text-emerald-300", skipped: "text-slate-400", pending: "text-slate-400",
};
export function Status({ s }: { s: string }) {
  return <span className={`text-xs font-semibold whitespace-nowrap ${STATUS_C[s] || "text-slate-300"}`}>{(s || "—").replace(/_/g, " ")}</span>;
}

const ACT_C: Record<string, string> = { create: "text-emerald-300", update: "text-amber-300", delete: "text-red-300", move: "text-violet-300", "no-op": "text-slate-400" };
export function Action({ a }: { a: string }) {
  return <span className={`text-xs font-bold uppercase ${ACT_C[a] || ""}`}>{a}</span>;
}

export function errText(e: unknown) {
  if (e instanceof ApiError) return e.status === 403 ? `Permission denied: ${e.message}` : e.message;
  return String(e);
}

export function ErrorBox({ error }: { error: unknown }) {
  if (!error) return null;
  return <div role="alert" className="rounded border border-red-500/40 bg-red-500/10 text-red-200 text-sm px-3 py-2">{errText(error)}</div>;
}

export function Note({ children, tone = "info" }: { children: ReactNode; tone?: "info" | "warn" | "bad" }) {
  const c = tone === "bad" ? "border-red-500/40 bg-red-500/10 text-red-200" : tone === "warn" ? "border-amber-500/40 bg-amber-500/10 text-amber-100" : "border-line bg-white/5 text-muted";
  return <div className={`rounded border px-3 py-2 text-xs ${c}`}>{children}</div>;
}

/** Mutation wrapper: runs, invalidates IaC queries, exposes error. */
export function useAct<T = any>(fn: (arg: any) => Promise<T>, onOk?: (r: T) => void) {
  const qc = useQueryClient();
  return useMutation({ mutationFn: fn, onSuccess: (r) => { qc.invalidateQueries({ predicate: (q) => String(q.queryKey[0]).startsWith("iac") }); onOk?.(r); } });
}

function fmtVal(v: unknown): string {
  if (v === null || v === undefined || v === "") return "—";
  if (Array.isArray(v)) return v.join(", ") || "—";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

/** Field-level diff (from a plan change or drift finding). */
export function FieldDiff({ fields, leftLabel = "current", rightLabel = "desired" }: { fields: any[]; leftLabel?: string; rightLabel?: string }) {
  if (!fields?.length) return <span className="text-muted text-xs">no field changes</span>;
  return <table className="text-xs w-full"><thead><tr className="text-muted"><th className="text-left pr-2 font-normal">field</th><th className="text-left pr-2 font-normal">{leftLabel}</th>
    <th className="text-left font-normal">{rightLabel}</th></tr></thead>
    <tbody>{fields.map((f: any) => <tr key={f.field} className="align-top">
      <td className="font-mono pr-2 whitespace-nowrap">{f.field}</td>
      <td className="pr-2"><span className="bg-red-500/10 text-red-200 px-1 rounded break-all">{fmtVal(f.current)}</span></td>
      <td><span className="bg-emerald-500/10 text-emerald-200 px-1 rounded break-all">{fmtVal(f.desired)}</span>
        {(f.added?.length || f.removed?.length) ? <div className="text-2xs text-muted">{f.added?.length ? `+ ${f.added.join(", ")} ` : ""}{f.removed?.length ? `− ${f.removed.join(", ")}` : ""}</div> : null}</td>
    </tr>)}</tbody></table>;
}

/** Side-by-side object view with changed keys highlighted. */
export function SideBySide({ left, right, leftLabel, rightLabel }: { left: any; right: any; leftLabel: string; rightLabel: string }) {
  const keys = Array.from(new Set([...Object.keys(left || {}), ...Object.keys(right || {})])).sort();
  return <div className="grid grid-cols-2 gap-2 text-xs font-mono">
    {[[leftLabel, left], [rightLabel, right]].map(([lab, obj]: any, side) => <div key={side} className="rounded border border-line p-2 min-w-0">
      <div className="text-2xs text-muted mb-1 font-sans">{lab}</div>
      {obj ? keys.map((k) => { const diff = JSON.stringify(left?.[k]) !== JSON.stringify(right?.[k]);
        return <div key={k} className={`break-all ${diff ? (side ? "bg-emerald-500/10" : "bg-red-500/10") : ""}`}><span className="text-muted">{k}: </span>{fmtVal(obj[k])}</div>; })
        : <div className="text-muted">absent</div>}
    </div>)}
  </div>;
}

/** Line diff (LCS) between two texts. */
export function LineDiff({ a, b, max = 4_000_000 }: { a: string; b: string; max?: number }) {
  const A = a.split("\n"), B = b.split("\n");
  if (A.length * B.length > max) return <Note tone="warn">Files too large to diff in the browser ({A.length} × {B.length} lines).</Note>;
  const n = A.length, m = B.length;
  const L: number[][] = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) L[i][j] = A[i] === B[j] ? L[i + 1][j + 1] + 1 : Math.max(L[i + 1][j], L[i][j + 1]);
  const rows: [string, string][] = [];
  let i = 0, j = 0;
  while (i < n && j < m) {
    if (A[i] === B[j]) { rows.push([" ", A[i]]); i++; j++; }
    else if (L[i + 1][j] >= L[i][j + 1]) { rows.push(["-", A[i]]); i++; }
    else { rows.push(["+", B[j]]); j++; }
  }
  while (i < n) rows.push(["-", A[i++]]);
  while (j < m) rows.push(["+", B[j++]]);
  const changed = rows.filter((r) => r[0] !== " ").length;
  if (!changed) return <Note>No differences.</Note>;
  return <pre className="text-xs font-mono max-h-[28rem] overflow-auto rounded border border-line">{rows.map((r, k) =>
    <div key={k} className={r[0] === "+" ? "bg-emerald-500/15 text-emerald-200" : r[0] === "-" ? "bg-red-500/15 text-red-200" : "text-muted"}>{r[0]} {r[1]}</div>)}</pre>;
}

export function Confirm({ title, children, confirmLabel, danger, disabled, onConfirm, onClose, busy }: {
  title: string; children: ReactNode; confirmLabel: string; danger?: boolean; disabled?: boolean; busy?: boolean; onConfirm: () => void; onClose: () => void;
}) {
  return <div className="fixed inset-0 z-50 bg-black/60 flex items-start justify-center p-2 sm:p-6 overflow-auto" onClick={onClose}>
    <div role="dialog" aria-modal="true" aria-label={title} className="card w-full max-w-xl sm:mt-16" onClick={(e) => e.stopPropagation()}>
      <div className="card-h"><h2>{title}</h2><button aria-label="Close" className="text-muted px-1" onClick={onClose}>✕</button></div>
      <div className="p-4 space-y-3 text-sm">{children}
        <div className="flex justify-end gap-2 pt-2"><button className="btn" onClick={onClose}>Cancel</button>
          <button className={`btn ${danger ? "btn-danger" : "btn-primary"}`} disabled={disabled || busy} onClick={onConfirm}>{busy ? "Working…" : confirmLabel}</button></div>
      </div>
    </div>
  </div>;
}

export function Pager({ page, size, total, onPage }: { page: number; size: number; total: number; onPage: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / size));
  if (pages <= 1) return null;
  return <div className="flex items-center gap-2 text-xs justify-end p-2">
    <button className="btn py-0.5" disabled={page <= 1} onClick={() => onPage(page - 1)}>Previous</button>
    <span className="text-muted">page {page} / {pages} · {total}</span>
    <button className="btn py-0.5" disabled={page >= pages} onClick={() => onPage(page + 1)}>Next</button></div>;
}

export function useLocalState<T>(key: string, init: T): [T, (v: T) => void] {
  const [v, setV] = useState<T>(() => { try { const s = sessionStorage.getItem(key); return s ? JSON.parse(s) : init; } catch { return init; } });
  return [v, (x: T) => { setV(x); try { sessionStorage.setItem(key, JSON.stringify(x)); } catch { /* ignore */ } }];
}
