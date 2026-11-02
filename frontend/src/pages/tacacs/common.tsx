import { ReactNode, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { Modal } from "../../components/ui";

export const RANGES: [string, string][] = [["1h", "1 hour"], ["6h", "6 hours"], ["24h", "24 hours"], ["7d", "7 days"], ["30d", "30 days"]];

export function useTacMeta() {
  return useQuery({ queryKey: ["tac-meta"], queryFn: () => api<any>("/tacacs/meta"), staleTime: 60_000 });
}

export function useCan() {
  const m = useTacMeta();
  const roles: string[] = m.data?.my_roles || [];
  return (role: string) => roles.includes(role);
}

/** Shown instead of a page section the user's TACACS+ roles do not cover (the backend enforces it too). */
export function Denied({ role, what }: { role: string; what: string }) {
  return <div role="alert" className="card p-4 text-sm text-muted">You need the TACACS+ <b>{role}</b> role to {what}. A SIEM administrator assigns it under
    TACACS+ → Settings → Role assignment.</div>;
}

export function RangeSelect({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return <select aria-label="Time range" className="input py-1" value={value} onChange={(e) => onChange(e.target.value)}>
    {RANGES.map(([k, l]) => <option key={k} value={k}>Last {l}</option>)}</select>;
}

export function Pager({ total, limit, offset, onChange }: { total: number; limit: number; offset: number; onChange: (o: number) => void }) {
  if (total <= limit) return null;
  return <div className="flex items-center gap-2 p-2 text-xs text-muted">
    <button className="btn" disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - limit))}>Previous</button>
    <span>{offset + 1}–{Math.min(total, offset + limit)} of {total}</span>
    <button className="btn" disabled={offset + limit >= total} onClick={() => onChange(offset + limit)}>Next</button></div>;
}

export function Status({ s }: { s?: string | null }) {
  const c: Record<string, string> = { up: "text-emerald-300", passed: "text-emerald-300", succeeded: "text-emerald-300", in_sync: "text-emerald-300",
    permit: "text-emerald-300", degraded: "text-amber-300", pending: "text-amber-300", pending_approval: "text-amber-300", queued: "text-amber-300",
    running: "text-sky-300", down: "text-red-300", failed: "text-red-300", invalid: "text-red-300", deny: "text-red-300", rejected: "text-red-300",
    rolled_back: "text-amber-300", cancelled: "text-muted", unknown: "text-muted", not_enforced: "text-amber-300" };
  return <span className={c[s || ""] || "text-muted"}>{(s || "—").replace(/_/g, " ")}</span>;
}

/** One-time secret display: the backend never returns it again. */
export function SecretOnce({ secret, notice, onClose }: { secret: string; notice: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  return <Modal title="Shared secret (shown once)" onClose={onClose}>
    <p className="text-sm mb-2">{notice}</p>
    <div className="flex gap-2 items-center"><code className="input w-full font-mono select-all break-all" aria-label="Shared secret">{secret}</code>
      <button className="btn" onClick={() => { navigator.clipboard?.writeText(secret).then(() => setCopied(true)); }}>{copied ? "Copied" : "Copy"}</button></div>
    <p className="text-2xs text-muted mt-2">Closing this dialog discards it from the browser. If it is lost, rotate the secret.</p>
    <div className="mt-3"><button className="btn btn-primary" onClick={onClose}>I have stored it</button></div>
  </Modal>;
}

export function useSave<T = any>(fn: (body: any) => Promise<T>, keys: string[], onDone?: (r: T) => void) {
  const qc = useQueryClient();
  return useMutation({ mutationFn: fn, onSuccess: (r) => { keys.forEach((k) => qc.invalidateQueries({ queryKey: [k] })); onDone?.(r); } });
}

export function ErrorText({ e }: { e: unknown }) {
  if (!e) return null;
  return <div role="alert" className="text-sm text-red-400 mt-2">{(e as Error).message}</div>;
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return <div><label className="label">{label}</label>{children}</div>;
}

export const list = (v: string) => v.split(",").map((x) => x.trim()).filter(Boolean);
