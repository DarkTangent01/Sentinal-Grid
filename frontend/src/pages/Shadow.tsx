import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { Card, Empty, Kpi, Loading, Modal, TableWrap, Time, Trunc, rowProps } from "../components/ui";
import { SHADOW_LABEL, ScopeBar, scopeParams } from "./Policies";

const SEV = { high: "sev-high", medium: "sev-medium", low: "sev-low" } as Record<string, string>;
const DIM_CLASS: Record<string, string> = { full: "text-red-300", partial: "text-amber-300", unknown: "text-slate-400", none: "text-slate-600" };

export function FindingCompare({ f, onClose }: { f: any; onClose: () => void }) {
  const nav = useNavigate();
  const e = f.evidence?.earlier || {};
  const l = f.evidence?.later || {};
  const rows: [string, string][] = [["srcintf", "Incoming interface"], ["dstintf", "Outgoing interface"], ["source", "Source"], ["destination", "Destination"], ["service", "Service"], ["schedule", "Schedule"]];
  const val = (o: any, k: string) => (Array.isArray(o[k]) ? o[k].join(", ") : o[k]) || "—";
  return (
    <Modal title={`${SHADOW_LABEL[f.classification] || f.classification}: policy ${f.earlier_policyid} → ${f.later_policyid}`} onClose={onClose} wide>
      <div className="space-y-3 text-sm">
        <div className="flex flex-wrap gap-2 items-center"><span className={`pill ${SEV[f.severity] || ""}`}>{f.severity}</span><span className="text-muted text-xs">confidence {f.confidence}</span></div>
        <p>{f.explanation}</p>
        <div className="tbl-wrap"><table className="tbl">
          <thead><tr><th>Condition</th><th>Earlier: #{f.earlier_policyid} {f.earlier_name} (seq {f.earlier_seq}, {f.earlier_action})</th><th>Coverage of later</th><th>Later: #{f.later_policyid} {f.later_name} (seq {f.later_seq}, {f.later_action})</th></tr></thead>
          <tbody>{rows.map(([k, label]) => (
            <tr key={k}><td className="text-muted text-xs nowrap">{label}</td><td className="font-mono text-xs cell-wrap">{val(e, k)}</td>
              <td className={`nowrap text-xs font-medium ${DIM_CLASS[f.dimensions?.[k]] || ""}`}>{f.dimensions?.[k]}</td><td className="font-mono text-xs cell-wrap">{val(l, k)}</td></tr>))}</tbody></table></div>
        {f.assumptions?.length > 0 && <div><b className="text-xs">Unresolved assumptions</b><ul className="text-xs list-disc pl-5 text-amber-200">{f.assumptions.map((a: string, i: number) => <li key={i}>{a}</li>)}</ul></div>}
        <div><b className="text-xs">Manual verification</b><ol className="text-xs list-decimal pl-5 space-y-0.5">{(f.verification || []).map((v: string, i: number) => <li key={i}>{v}</li>)}</ol></div>
        <p className="text-2xs text-muted">The SIEM never reorders, disables or deletes policies. Confirm in FortiGate before making any change.</p>
        {f.firewall_id && <div className="flex gap-2"><button className="btn" onClick={() => nav(`/policies/${f.firewall_id}/${encodeURIComponent(f.vdom)}/${f.earlier_policyid}`)}>Open policy {f.earlier_policyid}</button>
          <button className="btn" onClick={() => nav(`/policies/${f.firewall_id}/${encodeURIComponent(f.vdom)}/${f.later_policyid}`)}>Open policy {f.later_policyid}</button></div>}
      </div>
    </Modal>
  );
}

export function Shadow() {
  const [scope, setScope] = useState("");
  const [win, setWin] = useState(30);
  const [cls, setCls] = useState("");
  const [sev, setSev] = useState("");
  const [sel, setSel] = useState<any>(null);
  const q = useQuery({ queryKey: ["shadow", scope, cls, sev], queryFn: () => api<any>("/v1/policies/shadow", { params: { ...scopeParams(scope), classification: cls, severity: sev } }) });
  const d = q.data;
  return (
    <div className="space-y-4 min-w-0">
      <ScopeBar scope={scope} setScope={setScope} window={win} setWindow={setWin} />
      <p className="text-xs text-muted">Policies are compared in evaluation (sequence) order. A <b>full shadow</b> is reported only when an earlier enabled policy provably covers the later one in every condition. Objects that cannot be evaluated statically (FQDN, dynamic, geography, ISDB, user identity, custom schedules) downgrade a finding to <b>overlap (unverified)</b>. Allow rules placed above a broader deny (the usual exception pattern) are not reported.</p>
      <Loading q={q} />
      {d && <div className="kpi-grid">
        <Kpi label="High" value={d.by_severity.high} tone={d.by_severity.high ? "bad" : undefined} onClick={() => setSev(sev === "high" ? "" : "high")} />
        <Kpi label="Medium" value={d.by_severity.medium} tone={d.by_severity.medium ? "warn" : undefined} onClick={() => setSev(sev === "medium" ? "" : "medium")} />
        <Kpi label="Low" value={d.by_severity.low} onClick={() => setSev(sev === "low" ? "" : "low")} />
        {Object.entries(d.by_classification).map(([k, v]) => <Kpi key={k} label={SHADOW_LABEL[k]} value={v as number} onClick={() => setCls(cls === k ? "" : k)} />)}
      </div>}
      {(cls || sev) && <div className="text-xs">Filtered: {[cls && SHADOW_LABEL[cls], sev].filter(Boolean).join(", ")} <button className="link ml-2" onClick={() => { setCls(""); setSev(""); }}>clear</button></div>}
      <Card title={`Findings (${d?.items.length ?? 0})`}>
        {d && !d.items.length && <Empty text="No shadowed, redundant or overlapping policies detected by the current analysis." />}
        {!!d?.items.length && <TableWrap><table className="tbl">
          <thead><tr><th>Severity</th><th>Firewall / VDOM</th><th>Earlier policy</th><th>Later policy</th><th>Classification</th><th>Confidence</th><th className="w-full">Explanation</th></tr></thead>
          <tbody>{d.items.map((f: any) => (
            <tr key={f.id} {...rowProps(() => setSel(f))}>
              <td className="nowrap"><span className={`pill ${SEV[f.severity] || ""}`}>{f.severity}</span></td>
              <td className="text-xs nowrap">{f.firewall}<div className="text-muted">{f.vdom}</div></td>
              <td className="text-xs min-w-[9rem]"><span className="font-mono">#{f.earlier_policyid}</span> {f.earlier_name}<div className="text-muted">seq {f.earlier_seq} · {f.earlier_action}</div></td>
              <td className="text-xs min-w-[9rem]"><span className="font-mono">#{f.later_policyid}</span> {f.later_name}<div className="text-muted">seq {f.later_seq} · {f.later_action}</div></td>
              <td className="nowrap text-xs">{SHADOW_LABEL[f.classification]}</td>
              <td className="nowrap text-xs">{f.confidence}</td>
              <td className="text-xs text-muted"><Trunc text={f.explanation} max="max-w-[36rem]" /></td>
            </tr>))}</tbody></table></TableWrap>}
      </Card>
      {d?.runs?.length > 0 && <Card title="Analysis runs"><TableWrap maxH="max-h-60"><table className="tbl"><thead><tr><th>Started</th><th>Firewall</th><th>VDOM</th><th>Status</th><th className="num">Policies</th><th className="num">Findings</th><th>Note</th></tr></thead>
        <tbody>{d.runs.map((r: any) => <tr key={r.id}><td><Time v={r.started_at} /></td><td className="text-xs">{r.firewall_id}</td><td className="text-xs">{r.vdom}</td>
          <td className={`text-xs ${r.status === "ok" ? "text-emerald-400" : "text-red-400"}`}>{r.status}</td><td className="num">{r.policies}</td><td className="num">{r.findings}</td><td className="text-xs"><Trunc text={r.error} /></td></tr>)}</tbody></table></TableWrap></Card>}
      {sel && <FindingCompare f={sel} onClose={() => setSel(null)} />}
    </div>
  );
}
