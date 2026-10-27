import { useQuery } from "@tanstack/react-query";
import { api, downloadUrl } from "../lib/api";
import { Card, Kpi, Loading, TableWrap, Time } from "../components/ui";

const ST: Record<string, [string, string]> = {
  met: ["Met", "bg-emerald-500/15 text-emerald-300"], partial: ["Partial", "bg-amber-500/15 text-amber-300"],
  not_met: ["Not met", "bg-red-500/15 text-red-300"], manual: ["Manual check", "bg-slate-700/60 text-slate-300"],
};

export function Compliance() {
  const q = useQuery({ queryKey: ["compliance"], queryFn: () => api<any>("/compliance"), refetchInterval: 120_000 });
  const d = q.data;
  return (
    <div className="space-y-4 min-w-0">
      <div className="card !block p-3 border-amber-600/40 bg-amber-500/5 text-xs text-amber-200">{d?.disclaimer || "Evidence support only."}</div>
      <Loading q={q} />
      {d && <>
        <div className="flex flex-wrap items-end gap-3">
          <div className="kpi-grid flex-1">
            {Object.entries(ST).map(([k, [label]]) => <Kpi key={k} label={label} value={d.counts[k] ?? 0} tone={k === "met" ? "ok" : k === "not_met" && d.counts[k] ? "bad" : k === "partial" && d.counts[k] ? "warn" : undefined} />)}
          </div>
          <a className="btn" href={downloadUrl("/compliance/export.csv")}>Export evidence (CSV)</a>
        </div>
        <p className="text-xs text-muted">Generated <Time v={d.generated_at} />. Statuses are computed from current SIEM configuration and data (retention, feeds, detections, incidents, policy reviews, drift snapshots, assets).</p>
        {d.frameworks.map((fw: any) => (
          <Card key={fw.framework} title={fw.framework}>
            <TableWrap><table className="tbl"><thead><tr><th>Control</th><th className="w-1/3">Requirement</th><th>Status</th><th className="w-1/3">Evidence</th><th>How to improve</th></tr></thead>
              <tbody>{fw.controls.map((c: any) => <tr key={c.id}><td className="font-mono text-xs nowrap">{c.id}</td><td className="text-sm min-w-[14rem]">{c.title}</td>
                <td className="nowrap"><span className={`pill ${ST[c.status][1]}`}>{ST[c.status][0]}</span></td>
                <td className="text-xs text-muted min-w-[14rem] cell-wrap">{c.evidence || "—"}</td><td className="text-xs min-w-[12rem]">{c.how || "—"}</td></tr>)}</tbody></table></TableWrap>
          </Card>))}
      </>}
    </div>
  );
}
