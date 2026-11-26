/** ATT&CK tactic / technique badges for alert and rule rows (shared by both products' Alerts and Settings pages). */
export const TACTIC_NAMES: Record<string, string> = {
  TA0043: "Reconnaissance", TA0001: "Initial Access", TA0006: "Credential Access", TA0007: "Discovery",
  TA0005: "Defense Evasion", TA0011: "Command and Control", TA0010: "Exfiltration", TA0008: "Lateral Movement",
};

export function Mitre({ m }: { m?: any }) {
  if (!m?.tactic) return null;
  return (
    <span className="inline-flex flex-wrap gap-1 items-center">
      <span className="pill" title={m.tactic}>{m.tactic_name || TACTIC_NAMES[m.tactic] || m.tactic}</span>
      {(m.techniques || []).map((t: string) => (
        <a key={t} className="pill bg-slate-800 text-slate-300 hover:text-slate-100" href={`https://attack.mitre.org/techniques/${t.replace(".", "/")}/`}
          target="_blank" rel="noopener noreferrer" onClick={(e) => e.stopPropagation()}>{t}</a>))}
    </span>
  );
}
