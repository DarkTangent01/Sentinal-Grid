import { FormEvent, useState } from "react";
import { api } from "../lib/api";
import { ThemeToggle } from "../lib/theme";

const POINTS = ["FortiGate, Palo Alto and Windows logs in one place",
  "Alerts and incidents mapped to MITRE ATT&CK", "Read-only by design: the SIEM never changes firewall config"];

export function Login({ onLogin }: { onLogin: () => void }) {
  const [u, setU] = useState("");
  const [p, setP] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true); setErr("");
    try {
      await api("/auth/login", { method: "POST", body: { username: u, password: p } });
      onLogin();
    } catch (x) { setErr((x as Error).message); } finally { setBusy(false); }
  }
  return (
    <div className="h-full flex">
      {/* brand panel: white text on #CB202D→#A81A25 keeps >= 5.6:1 for the small copy */}
      <aside className="hidden lg:flex w-[44%] max-w-xl flex-col justify-between p-10 text-[#ffffff] bg-gradient-to-br from-[#cb202d] to-[#a81a25] relative overflow-hidden">
        <div aria-hidden className="absolute -right-24 -top-24 h-80 w-80 rounded-full bg-[#ffffff]/10" />
        <div aria-hidden className="absolute -left-16 bottom-10 h-56 w-56 rounded-full bg-[#ffffff]/5" />
        <div className="relative flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl bg-[#ffffff] text-[#cb202d] flex items-center justify-center">
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
              <path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z" /><path d="M8 12h2l1.5-3 2 6 1.5-3h1" />
            </svg>
          </div>
          <span className="text-lg font-extrabold tracking-tight">Sentinel Grid</span>
        </div>
        <div className="relative space-y-6">
          <h1 className="text-4xl font-extrabold leading-tight tracking-tight">Network security,<br />served fresh.</h1>
          <ul className="space-y-3 text-sm">
            {POINTS.map((t) => (
              <li key={t} className="flex gap-3"><span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-[#ffffff]" aria-hidden />{t}</li>
            ))}
          </ul>
        </div>
        <div className="relative text-xs">Authorized personnel only. All activity is audited.</div>
      </aside>

      <main className="flex-1 flex items-center justify-center p-6 relative">
        <ThemeToggle className="absolute top-4 right-4" />
        <form onSubmit={submit} className="card shadow-card p-8 w-full max-w-sm space-y-5">
          <div className="space-y-1">
            <div className="lg:hidden text-brand-400 font-extrabold tracking-tight text-lg">Sentinel Grid</div>
            <h2 className="text-2xl font-bold text-slate-100">Sign in</h2>
            <div className="text-sm text-muted">Use your SIEM account. <span className="lg:hidden">Activity is audited.</span></div>
          </div>
          <div><label className="label" htmlFor="login-user">Username</label>
            <input id="login-user" className="input w-full py-2.5" value={u} onChange={(e) => setU(e.target.value)} autoFocus autoComplete="username" /></div>
          <div><label className="label" htmlFor="login-pass">Password</label>
            <input id="login-pass" className="input w-full py-2.5" type="password" value={p} onChange={(e) => setP(e.target.value)} autoComplete="current-password" /></div>
          {err && <div role="alert" className="text-sm text-red-400">{err}</div>}
          <button className="btn btn-primary w-full justify-center py-2.5 text-[15px]" disabled={busy || !u || !p}>{busy ? "Signing in…" : "Sign in"}</button>
        </form>
      </main>
    </div>
  );
}
