import { FormEvent, KeyboardEvent, useEffect, useState } from "react";
import { api } from "../lib/api";
import { AUTH, AuthShell, Spinner } from "../components/AuthShell";
import { PRODUCT_TAGLINE, SentinelLogo, SentinelTile } from "../components/Brand";

const EYE = <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
  <path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z" /><circle cx="12" cy="12" r="3" /></svg>;
const EYE_OFF = <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
  <path d="M3 3l18 18M10.6 5.1A10.6 10.6 0 0 1 12 5c6.4 0 10 7 10 7a17.6 17.6 0 0 1-3.2 4.2M6.6 6.6A17 17 0 0 0 2 12s3.6 7 10 7a10 10 0 0 0 5.4-1.6M9.9 9.9a3 3 0 0 0 4.2 4.2" /></svg>;
const ALERT = <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden className="shrink-0 mt-0.5">
  <circle cx="12" cy="12" r="9" /><path d="M12 8v5M12 16h.01" /></svg>;

export function Login({ onLogin }: { onLogin: () => void }) {
  const [u, setU] = useState("");
  const [p, setP] = useState("");
  const [show, setShow] = useState(false);
  const [caps, setCaps] = useState(false);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => { document.title = "Sign in · Sentinel"; }, []);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true); setErr("");
    try {
      await api("/auth/login", { method: "POST", body: { username: u, password: p } });
      onLogin();
    } catch (x) { setErr((x as Error).message || "Sign-in failed"); } finally { setBusy(false); }
  }
  const onKey = (e: KeyboardEvent<HTMLInputElement>) => setCaps(e.getModifierState?.("CapsLock") ?? false);
  return (
    <AuthShell>
      <div className="min-h-screen mx-auto max-w-6xl px-5 sm:px-8 py-8 flex flex-col">
        <header className="flex items-center"><SentinelLogo size={30} /></header>
        <div className="flex-1 grid items-center gap-10 lg:grid-cols-[1.1fr_minmax(0,26rem)] py-10">
          <section className="hidden lg:block max-w-xl">
            <p className="text-xs font-semibold uppercase tracking-[0.14em] text-[#71717A]">Sentinel platform</p>
            <h1 className="mt-3 text-[2.25rem] leading-[1.1] font-semibold tracking-[-0.03em] text-[#F5F5F5]">
              One view of your network<br />and its security.</h1>
            <p className="mt-4 text-[15px] leading-relaxed text-[#A1A1AA] max-w-md">Monitor infrastructure, traffic and wireless, and detect, investigate
              and respond to threats — with one sign-in.</p>
            <div className="mt-8 grid gap-3 sm:grid-cols-2 max-w-lg">
              {(["nms", "grid"] as const).map((pr) => (
                <div key={pr} className="rounded-xl border border-[#292929] bg-[#111111] p-4">
                  <div className="flex items-center gap-2.5"><SentinelTile size={30} tone={pr} />
                    <span className="font-semibold text-[#F5F5F5]">Sentinel <span className={pr === "nms" ? "text-[#38BDF8]" : "text-[#A78BFA]"}>{pr === "nms" ? "NMS" : "Grid"}</span></span></div>
                  <p className="mt-2 text-xs text-[#A1A1AA]">{PRODUCT_TAGLINE[pr]}</p>
                </div>))}
            </div>
          </section>

          <form onSubmit={submit} className={`${AUTH.card} p-7 sm:p-8 w-full max-w-md mx-auto lg:mx-0 space-y-5`} aria-describedby={err ? "login-error" : undefined}>
            <div>
              <h2 className="text-xl font-semibold tracking-tight text-[#F5F5F5]">Sign in</h2>
              <p className="mt-1 text-sm text-[#A1A1AA]">One account for Sentinel NMS and Sentinel Grid.</p>
            </div>
            <div>
              <label className={AUTH.label} htmlFor="login-user">Username</label>
              <input id="login-user" className={AUTH.input} value={u} onChange={(e) => setU(e.target.value)} autoFocus autoComplete="username" spellCheck={false}
                aria-invalid={!!err} />
            </div>
            <div>
              <label className={AUTH.label} htmlFor="login-pass">Password</label>
              <div className="relative">
                <input id="login-pass" className={`${AUTH.input} pr-11`} type={show ? "text" : "password"} value={p} onChange={(e) => setP(e.target.value)}
                  onKeyUp={onKey} onKeyDown={onKey} autoComplete="current-password" aria-invalid={!!err} />
                <button type="button" onClick={() => setShow(!show)} aria-label={show ? "Hide password" : "Show password"} aria-pressed={show}
                  className="absolute right-1.5 top-1/2 -translate-y-1/2 rounded-md p-1.5 text-[#A1A1AA] hover:text-[#F5F5F5] hover:bg-[#1C1C1C] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#38BDF8]">
                  {show ? EYE_OFF : EYE}</button>
              </div>
              {caps && <p className="mt-1.5 text-xs text-[#FBBF24]" role="status">Caps Lock is on</p>}
            </div>
            {err && <div id="login-error" role="alert" className="flex gap-2 rounded-lg border border-[#EF4444]/40 bg-transparent px-3 py-2.5 text-sm text-[#FECACA]">{ALERT}{err}</div>}
            <button type="submit" className={AUTH.primary} disabled={busy || !u || !p}>{busy && <Spinner />}{busy ? "Signing in…" : "Sign in"}</button>
          </form>
        </div>
        <footer className="flex flex-wrap items-center justify-between gap-2 text-xs text-[#71717A]">
          <span>Authorized personnel only. All activity is audited.</span>
          <span>© Sentinel</span>
        </footer>
      </div>
    </AuthShell>
  );
}
