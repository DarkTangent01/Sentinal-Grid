import { KeyboardEvent, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../lib/api";
import { Me } from "../lib/context";
import { PRODUCT, Product, lastPathOf, rememberProduct } from "../lib/products";
import { AUTH, AuthShell, Spinner } from "../components/AuthShell";
import { SentinelLogo, SentinelTile } from "../components/Brand";

// Launch surface: always the dark Sentinel navy (components/AuthShell), product accents fixed (sky / violet).
const CARD: Record<Product, { ring: string; chip: string; cta: string }> = {
  nms: { ring: "group-hover:border-[#38BDF8]/60 group-focus-visible:border-[#38BDF8] group-hover:shadow-[0_24px_64px_-28px_rgb(56_189_248/0.45)]",
    chip: "bg-[#38BDF8]/10 text-[#7DD3FC] border-[#38BDF8]/25", cta: "text-[#7DD3FC]" },
  grid: { ring: "group-hover:border-[#A78BFA]/60 group-focus-visible:border-[#A78BFA] group-hover:shadow-[0_24px_64px_-28px_rgb(167_139_250/0.45)]",
    chip: "bg-[#A78BFA]/10 text-[#C4B5FD] border-[#A78BFA]/25", cta: "text-[#C4B5FD]" },
};
const ARROW = <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="M5 12h14M13 6l6 6-6 6" /></svg>;

export function ProductSelect({ me, onMeChange, onLogout }: { me: Me; onMeChange: () => Promise<void> | void; onLogout: () => void }) {
  useEffect(() => { document.title = "Choose a workspace · Sentinel"; }, []);
  const nav = useNavigate();
  const [remember, setRemember] = useState(!!me.default_product);
  const [busy, setBusy] = useState<Product | null>(null);
  const [err, setErr] = useState("");
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const products = me.products;

  const open = async (p: Product) => {
    setErr("");
    setBusy(p);
    try {
      const want = remember ? p : "none";
      if ((me.default_product || "none") !== want) {
        await api("/auth/me/preferences", { method: "PUT", body: { default_product: want } });
        await onMeChange();
      }
      rememberProduct(p);
      nav(lastPathOf(p));
    } catch (e) {
      setErr((e as Error).message || "Could not open the product.");
      setBusy(null);
    }
  };
  const onKey = (e: KeyboardEvent, i: number) => {
    const d = e.key === "ArrowRight" || e.key === "ArrowDown" ? 1 : e.key === "ArrowLeft" || e.key === "ArrowUp" ? -1 : 0;
    if (d) { e.preventDefault(); refs.current[(i + d + products.length) % products.length]?.focus(); }
  };

  return (
    <AuthShell header={
      <header className="relative flex items-center gap-3 px-5 sm:px-8 h-16">
        <SentinelLogo size={26} />
        <span className="flex-1" />
        <span className={`text-xs ${AUTH.muted} hidden sm:inline`}>Signed in as <b className="text-[#F1F5F9] font-medium">{me.username}</b></span>
        <button type="button" onClick={onLogout} className={AUTH.ghost}>Sign out</button>
      </header>}>
      <main className="mx-auto max-w-5xl px-5 sm:px-8 pt-8 sm:pt-14 pb-16">
        <div className="text-center mb-10">
          <h1 className="text-2xl sm:text-[1.75rem] font-semibold tracking-[-0.02em] text-[#F8FAFC]">Choose a workspace</h1>
          <p className={`mt-2 text-sm ${AUTH.muted}`}>Both products share your sign-in. Switch any time from the sidebar without signing out.</p>
        </div>
        <div role="list" className={`grid gap-5 ${products.length > 1 ? "md:grid-cols-2" : "max-w-md mx-auto"}`}>
          {products.map((p, i) => {
            const P = PRODUCT[p];
            const c = CARD[p];
            return (
              <div role="listitem" key={p} className="h-full">
                <button type="button" ref={(el) => { refs.current[i] = el; }} autoFocus={i === 0} onKeyDown={(e) => onKey(e, i)} onClick={() => open(p)} disabled={!!busy}
                  aria-label={`Open ${P.name}: ${P.kind}`} aria-describedby={`desc-${p}`}
                  className="group w-full h-full text-left rounded-2xl focus-visible:outline-none disabled:cursor-wait">
                  <div className={`h-full ${AUTH.card} p-6 sm:p-7 transition-[border-color,box-shadow,transform] duration-200 group-hover:-translate-y-0.5 ${c.ring}
                    ${busy === p ? "opacity-80" : ""}`}>
                    <div className="flex items-center gap-4">
                      <SentinelTile size={48} tone={p} />
                      <div className="min-w-0">
                        <div className="text-xl font-semibold tracking-[-0.02em] text-[#F8FAFC]">{P.name}</div>
                        <div className={`text-xs font-medium mt-0.5 ${AUTH.muted}`}>{P.kind}</div>
                      </div>
                    </div>
                    <p id={`desc-${p}`} className="mt-4 text-sm leading-relaxed text-[#CBD5E1]">{P.tagline}</p>
                    <ul className="mt-4 flex flex-wrap gap-1.5" aria-label={`${P.name} capabilities`}>
                      {P.features.map((f) => <li key={f} className={`rounded-md border px-2 py-0.5 text-[11px] font-medium ${c.chip}`}>{f}</li>)}
                    </ul>
                    <div className={`mt-6 flex items-center gap-1.5 text-sm font-semibold ${c.cta}`}>
                      {busy === p ? <><Spinner />Opening…</> : <>Open {P.name}<span className="transition-transform group-hover:translate-x-0.5">{ARROW}</span></>}</div>
                  </div>
                </button>
              </div>
            );
          })}
        </div>
        <div className="mt-8 flex flex-col items-center gap-2">
          <label className="inline-flex items-center gap-2 text-sm text-[#CBD5E1] cursor-pointer select-none">
            <input type="checkbox" className="h-4 w-4 accent-[#38BDF8]" checked={remember} onChange={(e) => setRemember(e.target.checked)} />
            Remember my choice and skip this screen next time
          </label>
          <p className={`text-xs ${AUTH.subtle}`}>You can change this later in Settings → Preferences.</p>
          {err && <div role="alert" className="mt-2 rounded-lg border border-[#EF4444]/40 bg-[#EF4444]/10 px-3 py-2 text-sm text-[#FECACA]">{err}</div>}
        </div>
      </main>
    </AuthShell>
  );
}

export function NoAccess({ me, onLogout }: { me: Me; onLogout: () => void }) {
  useEffect(() => { document.title = "No access · Sentinel"; }, []);
  return (
    <AuthShell>
      <div className="min-h-screen flex items-center justify-center p-6">
        <div role="alert" className={`max-w-md text-center ${AUTH.card} p-8`}>
          <div className="mx-auto mb-4 flex justify-center"><SentinelTile size={48} /></div>
          <h1 className="text-lg font-semibold text-[#F8FAFC]">No product access yet</h1>
          <p className="mt-2 text-sm text-[#CBD5E1]">Your account <b className="font-medium text-[#F1F5F9]">{me.username}</b> is signed in but has not been given access to
            Sentinel NMS or Sentinel Grid. Ask an administrator to assign a product to your account (Settings → Users).</p>
          <button type="button" onClick={onLogout} className={`mt-6 ${AUTH.ghost} !px-3 !py-1.5 !text-sm`}>Sign out</button>
        </div>
      </div>
    </AuthShell>
  );
}
