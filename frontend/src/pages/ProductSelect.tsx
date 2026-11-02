import { KeyboardEvent, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../lib/api";
import { Me } from "../lib/context";
import { PRODUCT, Product, lastPathOf, rememberProduct } from "../lib/products";
import { ProductMark } from "../components/Sidebar";

// The selector is always dark (a deliberate full-screen "launch" surface), so it uses fixed colours rather than the
// theme-mirrored palette classes.
const CARD: Record<Product, { tile: string; glow: string; border: string; chip: string; cta: string }> = {
  grid: { tile: "bg-[#e23744]", glow: "group-hover:shadow-[0_0_0_1px_#e23744,0_24px_60px_-24px_rgb(226_55_68/0.55)] group-focus-visible:shadow-[0_0_0_2px_#ef4f5f,0_24px_60px_-24px_rgb(226_55_68/0.55)]",
    border: "border-[#2a2d33]", chip: "bg-[#e23744]/10 text-[#ff96a0] border-[#e23744]/25", cta: "text-[#ff96a0]" },
  nms: { tile: "bg-[#0e9f9a]", glow: "group-hover:shadow-[0_0_0_1px_#14b8a6,0_24px_60px_-24px_rgb(20_184_166/0.5)] group-focus-visible:shadow-[0_0_0_2px_#2dd4bf,0_24px_60px_-24px_rgb(20_184_166/0.5)]",
    border: "border-[#2a2d33]", chip: "bg-[#14b8a6]/10 text-[#5eead4] border-[#14b8a6]/25", cta: "text-[#5eead4]" },
};

export function ProductSelect({ me, onMeChange, onLogout }: { me: Me; onMeChange: () => Promise<void> | void; onLogout: () => void }) {
  useEffect(() => { document.title = "Sentinel — choose a workspace"; }, []);
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
    <div className="min-h-full w-full overflow-auto text-[#e7e9ee] bg-[#0b0c0f] relative">
      <div aria-hidden className="pointer-events-none absolute inset-0 opacity-[0.55]"
        style={{ backgroundImage: "linear-gradient(rgb(255 255 255 / 0.045) 1px, transparent 1px), linear-gradient(90deg, rgb(255 255 255 / 0.045) 1px, transparent 1px)",
          backgroundSize: "40px 40px", maskImage: "radial-gradient(ellipse at 50% 40%, black 30%, transparent 80%)",
          WebkitMaskImage: "radial-gradient(ellipse at 50% 40%, black 30%, transparent 80%)" }} />
      <div aria-hidden className="pointer-events-none absolute -top-40 left-1/2 -translate-x-1/2 h-96 w-[60rem] rounded-full bg-[radial-gradient(closest-side,rgb(226_55_68/0.10),rgb(20_184_166/0.06),transparent)]" />
      <header className="relative flex items-center gap-3 px-5 sm:px-8 h-16">
        <div className="h-8 w-8 rounded-lg bg-[#1a1c21] border border-[#2a2d33] flex items-center justify-center text-[#e7e9ee]">
          <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z" /></svg></div>
        <span className="font-bold tracking-tight">Sentinel</span>
        <span className="flex-1" />
        <span className="text-xs text-[#9aa0aa] hidden sm:inline">Signed in as <b className="text-[#e7e9ee]">{me.username}</b></span>
        <button onClick={onLogout} className="rounded-md border border-[#2a2d33] px-2.5 py-1 text-xs text-[#c4c8d0] hover:bg-[#1a1c21] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#9aa0aa]">Sign out</button>
      </header>
      <main className="relative mx-auto max-w-5xl px-5 sm:px-8 pt-8 sm:pt-16 pb-16">
        <div className="text-center mb-10">
          <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight">Choose a workspace</h1>
          <p className="mt-2 text-sm text-[#9aa0aa]">Both products share your sign-in. Switch any time from the sidebar without signing out.</p>
        </div>
        <div role="list" className={`grid gap-5 ${products.length > 1 ? "md:grid-cols-2" : "max-w-md mx-auto"}`}>
          {products.map((p, i) => {
            const P = PRODUCT[p];
            const c = CARD[p];
            return (
              <div role="listitem" key={p} className="h-full">
                <button ref={(el) => { refs.current[i] = el; }} autoFocus={i === 0} onKeyDown={(e) => onKey(e, i)} onClick={() => open(p)} disabled={!!busy}
                  aria-label={`Open ${P.name}: ${P.kind}`} aria-describedby={`desc-${p}`}
                  className="group w-full h-full text-left rounded-2xl focus-visible:outline-none disabled:cursor-wait">
                  <div className={`h-full rounded-2xl border ${c.border} bg-[#121418]/90 backdrop-blur p-6 sm:p-7 transition-all duration-200 group-hover:-translate-y-0.5 ${c.glow}
                    group-active:translate-y-0 ${busy === p ? "opacity-80" : ""}`}>
                    <div className="flex items-start gap-4">
                      <div className={`h-12 w-12 shrink-0 rounded-xl flex items-center justify-center text-[#ffffff] ${c.tile}`}><ProductMark product={p} size={24} /></div>
                      <div className="min-w-0">
                        <div className="text-xl font-extrabold tracking-tight">{P.name}</div>
                        <div className="text-xs font-semibold uppercase tracking-[0.08em] text-[#9aa0aa] mt-0.5">{P.kind}</div>
                      </div>
                    </div>
                    <p id={`desc-${p}`} className="mt-4 text-sm leading-relaxed text-[#c4c8d0]">{P.tagline}</p>
                    <ul className="mt-4 flex flex-wrap gap-1.5" aria-label={`${P.name} capabilities`}>
                      {P.features.map((f) => <li key={f} className={`rounded-md border px-2 py-0.5 text-[11px] font-medium ${c.chip}`}>{f}</li>)}
                    </ul>
                    <div className={`mt-6 flex items-center gap-1.5 text-sm font-semibold ${c.cta}`}>
                      {busy === p ? "Opening…" : `Open ${P.name}`}
                      <span aria-hidden className="transition-transform group-hover:translate-x-0.5">→</span></div>
                  </div>
                </button>
              </div>
            );
          })}
        </div>
        <div className="mt-8 flex flex-col items-center gap-2">
          <label className="inline-flex items-center gap-2 text-sm text-[#c4c8d0] cursor-pointer select-none">
            <input type="checkbox" className="h-4 w-4 accent-[#9aa0aa]" checked={remember} onChange={(e) => setRemember(e.target.checked)} />
            Remember my choice and skip this screen next time
          </label>
          <p className="text-xs text-[#7d838e]">You can change this later in Settings → Preferences.</p>
          {err && <div role="alert" className="mt-2 rounded-md border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-[#fecaca]">{err}</div>}
        </div>
      </main>
    </div>
  );
}

export function NoAccess({ me, onLogout }: { me: Me; onLogout: () => void }) {
  useEffect(() => { document.title = "Sentinel — no access"; }, []);
  return (
    <div className="min-h-full w-full flex items-center justify-center bg-[#0b0c0f] text-[#e7e9ee] p-6">
      <div role="alert" className="max-w-md text-center rounded-2xl border border-[#2a2d33] bg-[#121418] p-8">
        <div className="mx-auto h-12 w-12 rounded-xl bg-[#1a1c21] border border-[#2a2d33] flex items-center justify-center mb-4 text-[#9aa0aa]">
          <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden><rect x="5" y="11" width="14" height="10" rx="2" /><path d="M8 11V7a4 4 0 0 1 8 0v4" /></svg></div>
        <h1 className="text-lg font-bold">No product access yet</h1>
        <p className="mt-2 text-sm text-[#c4c8d0]">Your account <b>{me.username}</b> is signed in but has not been given access to Sentinel Grid or Sentinel NMS.
          Ask an administrator to assign a product to your account (Settings → Users).</p>
        <button onClick={onLogout} className="mt-6 rounded-md border border-[#2a2d33] px-3 py-1.5 text-sm hover:bg-[#1a1c21] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#9aa0aa]">Sign out</button>
      </div>
    </div>
  );
}
