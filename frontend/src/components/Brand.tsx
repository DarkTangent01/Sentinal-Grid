/** Sentinel logo system (docs/design-system.md → Logo). One mark for the platform and both products; the product is
 *  told apart by its name and accent gradient. Geometry matches scripts/generate-brand.py (public/brand/*.svg,
 *  favicon) — change both together. */
import { useId } from "react";
import type { Product } from "../lib/products";

export const MARK_PATHS = ["M26.4 10 L16 4 L5.6 10 L16 16", "M5.6 22 L16 28 L26.4 22 L16 16"];
export const MARK_NODES: [number, number, number][] = [[26.4, 10, 2.25], [5.6, 22, 2.25], [16, 16, 3.1]];

export type MarkTone = "platform" | Product | "mono";
const GRADIENT: Record<Exclude<MarkTone, "mono">, [string, string]> = {
  platform: ["#38BDF8", "#A78BFA"], nms: ["#38BDF8", "#3B82F6"], grid: ["#A78BFA", "#6366F1"],
};

/** The mark alone. tone "mono" paints with currentColor (inherits the text colour). */
export function SentinelMark({ size = 24, tone = "platform", title, className = "" }: { size?: number; tone?: MarkTone; title?: string; className?: string }) {
  const id = useId().replace(/:/g, "");
  const paint = tone === "mono" ? "currentColor" : `url(#sg${id})`;
  return (
    <svg viewBox="0 0 32 32" width={size} height={size} className={className} role={title ? "img" : undefined} aria-label={title} aria-hidden={title ? undefined : true}>
      {tone !== "mono" && <defs><linearGradient id={`sg${id}`} x1="4" y1="4" x2="28" y2="28" gradientUnits="userSpaceOnUse">
        <stop offset="0" stopColor={GRADIENT[tone][0]} /><stop offset="1" stopColor={GRADIENT[tone][1]} /></linearGradient></defs>}
      <g fill="none" stroke={paint} strokeWidth={2.6} strokeLinecap="round" strokeLinejoin="round">{MARK_PATHS.map((d) => <path key={d} d={d} />)}</g>
      {MARK_NODES.map(([cx, cy, r]) => <circle key={`${cx}-${cy}`} cx={cx} cy={cy} r={r} fill={paint} />)}
    </svg>
  );
}

/** The mark on the navy tile (sidebar, collapsed rail, launcher, loading screen). */
export function SentinelTile({ size = 36, tone = "platform" }: { size?: number; tone?: MarkTone }) {
  return (
    <span className="inline-flex shrink-0 items-center justify-center rounded-[28%] bg-[#0B1220] ring-1 ring-inset ring-[#263449] shadow-sm"
      style={{ width: size, height: size }} aria-hidden>
      <SentinelMark size={Math.round(size * 0.66)} tone={tone} />
    </span>
  );
}

export const PRODUCT_NAME: Record<Product, string> = { nms: "Sentinel NMS", grid: "Sentinel Grid" };
export const PRODUCT_TAGLINE: Record<Product, string> = { nms: "Network Monitoring & Intelligence", grid: "Security Intelligence Platform" };

/** Mark + wordmark. With a product: "Sentinel NMS" / "Sentinel Grid" with the product word in its accent. */
export function SentinelLogo({ product, size = 28, tagline = false, tile = false, className = "" }: {
  product?: Product; size?: number; tagline?: boolean; tile?: boolean; className?: string;
}) {
  const accent = product === "grid" ? "text-violet-400" : "text-sky-400";
  return (
    <span className={`inline-flex items-center gap-2.5 min-w-0 ${className}`}>
      {tile ? <SentinelTile size={size + 8} tone={product || "platform"} /> : <SentinelMark size={size} tone={product || "platform"} />}
      <span className="min-w-0 leading-none">
        <span className="block font-semibold tracking-[-0.02em] text-slate-100 truncate" style={{ fontSize: Math.round(size * 0.62) }}>
          Sentinel{product && <span className={`ml-1 ${accent}`}>{product === "grid" ? "Grid" : "NMS"}</span>}
        </span>
        {tagline && product && <span className="block mt-1 text-[10.5px] font-medium tracking-[0.02em] text-subtle truncate">{PRODUCT_TAGLINE[product]}</span>}
      </span>
    </span>
  );
}

/** Full-screen loading state (session check). */
export function SplashScreen({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="h-full flex flex-col items-center justify-center gap-4 bg-bg" role="status" aria-live="polite">
      <SentinelTile size={48} />
      <span className="text-sm text-muted">{label}</span>
    </div>
  );
}
