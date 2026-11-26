/** Sentinel logo system (docs/design-system.md → Logo). One mark for the platform and both products; the product is
 *  told apart by its name and a solid accent colour. Geometry matches scripts/generate-brand.py (public/brand/*.svg,
 *  favicon) — change both together. */
import type { Product } from "../lib/products";

export const MARK_PATHS = ["M26.4 10 L16 4 L5.6 10 L16 16", "M5.6 22 L16 28 L26.4 22 L16 16"];
export const MARK_NODES: [number, number, number][] = [[26.4, 10, 2.25], [5.6, 22, 2.25], [16, 16, 3.1]];

export type MarkTone = "platform" | Product | "mono";
/** Solid colours, no gradients: the platform mark is neutral white; each product uses its own restrained accent. */
export const MARK_COLOR: Record<Exclude<MarkTone, "mono">, string> = { platform: "#F5F5F5", nms: "#38BDF8", grid: "#A78BFA" };

/** The mark alone. tone "mono" paints with currentColor (inherits the text colour). */
export function SentinelMark({ size = 24, tone = "platform", title, className = "" }: { size?: number; tone?: MarkTone; title?: string; className?: string }) {
  const paint = tone === "mono" ? "currentColor" : MARK_COLOR[tone];
  return (
    <svg viewBox="0 0 32 32" width={size} height={size} className={className} role={title ? "img" : undefined} aria-label={title} aria-hidden={title ? undefined : true}>
      <g fill="none" stroke={paint} strokeWidth={2.6} strokeLinecap="round" strokeLinejoin="round">{MARK_PATHS.map((d) => <path key={d} d={d} />)}</g>
      {MARK_NODES.map(([cx, cy, r]) => <circle key={`${cx}-${cy}`} cx={cx} cy={cy} r={r} fill={paint} />)}
    </svg>
  );
}

/** The mark on a plain black tile (launcher, loading screen): one hairline border, no shadow. */
export function SentinelTile({ size = 36, tone = "platform" }: { size?: number; tone?: MarkTone }) {
  return (
    <span className="inline-flex shrink-0 items-center justify-center rounded-[24%] bg-[#0A0A0A] border border-[#292929]"
      style={{ width: size, height: size }} aria-hidden>
      <SentinelMark size={Math.round(size * 0.62)} tone={tone} />
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
