/** Full-screen launch surfaces (sign-in, product selection, no access). Always the dark Sentinel navy, whatever the
 *  in-app theme: these are the brand's front door. A faint, static node-and-link pattern — no animation. */
import { ReactNode } from "react";

function NetworkPattern() {
  // a hexagonal lattice of nodes with a few links, drawn once as an SVG pattern
  return (
    <svg aria-hidden className="pointer-events-none absolute inset-0 h-full w-full" preserveAspectRatio="xMidYMid slice">
      <defs>
        <pattern id="sentinel-lattice" width="96" height="83" patternUnits="userSpaceOnUse">
          <g stroke="#38BDF8" strokeOpacity="0.10" strokeWidth="1" fill="none">
            <path d="M0 41.5 L24 0 M24 0 L72 0 M72 0 L96 41.5 M96 41.5 L72 83 M24 83 L0 41.5 M24 83 L48 41.5 L72 83" />
          </g>
          <g fill="#38BDF8" fillOpacity="0.22"><circle cx="24" cy="0" r="1.6" /><circle cx="72" cy="0" r="1.6" /><circle cx="0" cy="41.5" r="1.6" />
            <circle cx="96" cy="41.5" r="1.6" /><circle cx="48" cy="41.5" r="2" /><circle cx="24" cy="83" r="1.6" /><circle cx="72" cy="83" r="1.6" /></g>
        </pattern>
        <radialGradient id="sentinel-fade" cx="50%" cy="38%" r="70%"><stop offset="0" stopColor="#fff" stopOpacity="1" /><stop offset="1" stopColor="#fff" stopOpacity="0" /></radialGradient>
        <mask id="sentinel-mask"><rect width="100%" height="100%" fill="url(#sentinel-fade)" /></mask>
      </defs>
      <rect width="100%" height="100%" fill="url(#sentinel-lattice)" mask="url(#sentinel-mask)" />
    </svg>
  );
}

export function AuthShell({ children, header }: { children: ReactNode; header?: ReactNode }) {
  return (
    <div className="relative min-h-full w-full overflow-auto bg-[#0B1220] text-[#F1F5F9] [color-scheme:dark]">
      <NetworkPattern />
      <div aria-hidden className="pointer-events-none absolute inset-x-0 top-0 h-[28rem] bg-[radial-gradient(60rem_20rem_at_50%_-4rem,rgb(56_189_248/0.10),rgb(167_139_250/0.06)_45%,transparent_75%)]" />
      {header}
      <div className="relative">{children}</div>
    </div>
  );
}

/** Dark-surface form controls for the launch screens (fixed colours: these screens ignore the in-app theme). */
export const AUTH = {
  card: "rounded-2xl border border-[#263449] bg-[#111C2E]/90 backdrop-blur shadow-[0_24px_64px_-24px_rgb(2_6_23/0.8)]",
  input: "w-full rounded-lg border border-[#263449] bg-[#0F172A] px-3 py-2.5 text-sm text-[#F1F5F9] placeholder:text-[#64748B] transition-[border-color,box-shadow] " +
    "focus:outline-none focus:border-[#38BDF8]/70 focus:ring-2 focus:ring-[#38BDF8]/20",
  label: "block text-xs font-medium text-[#94A3B8] mb-1.5",
  primary: "inline-flex w-full items-center justify-center gap-2 rounded-lg bg-[#38BDF8] px-4 py-2.5 text-sm font-semibold text-[#0B1220] transition-colors " +
    "hover:bg-[#0EA5E9] disabled:opacity-50 disabled:pointer-events-none focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#38BDF8] focus-visible:ring-offset-2 focus-visible:ring-offset-[#0B1220]",
  ghost: "rounded-md border border-[#263449] px-2.5 py-1 text-xs text-[#CBD5E1] hover:bg-[#162238] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#38BDF8]",
  muted: "text-[#94A3B8]",
  subtle: "text-[#64748B]",
};

export function Spinner({ className = "" }: { className?: string }) {
  return <svg viewBox="0 0 24 24" width="16" height="16" className={`animate-spin ${className}`} aria-hidden>
    <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" strokeOpacity="0.25" strokeWidth="3" />
    <path d="M21 12a9 9 0 0 0-9-9" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" /></svg>;
}
