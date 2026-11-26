/** Full-screen launch surfaces (sign-in, product selection, no access). Always plain black, whatever the in-app theme:
 *  no pattern, no gradient, no animation. */
import { ReactNode } from "react";

export function AuthShell({ children, header }: { children: ReactNode; header?: ReactNode }) {
  return (
    <div className="relative min-h-full w-full overflow-auto bg-[#090909] text-[#F5F5F5] [color-scheme:dark]">
      {header}
      <div className="relative">{children}</div>
    </div>
  );
}

/** Dark-surface form controls for the launch screens (fixed colours: these screens ignore the in-app theme). */
export const AUTH = {
  card: "rounded-xl border border-[#292929] bg-[#111111]",
  input: "w-full rounded-md border border-[#292929] bg-[#0A0A0A] px-3 py-2 text-sm text-[#F5F5F5] placeholder:text-[#71717A] transition-colors " +
    "focus:outline-none focus:border-[#52525B]",
  label: "block text-xs font-medium text-[#A1A1AA] mb-1.5",
  primary: "inline-flex w-full items-center justify-center gap-2 rounded-md bg-[#F5F5F5] px-4 py-2 text-sm font-medium text-[#090909] transition-colors " +
    "hover:bg-[#D4D4D8] disabled:opacity-50 disabled:pointer-events-none focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#A1A1AA] focus-visible:ring-offset-2 focus-visible:ring-offset-[#090909]",
  ghost: "rounded-md border border-[#292929] px-2.5 py-1 text-xs text-[#D4D4D8] hover:bg-[#1C1C1C] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#A1A1AA]",
  muted: "text-[#A1A1AA]",
  subtle: "text-[#71717A]",
};

export function Spinner({ className = "" }: { className?: string }) {
  return <svg viewBox="0 0 24 24" width="16" height="16" className={`animate-spin ${className}`} aria-hidden>
    <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" strokeOpacity="0.25" strokeWidth="3" />
    <path d="M21 12a9 9 0 0 0-9-9" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" /></svg>;
}
