import { createContext, ReactNode, useContext, useEffect, useState } from "react";

export type Theme = "dark" | "light";
const KEY = "siem.theme";

export function initialTheme(): Theme {
  try {
    const saved = localStorage.getItem(KEY);
    if (saved === "light" || saved === "dark") return saved;
  } catch { /* storage unavailable */ }
  return "light"; // Zomato theme: day is the default; a saved choice (either way) still wins
}

export function applyTheme(t: Theme) {
  const el = document.documentElement;
  el.classList.toggle("light", t === "light");
  el.classList.toggle("dark", t === "dark");
}

const Ctx = createContext<{ theme: Theme; toggle: () => void; setTheme: (t: Theme) => void }>({ theme: "dark", toggle: () => {}, setTheme: () => {} });

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>(initialTheme);
  useEffect(() => {
    applyTheme(theme);
    try { localStorage.setItem(KEY, theme); } catch { /* ignore */ }
  }, [theme]);
  return <Ctx.Provider value={{ theme, setTheme, toggle: () => setTheme((t) => (t === "dark" ? "light" : "dark")) }}>{children}</Ctx.Provider>;
}

export const useTheme = () => useContext(Ctx);

export function ThemeToggle({ className = "" }: { className?: string }) {
  const { theme, toggle } = useTheme();
  const day = theme === "light";
  return (
    <button type="button" role="switch" aria-checked={day} aria-label={day ? "Switch to night theme" : "Switch to day theme"}
      title={day ? "Night theme" : "Day theme"} onClick={toggle}
      className={`inline-flex items-center gap-1.5 rounded-full border border-line bg-panel2 px-1 py-1 text-xs ${className}`}>
      <span className={`flex h-6 w-6 items-center justify-center rounded-full transition-colors ${!day ? "bg-brand-500/20 text-brand-300" : "text-slate-500"}`} aria-hidden>
        <svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" /></svg>
      </span>
      <span className={`flex h-6 w-6 items-center justify-center rounded-full transition-colors ${day ? "bg-brand-500/10 text-brand-400" : "text-slate-500"}`} aria-hidden>
        <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
          <circle cx="12" cy="12" r="4" fill="currentColor" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
        </svg>
      </span>
    </button>
  );
}
