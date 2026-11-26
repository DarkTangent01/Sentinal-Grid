/** @type {import('tailwindcss').Config} */
import plugin from "tailwindcss/plugin";
import twColors from "tailwindcss/colors";

// Sentinel design system (docs/design-system.md). Colours reference CSS variables so the UI switches between night
// (default) and day themes, and between the two products' accents, without component changes.
//
// - Neutrals: "slate" is mapped to the zinc scale (true neutral greys, no blue tint): #A1A1AA secondary, #71717A muted,
//   #52525B disabled; semantic surfaces (bg / panel / line) live in src/index.css.
// - brand: the product accent. Sentinel NMS = sky (#38BDF8, hover #0EA5E9), Sentinel Grid = violet (#A78BFA, hover
//   #8B5CF6), switched by <html data-product="…">. Components only ever say "brand".
// - Status hues are fixed in meaning: emerald = healthy (#22C55E family), amber = warning (#F59E0B), red = critical
//   (#EF4444), sky = informational (#38BDF8), slate = unknown / disabled (#64748B).
// The day theme mirrors each scale one step darker (400 → 700 …), so classes written for the dark UI (light text on
// dark surfaces) keep AA contrast on light surfaces.
const v = (name) => `rgb(var(--${name}) / <alpha-value>)`;
const HUES = ["slate", "sky", "emerald", "red", "amber", "orange", "teal", "violet", "indigo", "brand"];
const SCALES = {
  slate: twColors.zinc, sky: twColors.sky, emerald: twColors.green, red: twColors.red, amber: twColors.amber, orange: twColors.orange,
  teal: twColors.cyan, violet: twColors.violet, indigo: twColors.indigo,
};
const ACCENT = { nms: twColors.sky, grid: twColors.violet };
const SHADES = [50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 950];
const rgb = (hex) => { const n = parseInt(hex.slice(1), 16); return `${(n >> 16) & 255} ${(n >> 8) & 255} ${n & 255}`; };
const mirror = (scale, i) => scale[SHADES[Math.min(SHADES.length - 1, SHADES.length - i)]];

const paletteColors = Object.fromEntries(HUES.map((h) => [h, Object.fromEntries(SHADES.map((s) => [s, v(`c-${h}-${s}`)]))]));
const nightVars = {}, dayVars = {}, accentVars = { nms: [{}, {}], grid: [{}, {}] };
for (const h of HUES.filter((x) => x !== "brand")) {
  SHADES.forEach((s, i) => {
    nightVars[`--c-${h}-${s}`] = rgb(SCALES[h][s]);
    dayVars[`--c-${h}-${s}`] = rgb(mirror(SCALES[h], i));
  });
}
for (const [p, scale] of Object.entries(ACCENT)) {
  SHADES.forEach((s, i) => {
    accentVars[p][0][`--c-brand-${s}`] = rgb(scale[s]);
    accentVars[p][1][`--c-brand-${s}`] = rgb(mirror(scale, i));
  });
}
Object.assign(nightVars, accentVars.nms[0], { "--c-white": "255 255 255" });
Object.assign(dayVars, accentVars.nms[1], { "--c-white": rgb(twColors.zinc[900]) });

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: ["class", ":root:not(.light)"],
  theme: {
    extend: {
      colors: {
        ...paletteColors,
        white: v("c-white"),
        bg: v("bg"), panel: v("surface"), panel2: v("surface-2"), elevated: v("surface-3"), hover: v("surface-hover"), line: v("border"),
        "line-strong": v("border-strong"), disabled: v("text-disabled"),
        scrim: v("scrim"), muted: v("text-muted"), subtle: v("text-subtle"), accent: v("accent"), ok: v("ok"), warn: v("warn"), bad: v("bad"), info: v("info"),
        sev: { critical: v("sev-critical"), high: v("sev-high"), medium: v("sev-medium"), low: v("sev-low"), info: v("sev-info") },
        // solid fills carrying text (primary buttons, badges, logo tiles): per product and theme, tokens in index.css
        solid: { brand: v("solid-brand"), "brand-hover": v("solid-brand-hover"), on: v("solid-on") },
      },
      fontFamily: {
        sans: ["Inter Variable", "Inter", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "Roboto", "Helvetica Neue", "Arial", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
      fontSize: { "2xs": ["0.6875rem", "1rem"] },
      borderRadius: { card: "0.5rem" },
      boxShadow: {
        card: "none",
        pop: "0 8px 24px -8px rgb(var(--shadow) / 0.5)",
      },
      transitionTimingFunction: { out: "cubic-bezier(0.2, 0.8, 0.2, 1)" },
      keyframes: {
        "fade-in": { from: { opacity: "0" }, to: { opacity: "1" } },
        "pop-in": { from: { opacity: "0", transform: "translateY(4px) scale(0.98)" }, to: { opacity: "1", transform: "none" } },
        "slide-in": { from: { transform: "translateX(16px)", opacity: "0" }, to: { transform: "none", opacity: "1" } },
        shimmer: { "0%": { backgroundPosition: "-200% 0" }, "100%": { backgroundPosition: "200% 0" } },
      },
      animation: { "fade-in": "fade-in .15s ease-out", "pop-in": "pop-in .16s cubic-bezier(0.2,0.8,0.2,1)", "slide-in": "slide-in .2s cubic-bezier(0.2,0.8,0.2,1)",
                   shimmer: "shimmer 1.6s linear infinite" },
      screens: { xs: "480px", hd: "1360px" },  // hd: 1366×768 laptops (header fits one row from here)
    },
  },
  plugins: [plugin(({ addBase }) => addBase({
    ":root": nightVars, ":root.light": dayVars,
    ':root[data-product="grid"]': accentVars.grid[0], ':root.light[data-product="grid"]': accentVars.grid[1],
  }))],
};
