/** @type {import('tailwindcss').Config} */
import plugin from "tailwindcss/plugin";
import twColors from "tailwindcss/colors";

// Colours reference CSS variables so the whole UI switches between night (default) and day themes.
// Semantic tokens live in src/index.css. The Tailwind hue palettes used across components (slate, sky, emerald,
// red, amber, orange, white) are also variables: the day theme mirrors each scale (shifted one step darker) so classes
// written for a dark UI (light text, dark hover surfaces) become dark text on light surfaces with the same contrast.
const v = (name) => `rgb(var(--${name}) / <alpha-value>)`;
const HUES = ["slate", "sky", "emerald", "red", "amber", "orange", "brand"];
// Zomato theme: "brand" is the Zomato red scale (500 = #E23744, 600 = #CB202D); "slate" maps to neutral greys so the
// UI reads warm-neutral like Zomato's surfaces instead of blue-grey. Class names stay unchanged across components.
const SCALES = {
  sky: twColors.sky, emerald: twColors.emerald, red: twColors.red, amber: twColors.amber, orange: twColors.orange,
  slate: twColors.neutral,
  brand: { 50: "#fff0f1", 100: "#ffdfe2", 200: "#ffc2c8", 300: "#ff96a0", 400: "#ef4f5f", 500: "#e23744",
           600: "#cb202d", 700: "#a81a25", 800: "#8b1821", 900: "#741820", 950: "#400a0e" },
};
const SHADES = [50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 950];
const rgb = (hex) => { const n = parseInt(hex.slice(1), 16); return `${(n >> 16) & 255} ${(n >> 8) & 255} ${n & 255}`; };

const paletteColors = Object.fromEntries(HUES.map((h) => [h, Object.fromEntries(SHADES.map((s) => [s, v(`c-${h}-${s}`)]))]));
const nightVars = {}, dayVars = {};
for (const h of HUES) {
  SHADES.forEach((s, i) => {
    nightVars[`--c-${h}-${s}`] = rgb(SCALES[h][s]);
    // mirror one step darker (400→700, 500→600, 600→500): text written as -400 for dark backgrounds needs
    // -700 on white to reach WCAG AA 4.5:1; translucent backgrounds stay light
    dayVars[`--c-${h}-${s}`] = rgb(SCALES[h][SHADES[Math.min(SHADES.length - 1, SHADES.length - i)]]);
  });
}
nightVars["--c-white"] = "255 255 255";
dayVars["--c-white"] = rgb(SCALES.slate[900]);

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: ["class", ":root:not(.light)"],
  theme: {
    extend: {
      colors: {
        ...paletteColors,
        white: v("c-white"),
        bg: v("bg"), panel: v("surface"), panel2: v("surface-2"), line: v("border"),
        muted: v("text-muted"), accent: v("accent"), ok: v("ok"), warn: v("warn"), bad: v("bad"),
        sev: { critical: v("sev-critical"), high: v("sev-high"), medium: v("sev-medium"), low: v("sev-low"), info: v("sev-info") },
      },
      // system stack only: no web-font download (CSP font-src is 'self'); Zomato's own typeface is not bundled
      fontFamily: { sans: ["Inter", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "Roboto", "Helvetica Neue", "Arial", "sans-serif"],
                    mono: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"] },
      fontSize: { "2xs": ["0.6875rem", "1rem"] },
      borderRadius: { card: "0.875rem" },
      boxShadow: { card: "0 1px 2px rgb(28 28 28 / 0.04), 0 4px 16px -8px rgb(28 28 28 / 0.10)" },
      screens: { xs: "480px" },
    },
  },
  plugins: [plugin(({ addBase }) => addBase({ ":root": nightVars, ":root.light": dayVars }))],
};
