/// <reference types="vite/client" />
// Static UI consistency guards over the component sources. Each rule encodes one decision of the UI standardisation
// pass (docs/ui/UI_CONSISTENCY_AUDIT.md); a failure names the file and the line so the fix is obvious.
import { describe, expect, it } from "vitest";

const sources = import.meta.glob("../**/*.tsx", { query: "?raw", import: "default", eager: true }) as Record<string, string>;
const files = Object.entries(sources).map(([path, text]) => ({ path: path.replace(/^\.\.\//, "src/"), text }));

/** Lines of every file matching `re`, as "path:line: text". */
function hits(re: RegExp, filter: (path: string) => boolean = () => true) {
  const out: string[] = [];
  for (const f of files) {
    if (!filter(f.path)) continue;
    f.text.split("\n").forEach((line, i) => { if (re.test(line)) out.push(`${f.path}:${i + 1}: ${line.trim().slice(0, 140)}`); });
  }
  return out;
}

// Brand artwork with fixed colours (sign-in and product selector illustrations), and the chart palette definitions.
// brand identity (logo gradients, the always-dark launch screens) is fixed in both themes by design; charts own their palette
const HEX_ALLOWED = ["src/pages/Login.tsx", "src/pages/ProductSelect.tsx", "src/components/Chart.tsx", "src/components/Brand.tsx", "src/components/AuthShell.tsx"];

describe("UI consistency", () => {
  it("found the component sources", () => {
    expect(files.length).toBeGreaterThan(60);
  });

  it("colours come from tokens, not hex literals", () => {
    // theme tokens: Tailwind classes (index.css / tailwind.config.js) and, for charts, CHART_THEME / SERIES_ROLE /
    // STATUS_HEX / PALETTES in components/Chart.tsx; hex literals do not follow the day / night theme
    expect(hits(/#[0-9a-fA-F]{6}\b/, (p) => !HEX_ALLOWED.includes(p))).toEqual([]);
  });

  it("CSS variables hold RGB triplets: never use var(--token) as a colour directly", () => {
    expect(hits(/\[var\(--(bg|surface|surface-2|border|text|text-muted|accent)\b/)).toEqual([]);
  });

  it("every table uses the shared .tbl styles", () => {
    expect(hits(/<table(?![^>]*className="[^"]*\btbl\b)/, (p) => p !== "src/pages/iac/common.tsx")).toEqual([]);
  });

  it("one pager and one sortable header for the whole app", () => {
    expect(hits(/^export function (Pager|SortTh)\b|^function (Pager|SortTh)\b/, (p) => p !== "src/components/ui.tsx"
      && p !== "src/pages/tacacs/common.tsx")).toEqual([]);  // tacacs: offset adapter that renders the shared Pager
    // hand-rolled Previous / Next buttons
    expect(hits(/>‹<\/button>|>Previous<\/button>/, (p) => p !== "src/components/ui.tsx")).toEqual([]);
  });

  it("clickable table rows are keyboard accessible (rowProps)", () => {
    expect(hits(/<tr\b[^>]*\bonClick=/)).toEqual([]);
    expect(hits(/<td\b[^>]*\bonClick=(?!\{\(e\) => e\.stopPropagation\(\)\})/)).toEqual([]);  // stopPropagation cells only shield inner controls
  });

  it("form captions are associated with their control", () => {
    // <div><label className="label">X</label><input/></div> names nothing: wrap the control in the label
    // (<Field label="X">) or point the label at it with htmlFor
    expect(hits(/<div[^>]*><label className="label"(?![^>]*htmlFor)/)).toEqual([]);
  });

  it("status colours have a single definition", () => {
    expect(hits(/STATE_HEX|\b(up|down|degraded): "#[0-9a-fA-F]/)).toEqual([]);
  });
});
