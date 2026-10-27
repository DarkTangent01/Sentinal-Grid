import { describe, expect, it } from "vitest";
import { escHtml } from "./format";

describe("escHtml", () => {
  it("neutralises markup from log fields before it reaches an ECharts tooltip", () => {
    // e.g. a spoofed syslog subtype / country rendered in a Donut or WorldMap tooltip
    expect(escHtml('<img src=x onerror="alert(1)">')).toBe("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;");
    expect(escHtml("a&b 'c'")).toBe("a&amp;b &#39;c&#39;");
  });

  it("handles non-string values", () => {
    expect(escHtml(null)).toBe("");
    expect(escHtml(42)).toBe("42");
  });
});
