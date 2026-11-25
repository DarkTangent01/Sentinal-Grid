import { describe, expect, it } from "vitest";
import { activeFilterCount, apiParams, paramText, parseParam, pivot, readFilters, withFilters } from "./model";

describe("traffic filters in the URL", () => {
  it("validates and defaults", () => {
    const f = readFilters(new URLSearchParams("range=7d&vlan=20&port=abc&interface=3&evil=1&src=10.0.0.1"));
    expect(f).toEqual({ range: "7d", vlan: "20", src: "10.0.0.1" });            // bad port dropped, interface needs exporter, unknown key ignored
    expect(readFilters(new URLSearchParams("range=2y")).range).toBe("1h");
    expect(readFilters(new URLSearchParams("range=custom&start=2026-11-20T10:00")).range).toBe("1h");   // custom needs both ends
    expect(readFilters(new URLSearchParams("range=1h&start=2026-11-20T10:00")).start).toBeUndefined();
  });

  it("maps to API parameters", () => {
    expect(apiParams({ range: "24h", app: "HTTPS", vlan: "20" })).toEqual({ range: "24h", app: "HTTPS", vlan: "20" });
    const c = apiParams({ range: "custom", start: "2026-11-20T10:00:00Z", end: "2026-11-20T12:00:00Z" });
    expect(c).toEqual({ start: "2026-11-20T10:00:00.000Z", end: "2026-11-20T12:00:00.000Z" });
  });

  it("drill-down keeps filters and the tab, resets paging", () => {
    const sp = new URLSearchParams("tab=applications&range=24h&page=3&sort=-bytes&vlan=10");
    const n = withFilters(sp, { app: "QUIC", tab: "conversations", vlan: null });
    expect(n.get("app")).toBe("QUIC");
    expect(n.get("tab")).toBe("conversations");
    expect(n.get("range")).toBe("24h");
    expect(n.get("vlan")).toBeNull();
    expect(n.get("page")).toBeNull();
    expect(activeFilterCount(readFilters(n))).toBe(1);
  });
});

describe("series pivot", () => {
  it("fills missing series with zero and sorts by time", () => {
    const { rows, series } = pivot([{ t: "2", series: "B", bps: 5 }, { t: "1", series: "A", bps: 1 }, { t: "2", series: "A", bps: 2 }]);
    expect(series).toEqual(["B", "A"]);
    expect(rows).toEqual([{ t: "1", A: 1, B: 0 }, { t: "2", A: 2, B: 5 }]);
  });
});

describe("rule parameters", () => {
  it("parses by the default's type", () => {
    expect(parseParam(10, " 25 ")).toBe(25);
    expect(parseParam(10, "-1")).toBeNull();
    expect(parseParam(false, "true")).toBe(true);
    expect(parseParam([], "10.0.0.0/8, 192.168.1.1")).toEqual(["10.0.0.0/8", "192.168.1.1"]);
    expect(paramText(["a", "b"])).toBe("a, b");
  });
});
