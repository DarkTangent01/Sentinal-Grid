import { describe, expect, it } from "vitest";
import { dur, ms, pct, rangeParams, stackedDaily, availText } from "./fmt";

describe("wan formatting", () => {
  it("formats durations like the reference dashboard", () => {
    expect(dur(null)).toBe("—");
    expect(dur(0)).toBe("0s");
    expect(dur(45)).toBe("45s");
    expect(dur(127)).toBe("2m 7s");
    expect(dur(5880)).toBe("1h 38m");
    expect(dur(166_000)).toBe("1d 22h 6m");
  });
  it("never renders missing measurements as zero", () => {
    expect(ms(null)).toBe("—");
    expect(pct(undefined)).toBe("—");
    expect(availText(null)).toBe("—");
    expect(ms(0)).toBe("0.00 ms");
    expect(availText(100)).toBe("100%");
  });
  it("builds custom ranges and falls back for incomplete ones", () => {
    expect(rangeParams({ range: "7d" })).toEqual({ range: "7d" });
    expect(rangeParams({ range: "custom" })).toEqual({ range: "24h" });
    const r = rangeParams({ range: "custom", start: "2026-10-01T00:00", end: "2026-10-02T00:00" }) as any;
    expect(r.start < r.end && !("range" in r)).toBe(true);
  });
  it("stacks one series per ISP and keeps zero days", () => {
    const s = stackedDaily({ days: ["2026-10-01", "2026-10-02", "2026-10-03"], series: [
      { isp: "TTSL", counts: [2, 0, 1], sites: [["ASF"], [], ["ASF"]] }, { isp: "Jio", counts: [0, 0, 3], sites: [[], [], ["ZFSL"]] }] }, ["#a", "#b"]);
    expect(s.categories.length).toBe(3);
    expect(s.series.map((x) => x.name)).toEqual(["TTSL", "Jio"]);
    expect(s.series[0].data[1].value).toBe(0);
    expect(s.series[1].itemStyle.color).toBe("#b");
    expect(s.series[1].data[2].sites).toEqual(["ZFSL"]);
    expect(s.total).toBe(6);
  });
});
