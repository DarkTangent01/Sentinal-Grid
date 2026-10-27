import { describe, expect, it } from "vitest";
import { fmtPct, sumKey, toTimePairs, topNWithOther } from "./chartData";

describe("topNWithOther", () => {
  const rows = Array.from({ length: 12 }, (_, i) => ({ key: `c${i}`, value: 100 - i * 5 }));

  it("folds the tail into Other without losing counts", () => {
    const { slices, total } = topNWithOther(rows, 8);
    expect(slices).toHaveLength(8);
    expect(slices[7].name).toBe("Other (5)");
    expect(slices[7].members).toEqual(["c7", "c8", "c9", "c10", "c11"]);
    expect(slices.reduce((a, s) => a + s.value, 0)).toBe(total);
    expect(slices.reduce((a, s) => a + s.pct, 0)).toBeCloseTo(100, 6);
  });

  it("keeps everything when under the limit and ignores zero/invalid rows", () => {
    const { slices, total } = topNWithOther([{ key: "a", value: 3 }, { key: "b", value: 1 }, { key: "z", value: 0 }, { key: "n", value: NaN }], 8);
    expect(slices.map((s) => s.name)).toEqual(["a", "b"]);
    expect(total).toBe(4);
    expect(slices[0].pct).toBe(75);
  });

  it("handles empty input", () => {
    expect(topNWithOther([], 8)).toEqual({ slices: [], total: 0 });
  });
});

describe("time pairs", () => {
  it("parses UTC timestamps, sorts them and keeps real zeros", () => {
    const pts = [{ t: "2026-10-22T12:15:00Z", events: 0 }, { t: "2026-10-22 12:00:00", events: 5 }];
    const pairs = toTimePairs(pts, "events");
    expect(pairs).toEqual([[Date.UTC(2026, 9, 22, 12, 0), 5], [Date.UTC(2026, 9, 22, 12, 15), 0]]);
    expect(sumKey(pts, "events")).toBe(5);
  });
});

describe("fmtPct", () => {
  it("formats small and large percentages", () => {
    expect(fmtPct(0.04)).toBe("<0.1%");
    expect(fmtPct(4.26)).toBe("4.3%");
    expect(fmtPct(42.6)).toBe("43%");
  });
});
