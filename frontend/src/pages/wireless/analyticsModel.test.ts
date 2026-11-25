import { describe, expect, it } from "vitest";
import { dayIn, defaultRange, periodLabel, pivot, toParams } from "./analyticsModel";

describe("client analytics model", () => {
  it("takes calendar days in the user's timezone", () => {
    const now = new Date("2026-11-10T19:00:00Z");            // 00:30 on the 11th in India, still the 10th in UTC
    expect(dayIn("Asia/Kolkata", 0, now)).toBe("2026-11-11");
    expect(dayIn("UTC", 0, now)).toBe("2026-11-10");
    expect(defaultRange("day", "Asia/Kolkata", now)).toEqual({ start: "2026-11-05", end: "2026-11-11" });
    expect(defaultRange("week", "UTC", now).start).toBe("2026-08-19");
  });
  it("sends only the filters that are set", () => {
    expect(toParams({ start: "2026-11-01", end: "2026-11-07", period: "week", ssid: "CORP", ap: "", band: "5" })).toEqual({
      start_date: "2026-11-01", end_date: "2026-11-07", period: "week", controller_id: undefined, site: undefined, ssid: "CORP", ap_id: undefined,
      frequency_band: "5" });
  });
  it("pivots per-day rows without inventing zeros, keeping the top series", () => {
    const rows = [{ day: "2026-11-10", ssid: "CORP", unique_clients: 40 }, { day: "2026-11-11", ssid: "CORP", unique_clients: 42 },
      { day: "2026-11-11", ssid: "GUEST", unique_clients: 3 }, { day: "2026-11-10", ssid: "IOT", unique_clients: 1 }];
    const p = pivot(rows, "ssid", "unique_clients", 2);
    expect(p.days).toEqual(["2026-11-10", "2026-11-11"]);
    expect(p.series.map((s) => s.name)).toEqual(["CORP", "GUEST"]);
    expect(p.series[1].data).toEqual([null, 3]);                 // GUEST had no reading on the 10th: a gap, not 0
  });
  it("labels periods", () => {
    expect(periodLabel("2026-11-01", "month")).toMatch(/2026/);
    expect(periodLabel("2026-11-09", "week")).toMatch(/^wk of/);
  });
});
