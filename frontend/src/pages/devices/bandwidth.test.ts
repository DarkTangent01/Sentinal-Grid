import { describe, expect, it } from "vitest";
import { autoUnit, fmtBytesTotal, fmtIn, inUnit, peakOf, resolveUnit, shifted } from "./bandwidth";

describe("bandwidth units", () => {
  it("chooses Mbps or Gbps by scale and converts bytes correctly", () => {
    expect(autoUnit(9.4e9)).toBe("Gbps");
    expect(autoUnit(250e6)).toBe("Mbps");
    expect(autoUnit(12e3)).toBe("Kbps");
    expect(resolveUnit("MB/s", 1e9)).toBe("MB/s");
    expect(inUnit(8e6, "MB/s")).toBe(1);
    expect(inUnit(1e9, "Gbps")).toBe(1);
    expect(fmtIn(1.234e9, "Gbps")).toBe("1.23 Gbps");
    expect(fmtIn(null, "Mbps")).toBe("—");
  });
  it("never invents values and moves comparison series onto the current axis", () => {
    expect(inUnit(undefined, "Mbps")).toBeNull();
    expect(peakOf([{ rx_bps: null, tx_bps: 5 }, { rx_bps: 7 }])).toBe(7);
    expect(shifted([{ t: "2026-11-25T10:00:00.000Z", rx_bps: 1 }], 86400)[0].t).toBe("2026-11-26T10:00:00.000Z");
    expect(fmtBytesTotal(1_500_000_000)).toBe("1.5 GB");
    expect(fmtBytesTotal(null)).toBe("—");
  });
});
