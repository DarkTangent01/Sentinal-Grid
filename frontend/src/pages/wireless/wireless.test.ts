import { describe, expect, it } from "vitest";
import { bytes, dash, dbm, dur, pctv } from "./common";
import { ADMIN, NAV, activeItem } from "../../lib/products";

describe("wireless formatting", () => {
  it("never shows a missing measurement as zero", () => {
    expect(dbm(null)).toBe("—");
    expect(pctv(undefined)).toBe("—");
    expect(dash(null, " MHz")).toBe("—");
    expect(dbm(-67)).toBe("-67 dBm");
    expect(pctv(0)).toBe("0%");
    expect(bytes(null)).toBe("—");
    expect(bytes(2_500_000)).toBe("2.5 MB");
    expect(dur(7200)).toBe("2h 0m");
    expect(dur(null)).toBe("—");
  });
  it("highlights Wireless Alerts over the generic Network Alerts", () => {
    const nms = [...NAV.nms, ADMIN];
    expect(activeItem(nms, "/alerts", "?product=nms&rule_prefix=wireless_")).toBe("/alerts?product=nms&rule_prefix=wireless_");
    expect(activeItem(nms, "/alerts", "?product=nms")).toBe("/alerts?product=nms");
    expect(activeItem(nms, "/wireless", "?tab=rf-heatmap&band=5")).toBe("/wireless?tab=rf-heatmap");
    expect(activeItem(nms, "/wireless", "")).toBe("/wireless?tab=overview");
  });
});
