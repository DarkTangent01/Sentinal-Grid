import { describe, expect, it } from "vitest";
import { freqLabel, utilLevel } from "./Rf";
import { ADMIN, NAV, activeItem } from "../../lib/products";

describe("RF formatting", () => {
  it("shows the bonded-block center only when it differs and never invents a frequency", () => {
    expect(freqLabel({ frequency_mhz: 5180, center_frequency_mhz: 5210 })).toBe("5180 MHz (center 5210)");
    expect(freqLabel({ frequency_mhz: 2437, center_frequency_mhz: 2437 })).toBe("2437 MHz");
    expect(freqLabel({ frequency_mhz: null, center_frequency_mhz: null })).toBe("—");
  });
  it("keeps an unmeasured utilisation distinct from a low one", () => {
    expect(utilLevel(null)).toBe("none");
    expect(utilLevel(0)).toBe("ok");
    expect(utilLevel(65, 80)).toBe("elevated");
    expect(utilLevel(80, 80)).toBe("high");
    expect(utilLevel(72, 70)).toBe("high");
  });
  it("routes the RF section under Sentinel NMS navigation", () => {
    const nms = [...NAV.nms, ADMIN];
    expect(activeItem(nms, "/wireless", "?tab=rf-findings&rule=high_noise")).toBe("/wireless?tab=rf-findings");
    expect(activeItem(nms, "/wireless", "?tab=rf-radios")).toBe("/wireless?tab=rf-radios");
  });
});
