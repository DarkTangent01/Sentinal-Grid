import { describe, expect, it } from "vitest";
import { matrixCounts, pctTone, vendorKey } from "./snmp";

describe("snmp helpers", () => {
  it("groups vendors", () => {
    expect(vendorKey("juniper")).toBe("juniper");
    expect(vendorKey("generic")).toBe("other");
    expect(vendorKey(undefined)).toBe("other");
  });
  it("counts matrix cells", () => {
    expect(matrixCounts({ a: "observed", b: "observed", c: "unsupported" })).toMatchObject({ observed: 2, unsupported: 1, implemented: 0 });
  });
  it("tones polling success", () => {
    expect(pctTone(null)).toBeUndefined();
    expect(pctTone(99.5)).toBe("ok");
    expect(pctTone(95)).toBe("warn");
    expect(pctTone(50)).toBe("bad");
  });
});
