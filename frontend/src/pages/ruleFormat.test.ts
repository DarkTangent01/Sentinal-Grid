import { describe, expect, it } from "vitest";
import { fmtStats, fmtTimeframe } from "./ruleFormat";

describe("rule pack helpers", () => {
  it("formats time frames", () => {
    expect(fmtTimeframe(300)).toBe("5 min");
    expect(fmtTimeframe(3600)).toBe("1 h");
    expect(fmtTimeframe(90)).toBe("90 s");
    expect(fmtTimeframe(86400)).toBe("1 d");
    expect(fmtTimeframe(null)).toBe("—");
  });
  it("formats run statistics without inventing values", () => {
    expect(fmtStats(null)).toBe("never run");
    expect(fmtStats({ last_run: "x", error: "TimeoutError: slow" })).toBe("error: TimeoutError: slow");
    expect(fmtStats({ last_run: "x", matches: 2, duration_ms: 14.4 })).toBe("2 match(es) · 14 ms");
  });
});
