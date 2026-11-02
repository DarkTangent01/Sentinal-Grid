import { describe, expect, it } from "vitest";
import { fmtBps, fmtPctOrDash, fmtUptime, fmtWatts, pairs, statusTone } from "./fmt";

describe("switch formatting", () => {
  it("formats bit rates and keeps missing values missing", () => {
    expect(fmtBps(50_000_000)).toBe("50.0 Mbit/s");
    expect(fmtBps(9_500_000_000)).toBe("9.50 Gbit/s");
    expect(fmtBps(0)).toBe("0 bit/s");
    expect(fmtBps(null)).toBe("—");
    expect(fmtPctOrDash(undefined)).toBe("—");
    expect(fmtPctOrDash(0)).toBe("0.0%");
    expect(fmtWatts(6.1)).toBe("6.1 W");
    expect(fmtUptime(864000 * 10 / 100)).toBe("1d 0h");
  });

  it("keeps nulls in chart pairs (gap, not zero) and sorts by time", () => {
    const p = pairs([{ t: "2026-10-28T10:01:00+00:00", v: null }, { t: "2026-10-28T10:00:00+00:00", v: 5 }, { t: "2026-10-28 10:02:00", v: 0 }], "v");
    expect(p.map((x) => x[1])).toEqual([5, null, 0]);
    expect(p[2][0]).toBe(Date.parse("2026-10-28T10:02:00Z"));
  });

  it("maps utilisation to tones", () => {
    expect(statusTone(95)).toBe("bad");
    expect(statusTone(75)).toBe("warn");
    expect(statusTone(10)).toBe("ok");
    expect(statusTone(null)).toBeUndefined();
  });
});

import { groupLinks, worstStatus } from "./fmt";

describe("topology helpers", () => {
  it("groups parallel links and keeps the worst status", () => {
    const l = (a: string, b: string, status: string) => ({ a: { node: a }, b: { node: b }, status });
    const g = groupLinks([l("sw:1", "sw:2", "up"), l("sw:2", "sw:1", "down"), l("sw:1", "ext:x", "lost")]);
    expect(g.length).toBe(2);
    expect(g.find((x) => x.b === "sw:2")!.status).toBe("down");
    expect(g.find((x) => x.links.length === 2)!.links.length).toBe(2);
    expect(worstStatus(["up", "degraded", "unknown"])).toBe("degraded");
    expect(worstStatus([])).toBe("up");
  });
});
