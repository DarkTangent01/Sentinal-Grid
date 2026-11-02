import { describe, expect, it } from "vitest";
import { availTone, daysTone, describeScope, describeWindow, fmtAvail, fmtDaysLeft, fmtDur, scoreTone, serviceTarget } from "./nms";

describe("nms helpers", () => {
  it("formats durations", () => {
    expect(fmtDur(null)).toBe("—");
    expect(fmtDur(42)).toBe("42s");
    expect(fmtDur(600)).toBe("10m");
    expect(fmtDur(7500)).toBe("2h 05m");
    expect(fmtDur(90000)).toBe("1d 1h");
  });
  it("never shows an unmeasured availability as 0 %", () => {
    expect(fmtAvail(null)).toBe("—");
    expect(fmtAvail(99.9876)).toBe("99.988%");
    expect(fmtAvail(100)).toBe("100%");
    expect(fmtAvail(97.5)).toBe("97.50%");
    expect(availTone(null, 99.9)).toBeUndefined();
    expect(availTone(99.95, 99.9)).toBe("ok");
    expect(availTone(99.5, 99.9)).toBe("warn");
    expect(availTone(98, 99.9)).toBe("bad");
  });
  it("describes capacity forecasts", () => {
    expect(fmtDaysLeft(null)).toBe("not on current trend");
    expect(fmtDaysLeft(0)).toBe("now (over threshold)");
    expect(fmtDaysLeft(1)).toBe("1 day");
    expect(fmtDaysLeft(12.4)).toBe("12 days");
    expect(fmtDaysLeft(400)).toBe("> 1 year");
    expect(daysTone(5)).toBe("bad");
    expect(daysTone(20)).toBe("warn");
    expect(daysTone(90)).toBe("ok");
    expect(scoreTone(95)).toBe("ok");
    expect(scoreTone(null)).toBeUndefined();
  });
  it("describes maintenance windows and scope", () => {
    expect(describeWindow({ kind: "weekly", weekdays: [5, 6], start_time: "23:00", duration_minutes: 120, timezone: "Asia/Kolkata" }))
      .toBe("Every Sat, Sun at 23:00 Asia/Kolkata for 2h 00m");
    expect(describeWindow({ kind: "once", starts_at: "a", ends_at: "b" })).toBe("a → b");
    expect(describeScope({ all_devices: true })).toBe("All network alerts");
    expect(describeScope({ sites: ["WH1"], switch_ids: [1, 2], service_ids: [] }, { 1: "core", 2: "acc" })).toBe("site WH1 · core, acc");
    expect(describeScope({ switch_ids: [1, 2, 3, 4] })).toBe("4 devices");
  });
  it("shows service targets", () => {
    expect(serviceTarget({ kind: "tcp", target: "10.0.0.1", port: 22 })).toBe("10.0.0.1:22");
    expect(serviceTarget({ kind: "dns", target: "example.test", record: "AAAA" })).toBe("AAAA example.test");
    expect(serviceTarget({ kind: "http", target: "https://x.test/" })).toBe("https://x.test/");
  });
});
