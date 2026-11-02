import { describe, expect, it } from "vitest";
import { TABS } from "./TacacsPage";
import { list } from "./common";

describe("TACACS+ module navigation", () => {
  it("exposes every required page as a URL-addressable tab", () => {
    const labels = TABS.map(([, l]) => l);
    for (const page of ["Overview", "Servers", "Device clients", "Users & identity sources", "Authentication policies", "Authorization & commands",
      "Accounting explorer", "Session audit", "Configuration studio", "Testing center", "Health & failover", "Security alerts", "Audit & changes"]) {
      expect(labels).toContain(page);
    }
    expect(new Set(TABS.map(([k]) => k)).size).toBe(TABS.length);
  });

  it("splits comma-separated form fields without empty entries", () => {
    expect(list(" WH1, ,FC2 ,")).toEqual(["WH1", "FC2"]);
    expect(list("")).toEqual([]);
  });
});
