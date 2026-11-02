import { describe, expect, it } from "vitest";
import { highlight } from "./Studio";
import { can } from "./common";

describe("IaC studio highlighter", () => {
  it("escapes markup in user text (the result is rendered as HTML)", () => {
    const out = highlight('  comment: "<img src=x onerror=alert(1)>" # <script>alert(1)</script>');
    expect(out).not.toContain("<img");
    expect(out).not.toContain("<script>");
    expect(out).toContain("&lt;img");
    expect(out).toContain("&lt;script&gt;");
  });
  it("marks keys, variables and comments", () => {
    const out = highlight('    - {name: LAN, subnet: "${lan}"} # office');
    expect(out).toContain('name</span>');
    expect(out).toContain("text-sky-700");
    expect(out).toContain("text-violet-600");
    expect(out).toContain("italic");
  });
});

describe("IaC role gating (UI mirror of backend checks)", () => {
  it("viewer is implicit, other roles must be granted", () => {
    expect(can({ roles: ["viewer"] }, "viewer")).toBe(true);
    expect(can({ roles: ["editor"] }, "approver")).toBe(false);
    expect(can({ roles: ["editor", "approver", "deployer", "admin"] }, "deployer")).toBe(true);
    expect(can(undefined, "editor")).toBe(false);
  });
});
