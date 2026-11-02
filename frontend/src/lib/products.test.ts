/// <reference types="vite/client" />
import { describe, expect, it } from "vitest";
import { ADMIN, NAV, PRODUCT, activeItem, entryTarget, productOfLocation } from "./products";

const app = Object.values(import.meta.glob("../App.tsx", { query: "?raw", import: "default", eager: true }))[0] as string;
const routes = [...app.matchAll(/<Route path="([^"]+)"/g)].map((m) => m[1]);
const routeExists = (to: string) => {
  const path = to.split("?")[0];
  return routes.some((r) => r === path || (r.includes(":") && new RegExp(`^${r.replace(/:[^/]+/g, "[^/]+")}$`).test(path)));
};

describe("product routing", () => {
  it("assigns pages to products by purpose", () => {
    expect(productOfLocation("/incidents/12")).toBe("grid");
    expect(productOfLocation("/threat-intel")).toBe("grid");
    expect(productOfLocation("/vpn")).toBe("grid");
    expect(productOfLocation("/vpn-tunnels")).toBe("nms");
    expect(productOfLocation("/switches/4")).toBe("nms");
    expect(productOfLocation("/policies/1/root/7")).toBe("nms");
    expect(productOfLocation("/tacacs")).toBe("nms");
    expect(productOfLocation("/settings")).toBeNull();
    expect(productOfLocation("/reports")).toBeNull();
    expect(productOfLocation("/alerts", "?product=nms")).toBe("nms");
    expect(productOfLocation("/alerts")).toBeNull();
  });
  it("decides where sign-in lands", () => {
    expect(entryTarget({ products: [] })).toBe("/no-access");
    expect(entryTarget({ products: ["grid"] })).toBe("/grid");
    expect(entryTarget({ products: ["nms"] })).toBe("/nms");
    expect(entryTarget({ products: ["grid", "nms"] })).toBe("/select-product");
    expect(entryTarget({ products: ["grid", "nms"], default_product: "nms" })).toBe("/nms");
    expect(entryTarget({ products: ["grid"], default_product: "nms" })).toBe("/grid");   // a stale default never widens access
  });
  it("highlights the item whose tab matches, else the path", () => {
    const nms = [...NAV.nms, ADMIN];
    expect(activeItem(nms, "/isp", "?tab=sdwan")).toBe("/isp?tab=sdwan");
    expect(activeItem(nms, "/isp", "?tab=incidents&id=4")).toBe("/isp?tab=incidents");
    expect(activeItem(nms, "/isp", "")).toBe("/isp?tab=overview");
    expect(activeItem(nms, "/tacacs", "?tab=clients")).toBe("/tacacs?tab=clients");
    expect(activeItem(nms, "/tacacs", "?tab=servers")).toBe("/tacacs");
    expect(activeItem(nms, "/policies/shadow", "")).toBe("/policies/shadow");
    expect(activeItem(nms, "/nms", "")).toBe("/nms");
    expect(activeItem([...NAV.grid, ADMIN], "/incidents/3", "")).toBe("/incidents");
    expect(activeItem([...NAV.grid, ADMIN], "/settings", "")).toBe("/settings");
  });
  it("keeps each sidebar free of duplicates and dead links", () => {
    for (const p of ["grid", "nms"] as const) {
      const items = [...NAV[p], ADMIN].flatMap((g) => g.items);
      expect(new Set(items.map((i) => i.to)).size).toBe(items.length);
      expect(new Set(items.map((i) => i.label)).size).toBe(items.length);
      for (const it of items) if (!it.planned) expect(routeExists(it.to), `${p}: ${it.to}`).toBe(true);
      for (const it of items) if (!it.planned) {
        const owner = productOfLocation(it.to.split("?")[0], it.to.includes("?") ? it.to.slice(it.to.indexOf("?")) : "");
        expect(owner === null || owner === p, `${p} nav links to ${owner} page ${it.to}`).toBe(true);
      }
    }
    expect(routeExists(PRODUCT.grid.home) && routeExists(PRODUCT.nms.home)).toBe(true);
  });
  it("keeps every previously existing page reachable", () => {
    for (const r of ["/sources", "/destinations", "/ports", "/web", "/dns", "/security", "/alerts", "/explorer", "/firewalls", "/hardening", "/policies",
      "/policies/shadow", "/incidents", "/threat-intel", "/assets", "/geo", "/vpn", "/compliance", "/drift", "/notifications", "/searches", "/reports",
      "/search", "/hunting", "/detections", "/workbooks", "/watchlists", "/automation", "/graph", "/isp", "/fw-health", "/vpn-tunnels", "/bgp",
      "/identity", "/iac", "/switches", "/tacacs", "/log-sources", "/settings"]) expect(routeExists(r), r).toBe(true);
  });
});
