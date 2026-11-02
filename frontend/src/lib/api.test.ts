import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "./api";

afterEach(() => vi.unstubAllGlobals());

describe("api() request cancellation", () => {
  it("forwards the AbortSignal so a superseded query cancels its HTTP request", async () => {
    let seen: AbortSignal | undefined;
    vi.stubGlobal("document", { cookie: "" });
    vi.stubGlobal("fetch", vi.fn((_url: string, init: RequestInit) => {
      seen = init.signal ?? undefined;
      return new Promise((_resolve, reject) => init.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError"))));
    }));
    const ctl = new AbortController();
    const p = api("/analytics/kpis", { params: { range: "24h" }, signal: ctl.signal });
    ctl.abort();
    await expect(p).rejects.toThrow(/abort/i);
    expect(seen).toBe(ctl.signal);
  });
});
