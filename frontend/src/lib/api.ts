export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

function csrf(): string {
  const m = document.cookie.match(/(?:^|; )siem_csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : "";
}

export type Params = Record<string, string | number | boolean | undefined | null | (string | number)[]>;

export function qs(params?: Params): string {
  if (!params) return "";
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "") continue;
    if (Array.isArray(v)) v.forEach((x) => u.append(k, String(x)));
    else u.append(k, String(v));
  }
  const s = u.toString();
  return s ? `?${s}` : "";
}

export async function api<T = any>(path: string, opts: { method?: string; body?: unknown; params?: Params } = {}): Promise<T> {
  const method = opts.method ?? "GET";
  const headers: Record<string, string> = { Accept: "application/json" };
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") headers["X-CSRF-Token"] = csrf();
  const res = await fetch(`/api${path}${qs(opts.params)}`, {
    method, headers, credentials: "same-origin", body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  if (res.status === 401 && !path.startsWith("/auth/")) {
    window.dispatchEvent(new Event("siem:unauthorized"));
  }
  if (!res.ok) {
    let msg = res.statusText;
    try {
      const j = await res.json();
      msg = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail);
    } catch { /* ignore */ }
    throw new ApiError(res.status, msg);
  }
  return res.json();
}

export function downloadUrl(path: string, params?: Params) {
  return `/api${path}${qs(params)}`;
}
