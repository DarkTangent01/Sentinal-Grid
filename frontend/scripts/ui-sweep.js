// UI sweep: visits every route in the running app and reports layout and accessibility problems.
//
// Runs inside the browser against a signed-in session (dev server or a deployed instance), with no extra
// dependency. From the browser console or an automation tool:
//
//   const { uiSweep } = await import("/scripts/ui-sweep.js");   // dev server serves this file
//   const report = await uiSweep();                               // every sidebar link of the current product
//   const report = await uiSweep({ routes: ["/nms", "/switches"], settleMs: 6000 });
//
// Checks per route:
//   overflow    the page itself scrolls sideways (tables and charts must scroll inside their own wrapper)
//   errors      console errors / uncaught exceptions and failed API calls (HTTP >= 500) while the route loaded
//   alerts      visible [role=alert] messages (load failures are reported, never hidden)
//   unlabeled   form controls without an accessible name
//   nameless    buttons / links without an accessible name
//   imgs        role=img (charts) and <img> without a text alternative
//   bareTables  tables that are not inside a horizontally scrollable wrapper
//   stuck       loading placeholders still showing after settleMs
// It only navigates and reads the DOM: it never clicks, submits or changes data.

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function accessibleName(el) {
  const by = el.getAttribute("aria-labelledby");
  if (by) return by.split(/\s+/).map((id) => document.getElementById(id)?.textContent || "").join(" ").trim();
  const aria = el.getAttribute("aria-label");
  if (aria && aria.trim()) return aria.trim();
  if (el.id) {
    const lab = document.querySelector(`label[for="${CSS.escape(el.id)}"]`);
    if (lab && lab.textContent.trim()) return lab.textContent.trim();
  }
  const wrap = el.closest("label");
  if (wrap && wrap.textContent.trim()) return wrap.textContent.trim();
  if (el.getAttribute("title")) return el.getAttribute("title").trim();
  return "";
}

const visible = (el) => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
const describe = (el) => {
  const id = el.id ? `#${el.id}` : "";
  const cls = typeof el.className === "string" && el.className ? `.${el.className.trim().split(/\s+/).slice(0, 2).join(".")}` : "";
  const txt = (el.getAttribute("placeholder") || el.textContent || "").trim().slice(0, 40);
  return `${el.tagName.toLowerCase()}${id}${cls}${txt ? ` "${txt}"` : ""}`;
};

function scrollableX(el) {
  for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) {
    const ox = getComputedStyle(p).overflowX;
    if (ox === "auto" || ox === "scroll") return true;
  }
  return false;
}

function inspect() {
  const doc = document.documentElement;
  const main = document.querySelector("main");
  const r = {
    overflow: doc.scrollWidth > doc.clientWidth + 1 ? `page ${doc.scrollWidth}px > ${doc.clientWidth}px` : null,
    mainOverflow: main && main.scrollWidth > main.clientWidth + 1 ? `main ${main.scrollWidth}px > ${main.clientWidth}px` : null,
    alerts: [...document.querySelectorAll("[role=alert]")].filter(visible).map((e) => e.textContent.trim().slice(0, 120)),
    unlabeled: [...document.querySelectorAll("input:not([type=hidden]), select, textarea")].filter(visible)
      .filter((e) => !accessibleName(e)).map(describe),
    nameless: [...document.querySelectorAll("button, a[href], [role=button], [role=tab]")].filter(visible)
      .filter((e) => !accessibleName(e) && !e.textContent.trim()).map((e) => describe(e) + ` ${e.outerHTML.slice(0, 80)}`),
    imgs: [...document.querySelectorAll("[role=img], img")].filter(visible)
      .filter((e) => !(e.getAttribute("aria-label") || e.getAttribute("aria-labelledby") || e.getAttribute("alt") !== null && e.tagName === "IMG"))
      .map(describe),
    bareTables: [...document.querySelectorAll("table")].filter(visible).filter((t) => !scrollableX(t)).map(describe),
    stuck: [...document.querySelectorAll("main .animate-pulse, main [role=status]")].filter(visible).length,
  };
  for (const k of Object.keys(r)) if (Array.isArray(r[k])) r[k] = [...new Set(r[k])];
  return r;
}

function sidebarRoutes() {
  return [...new Set([...document.querySelectorAll("#sidebar nav a[href]")].map((a) => a.getAttribute("href")))];
}

async function settle(settleMs) {
  const t0 = Date.now();
  await sleep(400);
  while (Date.now() - t0 < settleMs) {
    const busy = document.querySelectorAll("main .animate-pulse, main [role=status]").length;
    if (!busy) { await sleep(300); return; }
    await sleep(250);
  }
}

export async function uiSweep({ routes, settleMs = 5000 } = {}) {
  const list = routes || sidebarRoutes();
  const errors = [];
  const origError = console.error;
  console.error = (...a) => { errors.push(a.map(String).join(" ").slice(0, 200)); origError.apply(console, a); };
  const onErr = (e) => errors.push(`uncaught: ${e.message || e.reason}`);
  window.addEventListener("error", onErr);
  window.addEventListener("unhandledrejection", onErr);
  const origFetch = window.fetch;
  window.fetch = async (...a) => {
    const res = await origFetch(...a);
    if (res.status >= 500) errors.push(`HTTP ${res.status} ${String(a[0]).slice(0, 120)}`);
    return res;
  };
  const results = [];
  try {
    for (const route of list) {
      errors.length = 0;
      history.pushState({}, "", route);
      dispatchEvent(new PopStateEvent("popstate"));
      await settle(settleMs);
      results.push({ route, viewport: `${innerWidth}x${innerHeight}`, ...inspect(), errors: [...new Set(errors)] });
    }
  } finally {
    console.error = origError;
    window.fetch = origFetch;
    window.removeEventListener("error", onErr);
    window.removeEventListener("unhandledrejection", onErr);
  }
  const problems = results.filter((r) => r.overflow || r.mainOverflow || r.errors.length || r.unlabeled.length || r.nameless.length
    || r.imgs.length || r.bareTables.length || r.stuck || r.alerts.length);
  return {
    routes: results.length,
    clean: results.length - problems.length,
    totals: {
      overflow: results.filter((r) => r.overflow || r.mainOverflow).length,
      errors: results.reduce((a, r) => a + r.errors.length, 0),
      alerts: results.reduce((a, r) => a + r.alerts.length, 0),
      unlabeled: results.reduce((a, r) => a + r.unlabeled.length, 0),
      nameless: results.reduce((a, r) => a + r.nameless.length, 0),
      imgs: results.reduce((a, r) => a + r.imgs.length, 0),
      bareTables: results.reduce((a, r) => a + r.bareTables.length, 0),
      stuck: results.filter((r) => r.stuck).length,
    },
    problems,
  };
}
