import logging
import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import text

from .api import access, admin, identities, netops, notifications, playbooks, reports, traffic, wireless_integrations, alerts, analytics, auth, configs, context, firewalls, flows, hardening, hunt, iac, devices, identity, isp, ops, policies, soc, switches, tacacs, wan, wireless, wireless_analytics, wireless_rf, nms, snmp, yaml_rules, netcompliance, ingest, siem
from .config import get_settings
from .db.ch import get_ch
from .db.pg import get_engine
from .api.deps import require_admin
from .logging_setup import setup_logging
from .observability import METRICS, access_log, new_request_id, request_id, route_of

log = logging.getLogger("api")

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                               "script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; "
                               "form-action 'self'; frame-ancestors 'none'",
    "Cache-Control": "no-store",
}


# routers per product (docs/architecture/MODULE_OWNERSHIP_MATRIX.md); SHARED_ROUTERS are mounted by every product app
SHARED_ROUTERS = (auth.router, alerts.router, admin.router, notifications.router, reports.router, identities.router)
PRODUCT_ROUTERS = {
    "grid": (analytics.router, context.router, soc.router, hunt.router, ops.router, identity.router, yaml_rules.router, ingest.router,
             siem.router),
    "nms": (firewalls.router, hardening.router, policies.router, isp.router, iac.router, switches.router, tacacs.router, wan.router,
            wireless.router, wireless_integrations.router, wireless_analytics.router, wireless_rf.router, configs.router, flows.router,
            nms.router, snmp.router, netcompliance.router, netops.router, traffic.router, devices.router),
}
TITLES = {None: "Sentinel Grid", "grid": "Sentinel Grid", "nms": "Sentinel NMS"}


def create_app(component: str = "api", product: str | None = None) -> FastAPI:
    """component "api": the main API (plus the device-access router when ACCESS_GATEWAY_INPROCESS is set, as in development
    and tests). component "access": the Device Access Gateway service (app/access): authentication checks and the
    device-access router only.

    product: "grid" or "nms" builds that product's API alone (its routers, alert rules and report sections, plus the
    shared services); None (default) is today's combined API with both products. PRODUCT (environment) sets it for
    uvicorn's factory mode (app.main:create_product_app)."""
    if product not in (None, "grid", "nms"):
        raise ValueError(f"unknown product: {product}")
    s = get_settings()
    setup_logging(s.log_level)
    from .composition import load
    load("nms" if component == "access" else product)   # registrations: alert rules, report sections
    if len(s.secret_key) < 32:
        raise RuntimeError("SECRET_KEY must be set to at least 32 characters")

    @asynccontextmanager
    async def lifespan(app):
        log.info("%s starting (demo_mode=%s)", component, s.demo_mode)
        if component == "access" or s.access_gateway_inprocess:
            # sessions and bulk jobs live in the gateway process: whatever a previous process left open cannot continue
            from .access.diagnostics import mark_orphans
            from .access.terminal import close_orphans
            try:
                n, m = await mark_orphans(), await close_orphans()
                if n or m:
                    log.warning("gateway start: %d interrupted diagnostic job(s) marked failed, %d session(s) closed", n, m)
            except Exception:
                log.exception("could not check for interrupted access sessions and jobs")
        yield
        await get_engine().dispose()
        log.info("api stopped")

    app = FastAPI(title=TITLES[product], version="1.0.0", lifespan=lifespan,
                  docs_url="/api/docs" if s.environment != "production" else None,
                  openapi_url="/api/openapi.json" if s.environment != "production" else None, redoc_url=None)

    @app.middleware("http")
    async def headers(request: Request, call_next):
        rid = new_request_id(request.headers.get("x-request-id"))
        token = request_id.set(rid)
        t0 = time.perf_counter()
        try:
            try:
                resp = await call_next(request)
            except Exception:
                log.exception("unhandled error on %s %s", request.method, request.url.path)
                resp = JSONResponse({"detail": "internal error", "request_id": rid}, status_code=500)
            for k, v in SECURITY_HEADERS.items():
                resp.headers.setdefault(k, v)
            resp.headers["X-Request-ID"] = rid
            took = time.perf_counter() - t0
            route = route_of(request)
            METRICS.observe(request.method, route, resp.status_code, took)
            if route not in ("/api/health", "/api/ready"):  # container health checks would flood the log
                access_log.info("%s %s %d %.1fms", request.method, route, resp.status_code, took * 1000,
                                extra={"duration_ms": round(took * 1000, 1), "status": resp.status_code})
            return resp
        finally:
            request_id.reset(token)

    if component == "access":
        app.include_router(playbooks.router)
        app.include_router(access.router)
        return app
    if s.access_gateway_inprocess and product != "grid":
        app.include_router(playbooks.router)
        app.include_router(access.router)
    app.state.product = product
    for r in SHARED_ROUTERS + tuple(r for p in (("grid", "nms") if product is None else (product,)) for r in PRODUCT_ROUTERS[p]):
        app.include_router(r)

    @app.get("/api/metrics", include_in_schema=False)
    async def metrics(_=Depends(require_admin)):
        """Per-process API metrics (each uvicorn worker reports its own), Prometheus text format, administrators only."""
        extra = {}
        pool = getattr(get_engine().sync_engine, "pool", None)
        for name, attr in (("db_pool_size", "size"), ("db_pool_checked_out", "checkedout"), ("db_pool_overflow", "overflow")):
            fn = getattr(pool, attr, None)
            if callable(fn):
                extra[name] = fn()
        text = METRICS.render(extra)
        if product == "grid":
            return PlainTextResponse(text, media_type="text/plain; version=0.0.4")
        try:   # NMS self-monitoring: objectives and each worker / poller process's newest figures (app/selfmon.py)
            from .db.ch import get_ch
            from .db.pg import session_factory
            from .selfmon import slo_status
            async with session_factory()() as s:
                st = await slo_status(s, get_ch())
            lines = ["# TYPE nms_slo_value gauge", "# TYPE nms_slo_ok gauge"]
            for o in st["slos"]:
                if o["value"] is not None:
                    lines.append(f'nms_slo_value{{objective="{o["key"]}"}} {o["value"]}')
                    lines.append(f'nms_slo_ok{{objective="{o["key"]}"}} {1 if o["ok"] else 0}')
            lines.append("# TYPE nms_process_metric gauge")
            for pr in st["processes"]:
                for k, v in pr["metrics"].items():
                    lines.append(f'nms_process_metric{{service="{pr["service"]}",instance="{pr["instance"]}",metric="{k.replace(chr(34), "")}"}} {v}')
            text += "\n".join(lines) + "\n"
        except Exception:
            log.warning("self-monitoring metrics unavailable", exc_info=True)
        return PlainTextResponse(text, media_type="text/plain; version=0.0.4")

    @app.get("/api/health")
    async def health():
        return {"status": "ok", "product": product or "combined"}

    @app.get("/api/ready")
    async def ready():
        checks = {}
        try:
            async with get_engine().connect() as c:
                await c.execute(text("SELECT 1"))
            checks["postgres"] = "ok"
        except Exception as e:
            checks["postgres"] = f"error: {type(e).__name__}"
        try:
            await get_ch().aquery("SELECT 1 AS x")
            checks["clickhouse"] = "ok"
        except Exception as e:
            checks["clickhouse"] = f"error: {type(e).__name__}"
        ok = all(v == "ok" for v in checks.values())
        return JSONResponse({"status": "ok" if ok else "degraded", **checks}, status_code=200 if ok else 503)

    return app


def create_product_app() -> FastAPI:
    """uvicorn --factory entry point: the product named by PRODUCT ("grid" / "nms"; empty = combined)."""
    import os
    return create_app("api", os.environ.get("PRODUCT") or None)
