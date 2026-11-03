import logging
import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import text

from .api import admin, alerts, analytics, auth, context, firewalls, hardening, hunt, iac, identity, isp, ops, policies, soc, switches, tacacs, wan, wireless, wireless_rf, nms, snmp, yaml_rules
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


def create_app() -> FastAPI:
    s = get_settings()
    setup_logging(s.log_level)
    if len(s.secret_key) < 32:
        raise RuntimeError("SECRET_KEY must be set to at least 32 characters")

    @asynccontextmanager
    async def lifespan(app):
        log.info("api starting (demo_mode=%s)", s.demo_mode)
        yield
        await get_engine().dispose()
        log.info("api stopped")

    app = FastAPI(title="Sentinel Grid", version="1.0.0", lifespan=lifespan,
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

    for r in (auth.router, firewalls.router, analytics.router, alerts.router, admin.router, hardening.router, policies.router, context.router, soc.router, hunt.router, isp.router, ops.router,
              identity.router, iac.router, switches.router, tacacs.router, wan.router, wireless.router, wireless_rf.router, nms.router, snmp.router, yaml_rules.router):
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
        return PlainTextResponse(METRICS.render(extra), media_type="text/plain; version=0.0.4")

    @app.get("/api/health")
    async def health():
        return {"status": "ok"}

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
