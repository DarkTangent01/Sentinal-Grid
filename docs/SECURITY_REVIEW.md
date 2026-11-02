# Security Review (modernization pass, 2026-11-02)

This pass focused on performance and reliability. It checked that no change weakens an existing control, and it re-checked the areas the changes touch. The full security audit of 2026-10-23 is in `SECURITY_AUDIT_REPORT.md`; its fixes remain in place.

## 1. Controls verified intact after the changes

| Control | Evidence |
|---|---|
| Authentication on every route | Unchanged `current_user` / `require_admin` dependencies. The new `/api/metrics` requires an administrator (test asserts 403 for analysts) |
| Product scoping (Grid / NMS) | `tests/test_products.py::test_every_api_route_is_classified` caught the new route; it is now classified as shared, with access enforced by the admin dependency |
| Site scoping | `GET /api/switches/interfaces` still filters switches through `site_allowed()` before the SQL query. The new test asserts an analyst scoped to one site sees only that site's interfaces |
| SQL injection | Every new query uses SQLAlchemy expressions or bound ClickHouse parameters. The only interpolated identifiers are constant index names in migration 0027 |
| Log injection | A caller-supplied `X-Request-ID` is accepted only if it matches `^[A-Za-z0-9._-]{8,64}$`; otherwise it is replaced (test sends a newline payload). Logs are JSON-encoded |
| Sensitive data in logs / metrics | The access log records the route *template* (for example `/api/switches/{sid}`), never the raw path or query string. Metrics labels are templates only (test asserts the numeric ID never appears) |
| Secrets | No secrets added. The new settings (`DB_POOL_SIZE`, `CLICKHOUSE_POOL_SIZE`, …) are non-sensitive and documented in `.env.example` |
| Error disclosure | 500 responses return `{"detail": "internal error", "request_id": …}`, never a traceback |

## 2. New attack-surface considerations

- **Dead-letter spool** (`INGEST_DEADLETTER_DIR`)
  - It holds raw normalised events, so it is as sensitive as the events table.
  - The directory is owned by the app user (uid 10001) in the image and mounted as a named Docker volume on `syslog` and `worker` only.
  - Files use JSON only, so there is no pickle or other unsafe deserialisation on replay.
  - Recommendation: include the volume in your data-retention policy and back-up scope.
- **`/api/metrics`**
  - It exposes request counts and latency per route template, plus pool gauges. That is operational data, not user data.
  - It is administrator-only and per process.
  - If scraped, use a dedicated low-privilege admin account over the internal network. Better still, add a separate scrape token later (TD-20).
- **Backpressure** cannot be abused to drop data silently. At the cap, TCP and parser workers pause, and the only path that can drop (inline UDP mode) counts drops as `dropped_buffer_full`.

## 3. Findings carried forward (unchanged from the 2026-10-23 audit, still open)

The open items are tracked in `SECURITY_AUDIT_REPORT.md` §8: MFA, token-encryption key rotation, DNS rebinding residual risk, cleartext UDP syslog, and so on.

New since that audit:
- **Per-site access control now exists.** That was U-1 in the previous report; see `site_allowed` and the users' `sites` field.
- **The ingress relay** (`deploy/ingress`) addresses the UDP conntrack loss that followed `syslog` restarts.

## 4. Dependency status

No dependencies were added or upgraded in this pass. The CI workflow now runs:
- `pip-audit` on the installed backend environment;
- `npm audit --omit=dev --audit-level=high` on runtime frontend dependencies (it passes today).

Build-time frontend findings (the Tailwind 3 dependency chain) are documented in the previous audit.
