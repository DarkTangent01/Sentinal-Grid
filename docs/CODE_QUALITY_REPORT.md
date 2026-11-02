# Code Quality Report

- **Date:** 2026-11-02
- **Tools run:** `ruff 0.8.4` (repository config), `pytest 9.0.3`, `tsc -b` (strict mode per `frontend/tsconfig.json`) and `vitest 4.1.12`.
- **Not available or not installed:** MyPy/Pyright, ESLint/Prettier, React Testing Library and Playwright. They are recommended in TECHNICAL_DEBT_REGISTER (TD-14, TD-15) rather than added here, to avoid new dependencies without agreement.

## 1. Lint, type and test status

| Check | Before | After |
|---|---|---|
| `ruff check app tests migrations` | see `PERFORMANCE_BENCHMARKS.md` §6 | no new findings introduced |
| `tsc -b --noEmit` | clean | clean |
| Backend tests | 417 passed / 1 live test deselected | see `PERFORMANCE_BENCHMARKS.md` §6 (417 + new tests) |
| Frontend tests | 38 passed | 39 passed |

## 2. Findings

| ID | File / module | Problem | Root cause | Impact | Action |
|---|---|---|---|---|---|
| Q1 | `app/api/tacacs.py` (1,263 lines), `hunt.py` (958), `switches.py` (842), `iac.py` (753) | Oversized route modules holding query building and business rules | Features grew inside routers | Harder review; logic can't be reused or tested without HTTP | Backlog TD-11. The three hot paths touched here (`switches/interfaces`, `snmp/polling-health`, `tacacs/health`) now push work into SQL, but stay in the routers to keep the diff reviewable |
| Q2 | `app/switches/service.py`, `nms/analytics.py`, `api/wireless.py`, `api/soc.py` | Aggregation in Python over full ORM loads, repeated across endpoints (for example `select(Switch)` in 10+ places) | No shared "device query" helper | Duplicated filtering logic and wasted I/O | Partly fixed (3 endpoints); TD-08 to TD-10 |
| Q3 | `app/alerts/engine.py:upsert_detections` | One query per detection | Lookup written inside the loop | Up to 200 round trips per rule per cycle | **Fixed**: one grouped query; `latest_by` keeps in-run consistency |
| Q4 | `app/api/tacacs.py:health_summary` | Query per server, loading every 24 h health row | Same | N+1 | **Fixed**: one `GROUP BY` |
| Q5 | `app/ingest/pipeline.py:flush` | Failed batch re-queued in front of an unbounded buffer | Missing bound and failure classification | Out of memory, or ingestion halted forever on a poison batch | **Fixed**, plus a dead-letter module and replay CLI |
| Q6 | `app/syslog_server.py:Framer` | `int()` on a digit-leading line raised; oversized frame raised | Framing ambiguity treated as fatal | One device could disconnect the shared relay session | **Fixed**; the existing test was updated to the new contract |
| Q7 | `app/snmp_traps.py:Dedup` | Pruned only expired keys | Missing hard bound | Unbounded growth during a unique-key storm | **Fixed**: `DEDUP_MAX_KEYS` with oldest-first eviction |
| Q8 | `app/snmp_traps.py` | Queue overflow counted as `errors` | Ambiguous counter | Drops indistinguishable from bad traps | **Fixed**: `dropped_queue_full` |
| Q9 | ~40 function-level imports (`worker.py`, `api/*.py`) | Cycles avoided by deferring imports | Module coupling | Hidden dependency graph | Backlog TD-16 |
| Q10 | `frontend/src/lib/context.tsx` | Context value rebuilt every render; `markUpdated()` set global state in every queryFn | Convenience pattern | Whole-tree re-render per query | **Fixed**: `useMemo`; cache-subscribed `useLastUpdated` |
| Q11 | `frontend/src/components/charts.tsx` | `useMemo` keyed on inline `series` arrays (25 call sites) | Memo key was an unstable reference | Option rebuilt and chart redrawn on every parent render | **Fixed**: keyed on content |
| Q12 | `frontend/src/components/Chart.tsx` | `setOption` called twice on mount | Init effect and option effect both apply | Double draw | **Fixed** |
| Q13 | `frontend` | 50+ pages statically imported | No route splitting | 2.4 MB entry bundle | **Fixed**: `React.lazy` per route |
| Q14 | Search inputs (switch interfaces/MACs, several TACACS pages) | One request per keystroke | No debounce on some pages | Request storms; up to 2,000-row refetches | **Fixed** for the switch tables; TACACS pages in TD-13 |
| Q15 | `vite.config.ts` | `chunkSizeWarningLimit: 1500` hid bundle growth | Warning suppressed | Silent regressions | Left as is; the entry chunk is now 264 KB. Lower it to 600 once ECharts sits in its own chunk (it already does) |
| Q16 | Repository root | No CI | — | Regressions found late | **Fixed**: `.github/workflows/ci.yml` |

## 3. Conventions followed in the changes

- **Comments:** where it matters, comments explain *why*, at the density of the surrounding code. Settings live in `app/config.py` with an explanatory comment, as the project already does.
- **No new runtime dependencies.** `echarts/core` is the same package.
- **One regression test per change** in `backend/tests/test_modernization.py`, plus `frontend/src/lib/api.test.ts`. The tests assert behaviour (for example "one SELECT instead of 51", "8 queries overlap 4 at a time", "poison chunk is spooled after 3 rejections while good chunks keep landing"), not implementation details.
