"""Product composition: the one place that decides which product registrations a process loads.

- load("grid"): Sentinel Grid (SIEM) only;
- load("nms"):  Sentinel NMS only;
- load(None):   both, as today's single deployment, the dev server and the test suite run.

Product modules register themselves with the shared frameworks (alert engine, reports) when imported; nothing else
imports across products. This module, like main / worker / devserver / demo, is a composition hub and may import both.
"""
from __future__ import annotations

import importlib

PRODUCTS = ("grid", "nms")
_MODULES = {
    "grid": ("app.alerts.siem", "app.analytics.report_sections", "app.enrich.identity_sources"),
    "nms": ("app.alerts.nms", "app.nms.report_sections", "app.traffic.identity_sources"),
}
LOADED: set[str] = set()


def load(product: str | None = None) -> tuple[str, ...]:
    """Import the registrations of one product (or both). Idempotent; returns the products now loaded."""
    if product not in (None, *PRODUCTS):
        raise ValueError(f"unknown product: {product}")
    for p in ([product] if product else PRODUCTS):
        for m in _MODULES[p]:
            importlib.import_module(m)
        LOADED.add(p)
    if product is None:
        importlib.import_module("app.alerts.combined")
    return tuple(sorted(LOADED))
