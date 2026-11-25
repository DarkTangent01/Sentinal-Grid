"""Import contract between Sentinel Grid (SIEM) and Sentinel NMS (docs/architecture/MODULE_OWNERSHIP_MATRIX.md).

- grid modules never import nms modules, and nms modules never import grid modules;
- shared modules (platform package, frameworks, auth, database layer) import neither product;
- composition hubs (the combined app, worker, dev server, demo feed, seeding) may import both, and nothing else may
  import a hub;
- every module under app/ has an owner: a new module fails this test until it is classified below.

The check reads source with ast (no imports run), so it also covers imports inside functions.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from app import composition

APP = Path(__file__).resolve().parents[1] / "app"

GRID = {
    "ai", "analytics", "assets", "automation", "compliance", "content", "detection", "enrich", "identity", "incidents",
    "ingest", "investigate_brief", "mitre", "response", "risk", "searches", "sigma", "socmetrics", "syslog_server",
    "tuning", "watchlists", "zeek",
    "alerts.custom", "alerts.rules", "alerts.siem", "alerts.travel",
    "api.analytics", "api.context", "api.hunt", "api.identity", "api.ingest", "api.ops", "api.siem", "api.soc",
    "api.yaml_rules",
}
NMS = {
    "access", "bgp", "bgp_analysis", "configs", "drift", "flows", "fortigate", "fwhealth", "hardening", "iac", "icmp", "isp",
    "netcompliance", "nms", "paloalto", "playbooks", "policy", "register", "selfmon", "snmp_profiles", "snmp_traps",
    "switches", "tacacs", "traffic", "vpnmon", "wan", "wan_alerts", "wan_metrics", "wireless",
    "alerts.nms",
    "api.access", "api.configs", "api.firewalls", "api.flows", "api.hardening", "api.iac", "api.isp", "api.netcompliance",
    "api.netops", "api.nms", "api.playbooks", "api.policies", "api.snmp", "api.switches", "api.tacacs", "api.traffic", "api.wan",
    "api.wireless", "api.wireless_analytics", "api.wireless_integrations", "api.wireless_rf",
}
SHARED = {
    "__init__", "platform", "config", "db", "security", "logging_setup", "observability", "products", "notify",
    "retention", "rotate_keys", "secret_files", "netguard", "reports",
    "alerts", "alerts.engine",
    "api", "api.admin", "api.alerts", "api.auth", "api.deps", "api.identities",
}
HUBS = {"main", "worker", "devserver", "demo", "composition", "bootstrap", "migrate", "alerts.combined",
        "access.asgi"}   # entry points: build an app or worker from the composition


def _module(path: Path) -> str:
    rel = path.relative_to(APP).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1] or ["__init__"]
    return ".".join(parts)


def owner(mod: str) -> str | None:
    """Longest matching prefix: 'alerts.siem' before 'alerts', 'api.hunt' before 'api'."""
    parts = mod.split(".")
    for n in range(len(parts), 0, -1):
        key = ".".join(parts[:n])
        for name, group in (("hub", HUBS), ("grid", GRID), ("nms", NMS), ("shared", SHARED)):
            if key in group:
                return name
    return None


def _imports(path: Path) -> set[str]:
    mod = _module(path)
    pkg = mod.split(".") if path.name == "__init__.py" else mod.split(".")[:-1]
    if mod == "__init__":
        pkg = []
    out = set()
    for n in ast.walk(ast.parse(path.read_text())):
        if isinstance(n, ast.ImportFrom):
            if n.level:
                base = pkg[: len(pkg) - n.level + 1]
                stem = ".".join(base + ([n.module] if n.module else []))
                for a in n.names:   # "from . import x" / "from .pkg import mod" may name a module
                    cand = f"{stem}.{a.name}".strip(".")
                    is_mod = (APP / cand.replace(".", "/")).with_suffix(".py").exists() or (APP / cand.replace(".", "/")).is_dir()
                    out.add(cand if is_mod else stem)
            elif n.module and (n.module == "app" or n.module.startswith("app.")):
                out.add(n.module.removeprefix("app").lstrip(".") or "__init__")
        elif isinstance(n, ast.Import):
            out |= {a.name.removeprefix("app.") for a in n.names if a.name.startswith("app.")}
        elif isinstance(n, ast.Call) and getattr(n.func, "attr", "") == "import_module" and n.args \
                and isinstance(n.args[0], ast.Constant) and str(n.args[0].value).startswith("app."):
            out.add(n.args[0].value.removeprefix("app."))
    return {m for m in out if m}


FILES = sorted(p for p in APP.rglob("*.py") if "__pycache__" not in p.parts)


def test_every_module_has_an_owner():
    missing = sorted(_module(p) for p in FILES if owner(_module(p)) is None)
    assert not missing, f"classify these modules in tests/test_product_boundaries.py: {missing}"


def _violations() -> list[str]:
    bad = []
    for p in FILES:
        src = owner(_module(p))
        for target in _imports(p):
            dst = owner(target)
            if dst is None or dst == src or src == "hub":
                continue
            if dst == "hub":
                bad.append(f"{_module(p)} ({src}) imports composition hub {target}")
            elif src in ("grid", "nms") and dst in ("grid", "nms"):
                bad.append(f"{_module(p)} ({src}) imports {target} ({dst})")
            elif src == "shared" and dst in ("grid", "nms"):
                bad.append(f"shared {_module(p)} imports {target} ({dst})")
    return sorted(bad)


def test_products_do_not_import_each_other():
    assert _violations() == []


@pytest.mark.parametrize("product", ["grid", "nms"])
def test_composition_lists_only_own_modules(product):
    for m in composition._MODULES[product]:
        assert owner(m.removeprefix("app.")) == product, m


def test_checker_catches_a_cross_import(tmp_path, monkeypatch):
    """The contract test itself must fail on a forbidden import (guards against a checker that sees nothing)."""
    pkg = tmp_path / "app"
    (pkg / "alerts").mkdir(parents=True)
    (pkg / "switches").mkdir()
    (pkg / "alerts" / "siem.py").write_text("from ..switches import alerts\n")
    (pkg / "switches" / "__init__.py").write_text("")
    (pkg / "switches" / "alerts.py").write_text("")
    (pkg / "platform").mkdir()
    (pkg / "platform" / "x.py").write_text("def f():\n    from app.analytics import queries\n")
    (pkg / "analytics").mkdir()
    (pkg / "analytics" / "queries.py").write_text("")
    import tests.test_product_boundaries as T
    monkeypatch.setattr(T, "APP", pkg)
    monkeypatch.setattr(T, "FILES", sorted(pkg.rglob("*.py")))
    v = T._violations()
    assert any("alerts.siem (grid) imports switches" in x for x in v), v
    assert any("shared platform.x imports analytics" in x for x in v), v
