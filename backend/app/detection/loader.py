"""Load and validate YAML rules.

Built-in rules: every `*.yml` under RULES_DIR (shipped with the code; enabled / severity / threshold overrides live in
their alert_rules row). Custom rules: YAML text stored in `alert_rules.params["yaml"]` with a version history.
A rule's identity is its `id`; `version` must increase on every change (checked when a custom rule is saved).
"""
from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import ValidationError

from .schema import Rule

RULES_DIR = Path(__file__).resolve().parents[2] / "rules"
MAX_YAML_BYTES = 64 * 1024


class RuleError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def parse_rule(text: str) -> Rule:
    """YAML text → validated Rule; RuleError with readable messages otherwise. Uses safe_load (no Python objects)."""
    if len(text.encode()) > MAX_YAML_BYTES:
        raise RuleError(["rule larger than 64 KB"])
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise RuleError([f"YAML syntax: {e}"])
    if not isinstance(data, dict):
        raise RuleError(["a rule is a YAML mapping (id, name, detection, …)"])
    try:
        return Rule.model_validate(data)
    except ValidationError as e:
        raise RuleError([f"{'.'.join(str(x) for x in err['loc'])}: {err['msg']}" for err in e.errors()])
    except ValueError as e:
        raise RuleError([str(e)])


@lru_cache(maxsize=1)
def builtin() -> dict[str, tuple[Rule, str]]:
    """{alert_rules key: (rule, yaml text)} for the shipped pack. Duplicate ids are a packaging error."""
    out: dict[str, tuple[Rule, str]] = {}
    for path in sorted(RULES_DIR.rglob("*.yml")):
        text = path.read_text()
        try:
            rule = parse_rule(text)
        except RuleError as e:
            raise RuleError([f"{path.name}: {m}" for m in e.errors])
        if rule.key in out:
            raise RuleError([f"{path.name}: duplicate rule id {rule.id}"])
        out[rule.key] = (rule, text)
    return out


def default_rule_rows() -> list[dict]:
    """alert_rules seed rows for the built-in pack (same shape as alerts.rules.DEFAULT_RULES)."""
    rows = []
    for key, (r, text) in builtin().items():
        c = r.detection.condition
        rows.append({"key": key, "name": f"{r.id} {r.name}", "severity": r.severity, "mitre": r.mitre_dict(),
                     "description": r.description.strip(),
                     "params": {"threshold": c.threshold, "interval_minutes": max(1, min(60, c.timeframe // 60)),
                                "rule_version": r.version, "rule_sha256": sha256(text)[:16]},
                     "enabled": r.status == "enabled"})
    return rows


def rule_for(key: str, params: dict | None) -> tuple[Rule, str, str] | None:
    """(rule, yaml, origin) for an alert_rules key: built-in pack first, then custom YAML in params."""
    b = builtin().get(key)
    if b:
        return b[0], b[1], "builtin"
    text = (params or {}).get("yaml")
    if text:
        return parse_rule(text), text, "custom"
    return None
