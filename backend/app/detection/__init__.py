"""Declarative (YAML) detection engine: rule model, loader, compiler to parameterised ClickHouse SQL, executor wired
into the alert engine, test runner. Rules live in `backend/rules/**/*.yml` (built-in pack, read-only) and in
alert_rules rows (`yml_*` keys, administrator-authored, versioned). See docs/DETECTION_RULES.md."""
