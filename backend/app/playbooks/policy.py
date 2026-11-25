"""Playbook policy: what Sentinel lets Ansible run.

A playbook is accepted only if every play and task uses the allowlisted structure below. It is classified:
  read_only  only facts / command modules whose commands classify READ_ONLY or LOW_RISK (access.commands.classify),
             plus debug / set_fact / assert / fail
  change     also network configuration modules (ios_config, junos_config, resource modules ...); such a run needs
             a second person's approval and NMS_CONFIG_CHANGES_ENABLED, exactly like a change request
Everything else is refused: shell / command / raw / script / copy / template / uri / file modules, local or delegated
execution, lookups and other Jinja that reads the controller (lookup, query, pipe, env, file), roles, includes,
imports, vars_files, become methods other than enable, and any host pattern other than the run's targets.
The check is static, on the stored text; the runner re-checks the exact approved version before every run.
"""
from __future__ import annotations

import re

import yaml

from ..access.commands import RANK, classify

READ_MODULES = {
    "ansible.builtin.debug", "ansible.builtin.set_fact", "ansible.builtin.assert", "ansible.builtin.fail",
    "cisco.ios.ios_facts", "cisco.nxos.nxos_facts", "junipernetworks.junos.junos_facts", "arista.eos.eos_facts", "ansible.netcommon.cli_command",
    "cisco.ios.ios_command", "cisco.nxos.nxos_command", "junipernetworks.junos.junos_command", "arista.eos.eos_command",
}
COMMAND_MODULES = {"cisco.ios.ios_command", "cisco.nxos.nxos_command", "junipernetworks.junos.junos_command", "arista.eos.eos_command"}
CHANGE_MODULE = re.compile(r"^(cisco\.(ios|nxos)\.(ios|nxos)_\w+|junipernetworks\.junos\.junos_\w+|arista\.eos\.eos_\w+|ansible\.netcommon\.cli_config)$")
SHORT = {m.split(".")[-1]: m for m in READ_MODULES if m.startswith("ansible.builtin.")}
PLAY_KEYS = {"name", "hosts", "gather_facts", "connection", "tasks", "vars", "become", "become_method", "serial", "max_fail_percentage",
             "any_errors_fatal", "ignore_unreachable"}
TASK_KEYS = {"name", "register", "when", "loop", "ignore_errors", "changed_when", "failed_when", "tags", "become", "become_method", "check_mode",
             "diff", "retries", "delay", "until", "vars"}
FORBIDDEN_JINJA = re.compile(r"\b(lookup|query|q)\s*\(|\bpipe\b|ansible_env|\benv\b\s*\(|hostvars\s*\[\s*['\"]localhost|\{%", re.I)
DESTRUCTIVE_KEYS = ("lines", "commands", "parents", "before", "after")


class PolicyError(ValueError):
    pass


def _strings(v):
    if isinstance(v, str):
        yield v
    elif isinstance(v, dict):
        for k, x in v.items():
            yield str(k)
            yield from _strings(x)
    elif isinstance(v, list):
        for x in v:
            yield from _strings(x)


def _cmd_text(c) -> str:
    return c.get("command", "") if isinstance(c, dict) else str(c)


def check(text: str) -> dict:
    """{"kind": read_only | change, "findings": [...], "modules": [...]} or PolicyError with every problem found."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise PolicyError(f"not valid YAML: {str(e)[:200]}")
    errors: list[str] = []
    findings: list[str] = []
    modules: set[str] = set()
    kind = "read_only"
    if not isinstance(doc, list) or not doc:
        raise PolicyError("a playbook is a non-empty list of plays")
    for s in _strings(doc):
        if FORBIDDEN_JINJA.search(s):
            errors.append(f"forbidden Jinja (lookups, environment or statements): {s[:80]}")
    for pi, play in enumerate(doc, 1):
        if not isinstance(play, dict):
            errors.append(f"play {pi}: not a mapping")
            continue
        extra = set(play) - PLAY_KEYS
        if extra:
            errors.append(f"play {pi}: keys not allowed: {', '.join(sorted(extra))} (no roles, includes, imports, pre/post tasks, vars_files)")
        if str(play.get("hosts", "")) not in ("targets", "all"):
            errors.append(f"play {pi}: hosts must be 'targets' (the devices chosen for the run)")
        if play.get("connection") not in (None, "ansible.netcommon.network_cli", "network_cli"):
            errors.append(f"play {pi}: connection must be network_cli")
        if play.get("become_method") not in (None, "enable", "ansible.netcommon.enable"):
            errors.append(f"play {pi}: only become_method enable is allowed")
        tasks = play.get("tasks") or []
        if not isinstance(tasks, list) or not tasks:
            errors.append(f"play {pi}: needs a list of tasks")
            continue
        for ti, task in enumerate(tasks, 1):
            where = f"play {pi} task {ti}" + (f" ({task.get('name')})" if isinstance(task, dict) and task.get("name") else "")
            if not isinstance(task, dict):
                errors.append(f"{where}: not a mapping")
                continue
            mods = [k for k in task if k not in TASK_KEYS]
            if len(mods) != 1:
                errors.append(f"{where}: exactly one module per task (found: {', '.join(mods) or 'none'}; delegate_to, local_action, "
                              "block, include and import are not allowed)")
                continue
            mod = SHORT.get(mods[0], mods[0])
            args = task[mods[0]]
            if task.get("become_method") not in (None, "enable", "ansible.netcommon.enable"):
                errors.append(f"{where}: only become_method enable is allowed")
            if mod in READ_MODULES:
                modules.add(mod)
                if mod in COMMAND_MODULES or mod == "ansible.netcommon.cli_command":
                    cmds = (args or {}).get("commands") if mod in COMMAND_MODULES else [(args or {}).get("command", "")]
                    if not isinstance(cmds, list) or not cmds:
                        errors.append(f"{where}: {mod} needs a literal list of commands")
                        continue
                    for c in cmds:
                        t = _cmd_text(c)
                        if "{{" in t:
                            errors.append(f"{where}: commands must be literal text (no templating): {t[:60]}")
                            continue
                        r, why = classify(t)
                        if RANK[r] > RANK["LOW_RISK"]:
                            errors.append(f"{where}: '{t[:60]}' is {r} ({why or 'not a read-only command'}); command modules may only run read-only commands")
                continue
            if CHANGE_MODULE.match(mod) and not mod.endswith(("_facts", "_command", "_ping")):
                modules.add(mod)
                kind = "change"
                if isinstance(args, dict) and args.get("src"):
                    errors.append(f"{where}: 'src' (a file on the runner) is not allowed; put the lines in the playbook")
                for key in DESTRUCTIVE_KEYS:
                    vals = (args or {}).get(key) if isinstance(args, dict) else None
                    for v in vals if isinstance(vals, list) else [vals] if isinstance(vals, str) else []:
                        r, _ = classify(_cmd_text(v), config_context=True)
                        if r == "DESTRUCTIVE":
                            errors.append(f"{where}: '{_cmd_text(v)[:60]}' is destructive and never allowed")
                findings.append(f"{where}: {mod} changes the configuration")
                continue
            errors.append(f"{where}: module '{mods[0]}' is not allowed (only network facts / command / configuration modules and "
                          "debug / set_fact / assert / fail)")
    if errors:
        raise PolicyError("; ".join(errors[:20]))
    return {"kind": kind, "findings": findings, "modules": sorted(modules)}
