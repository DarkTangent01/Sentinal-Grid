"""Render a PlanSpec as FortiOS 7.x CLI (apply script + rollback script). Pure functions; no device I/O."""
import ipaddress
import re

from .spec import PlanSpec

_SAFE = re.compile(r'^[^"\\\x00-\x1f\x7f]*$')


def q(s: str) -> str:
    """Quote a value for FortiOS CLI. Validation already rejects quotes/backslashes/control characters; refuse here
    too, because a value that escapes its quotes becomes CLI commands."""
    if not _SAFE.match(s):
        raise ValueError(f"unsafe CLI value {s!r}")
    return f'"{s}"'


def _members(names: list[str]) -> str:
    return " ".join(q(n) for n in names)


def _wrap_vdom(lines: list[str], vdom: str | None) -> list[str]:
    if not vdom:
        return lines
    return ["config vdom", f"    edit {q(vdom)}", *[f"    {l}" for l in lines], "    next", "end"]


def _one_line(s: str) -> str:
    """Plan names go into a '#' comment line; a newline would start a real command."""
    return "".join(c if c.isprintable() else " " for c in s)


def render_apply(spec: PlanSpec, plan_id: int | None = None, plan_name: str = "") -> str:
    tag = f"Sentinel Grid plan #{plan_id}" if plan_id else "Sentinel Grid"
    out: list[str] = []

    if spec.addresses:
        out.append("config firewall address")
        for a in spec.addresses:
            out.append(f"    edit {q(a.name)}")
            if a.subnet:
                net = ipaddress.ip_network(a.subnet)
                out.append(f"        set subnet {net.network_address} {net.netmask}")
            else:
                out += ["        set type fqdn", f"        set fqdn {q(a.fqdn)}"]
            out.append(f"        set comment {q((a.comment or tag)[:255])}")
            out.append("    next")
        out.append("end")

    if spec.address_groups:
        out.append("config firewall addrgrp")
        for g in spec.address_groups:
            out += [f"    edit {q(g.name)}", f"        set member {_members(g.members)}",
                    f"        set comment {q((g.comment or tag)[:255])}", "    next"]
        out.append("end")

    if spec.services:
        out.append("config firewall service custom")
        for s in spec.services:
            out.append(f"    edit {q(s.name)}")
            if s.tcp:
                out.append(f"        set tcp-portrange {' '.join(s.tcp)}")
            if s.udp:
                out.append(f"        set udp-portrange {' '.join(s.udp)}")
            out += [f"        set comment {q((s.comment or tag)[:255])}", "    next"]
        out.append("end")

    if spec.service_groups:
        out.append("config firewall service group")
        for g in spec.service_groups:
            out += [f"    edit {q(g.name)}", f"        set member {_members(g.members)}",
                    f"        set comment {q((g.comment or tag)[:255])}", "    next"]
        out.append("end")

    if spec.url_filters:
        out.append("config webfilter urlfilter")
        for u in spec.url_filters:
            out += [f"    edit {u.table_id}", f"        set name {q(u.name)}", "        config entries"]
            entries = list(u.entries)
            for i, e in enumerate(entries, start=1):
                out += [f"            edit {i}", f"                set url {q(e.url)}", f"                set type {e.type}",
                        f"                set action {e.action}", "            next"]
            if u.block_others:
                n = len(entries) + 1
                out += [f"            edit {n}", '                set url "*"', "                set type wildcard",
                        "                set action block", "            next"]
            out += ["        end", "    next"]
        out.append("end")
        profiles = [u for u in spec.url_filters if u.profile_name]
        if profiles:
            out.append("config webfilter profile")
            for u in profiles:
                out += [f"    edit {q(u.profile_name)}", f"        set comment {q(tag)}", "        config web",
                        f"            set urlfilter-table {u.table_id}", "        end", "    next"]
            out.append("end")

    if spec.policies:
        out.append("config firewall policy")
        for p in spec.policies:
            out += ["    edit 0", f"        set name {q(p.name)}",
                    f"        set srcintf {_members(p.srcintf)}", f"        set dstintf {_members(p.dstintf)}",
                    f"        set action {p.action}", f"        set srcaddr {_members(p.srcaddr)}",
                    f"        set dstaddr {_members(p.dstaddr)}", f"        set schedule {q(p.schedule)}",
                    f"        set service {_members(p.service)}"]
            if p.action == "accept":
                if p.webfilter_profile:
                    out += ["        set utm-status enable", f"        set webfilter-profile {q(p.webfilter_profile)}",
                            f"        set ssl-ssh-profile {q(p.ssl_ssh_profile)}"]
                out.append(f"        set nat {'enable' if p.nat else 'disable'}")
            out += [f"        set logtraffic {p.logtraffic}",
                    f"        set comments {q((p.comments or tag)[:1023])}", "    next"]
        out.append("end")

    header = [
        f"# {tag}{' — ' + _one_line(plan_name) if plan_name else ''}",
        "# Generated FortiOS 7.x CLI. REVIEW BEFORE APPLYING. The SIEM never applies changes itself.",
        "# Take a configuration backup first:  execute backup config ...",
    ]
    if spec.policies:
        header.append("# New policies are appended at the END of the policy list (edit 0). Move them above broader")
        header.append("# rules afterwards, e.g.:  config firewall policy / move <new-id> before <existing-id> / end")
    return "\n".join(header + _wrap_vdom(out, spec.vdom)) + "\n"


def render_rollback(spec: PlanSpec, plan_id: int | None = None) -> str:
    out: list[str] = []
    if spec.policies:
        out.append("# Policies were created with 'edit 0' (auto ID). Look up their IDs first:")
        for p in spec.policies:
            out.append(f"#   show firewall policy | grep -f {q(p.name)}")
        out.append("config firewall policy")
        for p in spec.policies:
            out.append(f"    delete <ID of {p.name}>")
        out.append("end")
    profiles = [u for u in spec.url_filters if u.profile_name]
    if profiles:
        out.append("config webfilter profile")
        out += [f"    delete {q(u.profile_name)}" for u in profiles]
        out.append("end")
    if spec.url_filters:
        out.append("config webfilter urlfilter")
        out += [f"    delete {u.table_id}" for u in spec.url_filters]
        out.append("end")
    for section, items in (("firewall service group", spec.service_groups), ("firewall service custom", spec.services),
                           ("firewall addrgrp", spec.address_groups), ("firewall address", spec.addresses)):
        if items:
            out.append(f"config {section}")
            out += [f"    delete {q(i.name)}" for i in items]
            out.append("end")
    head = [f"# Rollback for Sentinel Grid plan #{plan_id}" if plan_id else "# Rollback",
            "# Deletes objects in reverse dependency order. Objects still referenced elsewhere cannot be deleted;",
            "# FortiOS will report the referencing entries. Updated (pre-existing) objects are NOT restored: use your backup."]
    return "\n".join(head + _wrap_vdom(out, spec.vdom)) + "\n"
