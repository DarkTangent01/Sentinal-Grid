"""Guided device configuration templates (preview / export only: nothing is pushed to devices).

Secrets are never embedded: the template uses a placeholder, and the engineer pastes the client's shared secret, shown
once at creation or rotation. Every template starts with the emergency-access step, because enabling TACACS+
authorization on a device without a tested local fallback can lock everyone out.
"""
from __future__ import annotations

from .vendors import CAPABILITIES

SECRET = "<SHARED-SECRET-FROM-SIEM>"
EMERGENCY = "<EMERGENCY-PASSWORD-KEPT-OFFLINE>"


def _v(x) -> str:
    return x or "<SECONDARY-SERVER-IP>"


def fortigate(c: dict, primary: str, secondary: str | None, firmware: str) -> dict:
    cfg = f"""# 0. Emergency access FIRST: a local super_admin with a strong password kept offline, restricted trusted hosts.
config system admin
    edit "emergency"
        set accprofile "super_admin"
        set password {EMERGENCY}
        set trusthost1 <MGMT-NETWORK> <MASK>
    next
end

# 1. TACACS+ server
config user tacacs+
    edit "sg-tacacs"
        set server "{primary}"
        set key {SECRET}
        set secondary-server "{_v(secondary)}"
        set secondary-key {SECRET}
        set authen-type auto
        set authorization enable
        set source-ip {c['address'].split('/')[0]}
    next
end
config user group
    edit "sg-tacacs-admins"
        set member "sg-tacacs"
    next
end

# 2. Wildcard remote admin: the admin profile comes from the server (admin_prof) when accprofile-override is enabled
config system admin
    edit "sg-tacacs-admins"
        set remote-auth enable
        set wildcard enable
        set remote-group "sg-tacacs-admins"
        set accprofile "prof_readonly"
        set accprofile-override enable
        set vdom "root"
    next
end

# 3. Accounting (FortiOS 6.4 and later: verify the commands exist on this release)
config log tacacs+accounting setting
    set status enable
    set server "{primary}"
    set server-key {SECRET}
end
config log tacacs+accounting filter
    set login-audit enable
    set config-change-audit enable
    set cli-cmd-audit enable
end
"""
    return {"vendor": "fortinet", "label": CAPABILITIES["fortinet"]["label"], "firmware": firmware or "FortiOS 6.4 / 7.0 / 7.2 / 7.4",
            "config": cfg, "requirements": ["admin profiles named in the TACACS+ roles exist on the FortiGate (config system accprofile)",
                                            "TCP/49 from the FortiGate source IP to both servers", "the FortiGate is a TACACS+ client in the SIEM"],
            "limitations": ["no per-command authorization (FortiOS does not send command authorization requests)",
                            "accounting commands and fields vary by FortiOS release"],
            "validation": ["diagnose test authserver tacacs+ sg-tacacs <user> <password>", "log in over SSH with a TACACS+ user in a second session; "
                           "keep the current session open until it works", "check TACACS+ → Accounting Explorer for the login"],
            "rollback": ["config system admin; delete \"sg-tacacs-admins\"; end", "config user tacacs+; delete \"sg-tacacs\"; end",
                         "log in with the emergency account if remote authentication fails"]}


def cisco(c: dict, primary: str, secondary: str | None, firmware: str) -> dict:
    cfg = f"""! 0. Emergency access FIRST: local fallback account; keep an existing session open until step 4 is verified.
username emergency privilege 15 secret 0 {EMERGENCY}
!
aaa new-model
tacacs server SG-PRIMARY
 address ipv4 {primary}
 key 0 {SECRET}
 timeout 5
tacacs server SG-SECONDARY
 address ipv4 {_v(secondary)}
 key 0 {SECRET}
 timeout 5
aaa group server tacacs+ SG-TACACS
 server name SG-PRIMARY
 server name SG-SECONDARY
 ip tacacs source-interface <MGMT-INTERFACE>
!
! 1. Authentication (local fallback only when no server answers)
aaa authentication login default group SG-TACACS local
aaa authentication enable default group SG-TACACS enable
! 2. Authorization (exec privilege + per-command); if-authenticated keeps access when both servers are unreachable
aaa authorization exec default group SG-TACACS local if-authenticated
aaa authorization commands 1 default group SG-TACACS local if-authenticated
aaa authorization commands 15 default group SG-TACACS local if-authenticated
! 3. Accounting
aaa accounting exec default start-stop group SG-TACACS
aaa accounting commands 1 default start-stop group SG-TACACS
aaa accounting commands 15 default start-stop group SG-TACACS
!
line vty 0 15
 login authentication default
"""
    return {"vendor": "cisco", "label": CAPABILITIES["cisco"]["label"], "firmware": firmware or "IOS-XE 16.x / 17.x (IOS 15.x: use 'tacacs-server host')",
            "config": cfg, "requirements": ["roles define a Cisco priv-lvl", "command rules tested in the AAA Testing Center (simulation)",
                                            "TCP/49 from the management interface to both servers"],
            "limitations": ["commands are only authorised at the privilege levels listed in 'aaa authorization commands'",
                            "console authorization needs 'aaa authorization console' (not enabled here on purpose)"],
            "validation": ["test aaa group SG-TACACS <user> <password> new-code", "show tacacs (packets, failures per server)",
                           "open a second SSH session with a TACACS+ user; run a permitted and a denied command"],
            "rollback": ["no aaa authorization commands 15 default group SG-TACACS local if-authenticated",
                         "no aaa authorization commands 1 default group SG-TACACS local if-authenticated",
                         "aaa authentication login default local", "log in with the emergency account if needed"]}


def ruckus(c: dict, primary: str, secondary: str | None, firmware: str) -> dict:
    cfg = f"""! 0. Emergency access FIRST: local super-user (privilege 0) with a password kept offline.
username emergency privilege 0 password {EMERGENCY}
!
tacacs-server host {primary}
tacacs-server host {_v(secondary)}
tacacs-server key {SECRET}
ip tacacs source-interface management 1
!
! 1. Authentication with local fallback
aaa authentication login default tacacs+ local
aaa authentication enable default tacacs+ local
aaa authentication login privilege-mode
! 2. Authorization (foundry-privlvl: 0 super-user, 4 port-config, 5 read-only) and per-command
aaa authorization exec default tacacs+
aaa authorization commands 0 default tacacs+
! 3. Accounting
aaa accounting exec default start-stop tacacs+
aaa accounting commands 0 default start-stop tacacs+
aaa accounting system default start-stop tacacs+
"""
    return {"vendor": "ruckus", "label": CAPABILITIES["ruckus"]["label"], "firmware": firmware or "FastIron 08.0.90+ / 09.0.x / 10.0.x",
            "config": cfg, "requirements": ["roles define a Ruckus privilege (0, 4 or 5)", "TCP/49 from the management port to both servers"],
            "limitations": ["one global TACACS+ key on many FastIron releases: every server must use the same key for this device",
                            "privilege semantics are inverted compared with Cisco (0 = super-user)"],
            "validation": ["show aaa (server status and counters)", "log in with a TACACS+ user in a second session; run show and config commands"],
            "rollback": ["no aaa authorization commands 0 default tacacs+", "aaa authentication login default local",
                         "log in with the emergency account if needed"]}


def generic(c: dict, primary: str, secondary: str | None, firmware: str) -> dict:
    return {"vendor": c["vendor"], "label": CAPABILITIES["other"]["label"], "firmware": firmware or "unknown",
            "config": f"# Configure TACACS+ servers {primary} and {_v(secondary)} with key {SECRET}; keep a local emergency account.\n",
            "requirements": ["vendor documentation"], "limitations": ["capabilities not verified for this vendor"],
            "validation": ["log in with a TACACS+ user in a second session"], "rollback": ["revert to local authentication"]}


def template(c: dict, primary: str, secondary: str | None) -> dict:
    fn = {"fortinet": fortigate, "cisco": cisco, "ruckus": ruckus}.get(c["vendor"], generic)
    t = fn(c, primary, secondary, c.get("firmware") or "")
    return {**t, "device": c["name"], "address": c["address"], "model": c.get("model") or "", "primary": primary, "secondary": secondary,
            "secret_note": "The shared secret is shown once when the client is created or rotated. Paste it where the template says "
                           f"{SECRET}; it is never included in templates or exports.",
            "warning": "Review with a second engineer. Apply during a change window from a session that stays open until a new TACACS+ "
                       "login works. The SIEM never pushes this configuration."}
