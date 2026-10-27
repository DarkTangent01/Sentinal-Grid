"""Bulk-register FortiGates from a JSON file (see deploy/firewalls.example.json).

    FGT_TOKEN_HQ_FW01=... python -m app.register /path/firewalls.json [--test]

API tokens are read from the environment variable named by `token_env` and stored encrypted; they are never read
from the file itself. Existing firewalls (matched by name) are updated.
"""
import argparse
import asyncio
import json
import os
import sys

from sqlalchemy import select

from .db.models import AuditLog, Firewall
from .db.pg import session_factory
from .fortigate.service import apply_test_report, run_connection_test
from .security import TokenCipher

FIELDS = ("host", "https_port", "vdom", "site", "tags", "poll_interval_seconds", "syslog_source_ips", "ca_bundle_path",
          "api_log_pull", "api_log_device", "enabled")


async def main(path: str, test: bool) -> int:
    data = json.load(open(path))
    cipher = TokenCipher()
    rc = 0
    async with session_factory()() as s:
        for item in data.get("firewalls", []):
            fw = (await s.execute(select(Firewall).where(Firewall.name == item["name"]))).scalar_one_or_none()
            created = fw is None
            if created:
                fw = Firewall(name=item["name"], tags=[], syslog_source_ips=[], capabilities={}, health={}, api_log_cursor={})
                s.add(fw)
            for k in FIELDS:
                if k in item:
                    setattr(fw, k, item[k])
            if "fortios_version" in item:
                fw.fortios_version_declared = item["fortios_version"]
            env = item.get("token_env")
            if env:
                tok = os.environ.get(env)
                if not tok:
                    print(f"[{item['name']}] WARNING: environment variable {env} is not set; token unchanged")
                else:
                    fw.token_ciphertext = cipher.encrypt(tok)
            s.add(AuditLog(username="cli", action="firewall_create" if created else "firewall_update", target=fw.name,
                           detail={"source": "app.register"}))
            await s.commit()
            print(f"[{fw.name}] {'created' if created else 'updated'} (id={fw.id})")
            if test and fw.token_ciphertext:
                report = await run_connection_test(fw)
                apply_test_report(fw, report)
                await s.commit()
                print(f"[{fw.name}] test: ok={report.get('ok')} auth={report.get('auth')} error={report.get('error')}")
                rc |= 0 if report.get("ok") else 2
    return rc


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--test", action="store_true", help="run Test Connection after registering")
    a = ap.parse_args()
    sys.exit(asyncio.run(main(a.file, a.test)))
