"""Re-encrypt every stored credential with the current TOKEN_ENCRYPTION_KEY (docs/CREDENTIAL_ROTATION.md).

    1. put the new key in the token_encryption_key secret file and the old one in token_encryption_key_previous
    2. restart the services, then:  python -m app.rotate_keys            (dry run: counts only)
                                     python -m app.rotate_keys --apply    (re-encrypts, one transaction per table)
    3. when it reports 0 values left on the old key, remove token_encryption_key_previous and restart.

Only counts are printed; no plaintext or ciphertext is ever written to the output.
"""
from __future__ import annotations

import argparse
import asyncio

from sqlalchemy import text

# (table, primary key, ciphertext column) — every Fernet-encrypted column in the schema
COLUMNS = [
    ("firewalls", "id", "token_ciphertext"),
    ("notification_channels", "id", "secret_ciphertext"),
    ("iac_backups", "id", "full_config_ciphertext"),
    ("switch_credentials", "id", "secret_ciphertext"),
    ("tacacs_clients", "id", "secret_ciphertext"),
    ("tacacs_clients", "id", "pending_secret_ciphertext"),
    ("tacacs_identity_sources", "id", "bind_secret_ciphertext"),
    ("tacacs_config_versions", "id", "content_ciphertext"),
]


async def rotate(session_factory, apply: bool) -> dict:
    from .security import TokenCipher
    cipher = TokenCipher()
    report = {}
    for table, pk, col in COLUMNS:
        async with session_factory() as s:
            rows = (await s.execute(text(f"SELECT {pk}, {col} FROM {table} WHERE {col} IS NOT NULL AND {col} != ''"))).all()
            old = [(i, v) for i, v in rows if cipher.needs_rotation(v)]
            failed = 0
            if apply:
                for i, v in old:
                    try:
                        await s.execute(text(f"UPDATE {table} SET {col} = :v WHERE {pk} = :i"), {"v": cipher.rotate(v), "i": i})
                    except RuntimeError:
                        failed += 1           # neither the current nor a previous key opens it: left untouched
                await s.commit()
            report[f"{table}.{col}"] = {"values": len(rows), "on_previous_key": len(old), "rotated": len(old) - failed if apply else 0,
                                        "undecryptable": failed}
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true", help="re-encrypt (default: dry run, counts only)")
    args = ap.parse_args()
    from .db.pg import init_engine, session_factory
    init_engine()
    report = asyncio.run(rotate(session_factory(), args.apply))
    width = max(len(k) for k in report)
    for k, r in report.items():
        print(f"{k:<{width}}  values={r['values']:<5} on_previous_key={r['on_previous_key']:<5} rotated={r['rotated']:<5} "
              f"undecryptable={r['undecryptable']}")
    left = sum(r["on_previous_key"] - r["rotated"] for r in report.values())
    print(("applied" if args.apply else "dry run") + f": {left} value(s) still on a previous key")


if __name__ == "__main__":
    main()
