"""Secret loading (docs/SECRET_MANAGEMENT.md).

Every secret setting can come from a file instead of the environment: `<NAME>_FILE=/run/secrets/<name>` (Docker /
Compose / Swarm secrets, Kubernetes secret volumes, Vault agent templates). The file wins over a plain `<NAME>`
environment variable, which stays supported for development and for installations not yet migrated.

Rules:
* Values are read once at start-up and never logged, never put in exception messages (only the variable name is),
  never returned by an API, and hidden from the Settings repr.
* A configured `_FILE` that is missing, unreadable, empty or larger than 64 KB stops the process with a message
  naming the variable, so a broken mount fails loudly instead of running with an empty secret.
* In production a secret that still arrives as a plain environment variable is reported once (name only), because
  environment variables are visible through `docker inspect`, `/proc/<pid>/environ` and `docker compose config`.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

log = logging.getLogger("secrets")

# Settings field → environment variable family. Each also accepts <NAME>_FILE.
SECRET_FIELDS: dict[str, str] = {
    "secret_key": "SECRET_KEY",
    "token_encryption_key": "TOKEN_ENCRYPTION_KEY",
    "token_encryption_key_previous": "TOKEN_ENCRYPTION_KEY_PREVIOUS",
    "bootstrap_admin_password": "BOOTSTRAP_ADMIN_PASSWORD",
    "clickhouse_password": "CLICKHOUSE_PASSWORD",
    "database_password": "DATABASE_PASSWORD",
    "anthropic_api_key": "ANTHROPIC_API_KEY",
}
OPTIONAL = {"token_encryption_key_previous", "anthropic_api_key", "database_password"}   # an empty file means "not used"
MAX_SECRET_BYTES = 64 * 1024


class SecretError(RuntimeError):
    """Raised for an unusable secret file. The message names the variable, never the value or its content."""


def read_secret_file(var: str, path: str, optional: bool = False) -> str:
    p = Path(path)
    try:
        if not p.is_file():
            raise SecretError(f"{var} points to a file that does not exist or is not a regular file")
        if p.stat().st_size > MAX_SECRET_BYTES:
            raise SecretError(f"{var}: secret file is larger than 64 KB")
        value = p.read_text(encoding="utf-8")
    except SecretError:
        raise
    except (OSError, UnicodeDecodeError) as e:
        raise SecretError(f"{var}: secret file is not readable ({type(e).__name__})") from None
    value = value.rstrip("\r\n")          # editors and `echo` add a trailing newline; inner whitespace is kept
    if not value and not optional:
        raise SecretError(f"{var}: secret file is empty")
    return value


def file_overrides(environ: dict[str, str] | None = None) -> dict[str, str]:
    """{settings field: value} for every secret whose <NAME>_FILE is set."""
    env = os.environ if environ is None else environ
    out = {}
    for field, name in SECRET_FIELDS.items():
        path = env.get(f"{name}_FILE")
        if path:
            out[field] = read_secret_file(f"{name}_FILE", path, optional=field in OPTIONAL)
    return out


def plain_env_secrets(environ: dict[str, str] | None = None) -> list[str]:
    """Names of secrets present as plain environment variables. Reported even when a _FILE also exists: the file
    wins, but the variable is still visible to `docker inspect` (e.g. a value left behind in .env)."""
    env = os.environ if environ is None else environ
    return sorted(name for name in SECRET_FIELDS.values() if env.get(name) and env.get(name) != "__CHANGE_ME__")


def inject_database_password(url: str, password: str | None) -> str:
    """Put a file-supplied password into DATABASE_URL (postgresql+asyncpg://user@host/db → user:<pw>@host/db).
    A URL that already carries a password is left alone (environment-only installations)."""
    if not password:
        return url
    from sqlalchemy.engine import make_url
    u = make_url(url)
    if u.password:
        return url
    return u.set(password=password).render_as_string(hide_password=False)


def warn_plain_env(environment: str) -> None:
    names = plain_env_secrets()
    if names and environment == "production":
        log.warning("secrets passed as plain environment variables (visible via docker inspect): %s. Move them to files "
                    "and set <NAME>_FILE (docs/SECRET_MANAGEMENT.md).", ", ".join(names))
