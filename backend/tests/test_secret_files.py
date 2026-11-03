"""Secret handling: file-based secrets (<NAME>_FILE), secure failure, no secret in repr / logs / errors, database URL
password injection, token-key rotation, and static checks of the Compose file, Dockerfiles, .env.example and the
frontend source. Every value below is a throwaway test string, never a real credential."""
import json
import logging
import re
from pathlib import Path

import pytest
import yaml
from cryptography.fernet import Fernet

from app import secret_files as SF
from app.config import Settings, get_settings

ROOT = Path(__file__).resolve().parents[2]
SECRET_ENV = set(SF.SECRET_FIELDS.values())
CANARY = "canary-Zq7-not-a-real-secret-4411"


@pytest.fixture
def fresh_settings(monkeypatch):
    get_settings.cache_clear()
    for name in SECRET_ENV:
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(f"{name}_FILE", raising=False)
    yield monkeypatch
    get_settings.cache_clear()


def _secret(tmp_path, name, value):
    p = tmp_path / name
    p.write_text(value)
    return str(p)


def test_file_wins_over_environment_and_trailing_newline_is_removed(fresh_settings, tmp_path):
    fresh_settings.setenv("SECRET_KEY", "env-value-should-lose-xxxxxxxxxxxxxxxxx")
    fresh_settings.setenv("SECRET_KEY_FILE", _secret(tmp_path, "sk", CANARY + "  inner kept\n"))
    s = get_settings()
    assert s.secret_key == CANARY + "  inner kept"


def test_database_password_is_injected_into_a_passwordless_url(fresh_settings, tmp_path):
    fresh_settings.setenv("DATABASE_URL", "postgresql+asyncpg://siem_app@postgres:5432/siem")
    fresh_settings.setenv("DATABASE_PASSWORD_FILE", _secret(tmp_path, "db", "p@ss/w:rd%x"))
    url = get_settings().database_url
    from sqlalchemy.engine import make_url
    assert make_url(url).password == "p@ss/w:rd%x" and make_url(url).username == "siem_app"
    assert SF.inject_database_password("postgresql+asyncpg://u:keep@h/d", "other") == "postgresql+asyncpg://u:keep@h/d"


@pytest.mark.parametrize("setup,message", [
    (lambda p: str(p / "missing"), "does not exist"),
    (lambda p: _secret(p, "empty", "\n"), "is empty"),
    (lambda p: _secret(p, "huge", "x" * (SF.MAX_SECRET_BYTES + 1)), "larger than 64 KB"),
    (lambda p: str(p), "does not exist or is not a regular file"),
])
def test_unusable_secret_file_fails_loudly_without_revealing_anything(fresh_settings, tmp_path, setup, message):
    fresh_settings.setenv("TOKEN_ENCRYPTION_KEY_FILE", setup(tmp_path))
    with pytest.raises(SF.SecretError) as e:
        get_settings()
    assert message in str(e.value) and "TOKEN_ENCRYPTION_KEY_FILE" in str(e.value)
    assert str(tmp_path) not in str(e.value)          # neither the path nor any content is echoed


def test_optional_secrets_may_be_empty(fresh_settings, tmp_path):
    fresh_settings.setenv("ANTHROPIC_API_KEY_FILE", _secret(tmp_path, "ai", ""))
    fresh_settings.setenv("TOKEN_ENCRYPTION_KEY_PREVIOUS_FILE", _secret(tmp_path, "prev", "\n"))
    s = get_settings()
    assert s.anthropic_api_key == "" and s.token_encryption_key_previous == ""


def test_settings_repr_and_dump_for_logs_hide_secrets(fresh_settings, tmp_path):
    for name in ("SECRET_KEY", "TOKEN_ENCRYPTION_KEY", "CLICKHOUSE_PASSWORD", "BOOTSTRAP_ADMIN_PASSWORD", "DATABASE_PASSWORD"):
        fresh_settings.setenv(f"{name}_FILE", _secret(tmp_path, name, CANARY))
    s = get_settings()
    assert CANARY not in repr(s) and CANARY not in str(s)
    assert "secret_key" not in repr(s) and "database_url" not in repr(s)


def test_plain_environment_secrets_are_reported_by_name_only(fresh_settings, caplog):
    fresh_settings.setenv("SECRET_KEY", CANARY)
    fresh_settings.setenv("CLICKHOUSE_PASSWORD", CANARY)
    with caplog.at_level(logging.WARNING, logger="secrets"):
        SF.warn_plain_env("production")
    assert "CLICKHOUSE_PASSWORD, SECRET_KEY" in caplog.text and CANARY not in caplog.text
    caplog.clear()
    SF.warn_plain_env("development")
    assert caplog.text == ""


def test_token_cipher_rotation_with_previous_key(fresh_settings):
    from app.security import TokenCipher
    old, new = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    ct = TokenCipher(old, []).encrypt(CANARY)
    c = TokenCipher(new, [old])
    assert c.decrypt(ct) == CANARY and c.needs_rotation(ct)
    rotated = c.rotate(ct)
    assert not c.needs_rotation(rotated) and TokenCipher(new, []).decrypt(rotated) == CANARY
    with pytest.raises(RuntimeError) as e:
        TokenCipher(new, []).decrypt(ct)              # old ciphertext without the previous key: clear error, no data
    assert CANARY not in str(e.value)
    with pytest.raises(RuntimeError, match="not a valid Fernet key"):
        TokenCipher("not-a-key", [])


async def test_rotate_keys_reencrypts_every_column(db, fresh_settings, tmp_path):
    from app.db.models import Firewall, NotificationChannel
    from app.db.pg import session_factory
    from app.rotate_keys import rotate
    from app.security import TokenCipher
    old, new = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    oc = TokenCipher(old, [])
    db.add(Firewall(name="fw-rot", host="192.0.2.1", token_ciphertext=oc.encrypt("tok-" + CANARY)))
    db.add(NotificationChannel(name="hook", type="webhook", enabled=True, secret_ciphertext=oc.encrypt(json.dumps({"url": CANARY}))))
    await db.commit()
    fresh_settings.setenv("TOKEN_ENCRYPTION_KEY_FILE", _secret(tmp_path, "k", new))
    fresh_settings.setenv("TOKEN_ENCRYPTION_KEY_PREVIOUS_FILE", _secret(tmp_path, "p", old))
    dry = await rotate(session_factory(), apply=False)
    assert dry["firewalls.token_ciphertext"]["on_previous_key"] == 1 and dry["firewalls.token_ciphertext"]["rotated"] == 0
    done = await rotate(session_factory(), apply=True)
    assert done["firewalls.token_ciphertext"]["rotated"] == 1 and done["notification_channels.secret_ciphertext"]["rotated"] == 1
    again = await rotate(session_factory(), apply=False)
    assert all(r["on_previous_key"] == 0 for r in again.values())
    fw = (await db.execute(__import__("sqlalchemy").select(Firewall))).scalars().one()
    await db.refresh(fw)
    assert TokenCipher(new, []).decrypt(fw.token_ciphertext) == "tok-" + CANARY


# ------------------------------------------------------------------ static checks of the deployment files
def _compose():
    return yaml.safe_load((ROOT / "docker-compose.yml").read_text())


SECRET_NAME = re.compile(r"(PASSWORD|SECRET|_KEY|TOKEN)(?!_FILE)$")


def test_compose_passes_no_secret_through_environment_or_interpolation():
    text = (ROOT / "docker-compose.yml").read_text()
    assert not re.search(r"\$\{[A-Z_]*(PASSWORD|SECRET|_KEY|TOKEN)[A-Z_]*(:-[^}]*)?\}", text)
    for name, svc in _compose()["services"].items():
        env = svc.get("environment") or {}
        bad = [k for k in env if SECRET_NAME.search(k)]
        assert not bad, (name, bad)
        for k, v in env.items():
            if k.endswith("_FILE"):
                assert str(v).startswith("/run/secrets/"), (name, k)
        assert not (svc.get("build") or {}).get("args") if isinstance(svc.get("build"), dict) else True


def test_each_service_mounts_only_the_secrets_it_needs():
    services = _compose()["services"]
    want = {"api": {"db_app_password", "clickhouse_password", "secret_key", "token_encryption_key", "token_encryption_key_previous", "anthropic_api_key"},
            "worker": {"db_app_password", "clickhouse_password", "token_encryption_key", "token_encryption_key_previous"},
            "traps": {"db_app_password", "clickhouse_password", "token_encryption_key", "token_encryption_key_previous"},
            "syslog": {"db_app_password", "clickhouse_password"},
            "migrate": {"db_app_password", "clickhouse_password", "bootstrap_admin_password"},
            "postgres": {"postgres_password"}, "clickhouse": {"clickhouse_password"}, "web": set(), "ingress": set(), "tacacs": set()}
    anchor = set(yaml.safe_load((ROOT / "docker-compose.yml").read_text())["x-backend"]["secrets"])
    for name, svc in services.items():
        got = set(svc.get("secrets") or ([] if name in ("postgres", "clickhouse", "web", "ingress", "tacacs") else anchor))
        assert got == want[name], (name, got)
    files = _compose()["secrets"]
    assert all(v["file"].startswith("./secrets/") for v in files.values())


def test_network_segmentation_and_container_hardening():
    c = _compose()
    assert c["networks"]["backend"].get("internal") is True
    assert c["networks"]["ingest"].get("internal") is True                 # syslog parses untrusted input: no egress
    assert set(c["services"]["syslog"]["networks"]) == {"backend", "ingest"}
    for name, svc in c["services"].items():
        assert not svc.get("privileged"), name
        assert all("docker.sock" not in str(v) for v in svc.get("volumes") or []), name
        assert svc.get("network_mode") not in ("host",) and svc.get("pid") != "host" and svc.get("ipc") != "host", name
    for db in ("postgres", "clickhouse"):
        assert not c["services"][db].get("ports") and list(c["services"][db]["networks"]) == ["backend"]
    assert c["services"]["web"]["networks"] == ["frontend"] and c["services"]["web"]["read_only"] is True
    anchor = c["x-backend"]
    assert anchor["read_only"] is True and anchor["cap_drop"] == ["ALL"] and "no-new-privileges:true" in anchor["security_opt"]


def test_dockerfiles_bake_in_no_secrets():
    for df in (ROOT / "backend/Dockerfile", ROOT / "frontend/Dockerfile", ROOT / "deploy/ingress/Dockerfile"):
        text = df.read_text()
        assert not re.search(r"^\s*(ARG|ENV)\s+\S*(PASSWORD|SECRET|TOKEN|_KEY)", text, re.M | re.I), df
        assert not re.search(r"^\s*COPY\s+.*(\.env|secrets)", text, re.M), df
    assert re.search(r"^USER\s+siem", (ROOT / "backend/Dockerfile").read_text(), re.M)


def test_env_example_holds_no_secrets_and_secrets_are_ignored():
    keys = re.findall(r"^([A-Z_]+)=", (ROOT / ".env.example").read_text(), re.M)
    assert not [k for k in keys if k in SECRET_ENV], keys
    assert "secrets/" in (ROOT / ".gitignore").read_text()
    assert "--exclude='/secrets/'" in (ROOT / "scripts/deploy.sh").read_text()


def test_frontend_source_holds_no_secrets():
    pattern = re.compile(r"(import\.meta\.env\.\w*(SECRET|PASSWORD|TOKEN|KEY)|-----BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|sk-ant-[A-Za-z0-9_-]{20,}"
                         r"|xox[baprs]-[A-Za-z0-9-]{10,}|ghp_[A-Za-z0-9]{30,})")
    hits = [str(p) for p in (ROOT / "frontend/src").rglob("*.ts*") if pattern.search(p.read_text())]
    assert not hits, hits


def test_scripts_never_put_passwords_on_command_lines_or_source_env():
    for name in ("backup.sh", "restore.sh", "migrate-secrets.sh", "create-app-db-role.sh", "gen-secrets.sh"):
        text = (ROOT / "scripts" / name).read_text()
        assert "--password" not in text and not re.search(r"^\s*(source|\.)\s+\.env", text, re.M), name
    text = (ROOT / "scripts/create-app-db-role.sh").read_text()
    assert '-v pw=' not in text and "printf" in text


def test_settings_default_database_url_has_no_credentials():
    url = Settings.model_fields["database_url"].default
    from sqlalchemy.engine import make_url
    assert make_url(url).password is None
