"""Deployment state for the Deployments page: parsed from the files scripts/release.sh writes; administrators only."""
import json

from app.platform import deployments as D

from .test_api import api, login  # noqa: F401
from .test_iac import As


def test_state_parses_versions_status_and_history(tmp_path):
    (tmp_path / "versions.env").write_text("# managed\nAPI_TAG=20261126-0700-abc\nWORKER_TAG=20261125-0900-def\nPOSTGRES_DB=siem\n")
    (tmp_path / "versions.prev.env").write_text("API_TAG=20261125-0900-def\n")
    (tmp_path / "status.json").write_text(json.dumps({"ts": "2026-11-26T07:00:00Z", "ui_release": "20261126-0700-u1", "services": {
        "api": {"tag_var": "API_TAG", "state": "running", "health": "healthy", "containers": 1},
        "worker": {"tag_var": "WORKER_TAG", "state": "running", "health": "healthy", "containers": 1}}}))
    (tmp_path / "history.jsonl").write_text("\n".join([
        json.dumps({"ts": "2026-11-25T09:00:00Z", "service": "api", "from": "1.0.0", "to": "20261125-0900-def", "result": "ok"}),
        "not json",
        json.dumps({"ts": "2026-11-26T07:00:00Z", "service": "api", "from": "20261125-0900-def", "to": "20261126-0700-abc", "result": "ok",
                    "secret": "never shown"})]))
    st = D.state(tmp_path)
    api_row = next(x for x in st["services"] if x["service"] == "api")
    assert api_row == {"service": "api", "tag": "20261126-0700-abc", "previous": "20261125-0900-def", "state": "running", "health": "healthy",
                       "containers": 1, "deployed_at": "2026-11-26T07:00:00Z"}
    assert st["versions"] == {"API_TAG": "20261126-0700-abc", "WORKER_TAG": "20261125-0900-def"}
    assert [h["to"] for h in st["history"]] == ["20261126-0700-abc", "20261125-0900-def"] and "secret" not in st["history"][0]
    assert st["ui_release"] == "20261126-0700-u1"
    empty = D.state(tmp_path / "missing")
    assert empty["available"] is False and empty["services"] == [] and empty["history"] == []


async def test_deployments_endpoint_is_admin_only(api, db, monkeypatch, tmp_path):  # noqa: F811
    monkeypatch.setattr(D, "STATE_DIR", tmp_path)
    admin = await As.login(api, "admin1")
    analyst = await As.login(api, "analyst1")
    assert (await analyst.get("/api/admin/deployments")).status_code == 403
    r = await admin.get("/api/admin/deployments")
    assert r.status_code == 200 and r.json()["available"] is True


def test_migration_check_flags_destructive_upgrades_only():
    from app.migrate_check import findings, pending, script_dir
    expand = '''
def upgrade():
    op.add_column("t", sa.Column("x", sa.Integer()))
    op.create_index("ix", "t", ["x"])
    op.alter_column("t", "y", nullable=True)
def downgrade():
    op.drop_column("t", "x")
'''
    assert findings(expand) == []                                         # drops in downgrade() are fine
    contract = '''
def upgrade():
    op.drop_column("t", "old")
    op.alter_column("t", "a", new_column_name="b")
    op.execute("DELETE FROM t WHERE x = 1")
    op.execute(sa.text("ALTER TABLE t RENAME TO u"))
'''
    f = findings(contract)
    assert len(f) == 4 and f[0].startswith("drop_column") and "renaming" in f[1] and "DELETE FROM" in f[2] and "RENAME TO" in f[3]
    # history: 0024 (topology module removed) and 0027 (index replaced) were destructive and are applied everywhere; they
    # are only checked when pending (a new database), where nothing can be using the old schema. Everything since is
    # expand-only.
    s = script_dir()
    flagged = {r.revision for r in pending(s, None) if findings(open(r.path).read())}
    assert flagged == {"0024", "0027"}
    assert [r.revision for r in pending(s, "0039")] == ["0040", "0041"]
