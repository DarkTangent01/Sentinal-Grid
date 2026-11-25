"""SIEM transformation: HTTP ingest tokens, threat-intel connectors and indicator attributes, incident lifecycle, response actions

Revision ID: 0034
Revises: 0033
Create Date: 2026-11-14 18:00:00.000000

Additive only: new nullable / defaulted columns, two indexes and one new table (response_actions). Existing rows keep working: incidents get stage "new"
(the API derives the real stage from the existing status), indicators have no confidence / expiry, feeds no auth.
Downgrade drops the columns.
"""
from alembic import op
import sqlalchemy as sa


revision = '0034'
down_revision = '0033'
branch_labels = None
depends_on = None

COLUMNS = {
    "log_sources": [sa.Column("token_hash", sa.String(64), nullable=True), sa.Column("token_hint", sa.String(8), nullable=False, server_default=""),
                    sa.Column("token_created_at", sa.DateTime(timezone=True), nullable=True)],
    "ti_feeds": [sa.Column("auth_header", sa.String(64), nullable=False, server_default=""), sa.Column("auth_ciphertext", sa.Text(), nullable=False, server_default=""),
                 sa.Column("default_confidence", sa.Integer(), nullable=False, server_default="50"), sa.Column("expire_days", sa.Integer(), nullable=False, server_default="0")],
    "ti_indicators": [sa.Column("confidence", sa.Integer(), nullable=True), sa.Column("threat", sa.String(96), nullable=False, server_default=""),
                      sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True), sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
                      sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
                      sa.Column("false_positive", sa.Boolean(), nullable=False, server_default=sa.false()), sa.Column("fp_by", sa.String(64), nullable=False, server_default="")],
    "incidents": [sa.Column("stage", sa.String(16), nullable=False, server_default="new"), sa.Column("priority", sa.String(4), nullable=False, server_default=""),
                  sa.Column("tags", sa.JSON(), nullable=True), sa.Column("escalated_at", sa.DateTime(timezone=True), nullable=True),
                  sa.Column("escalated_by", sa.String(64), nullable=False, server_default=""), sa.Column("escalated_to", sa.String(64), nullable=False, server_default=""),
                  sa.Column("escalation_reason", sa.Text(), nullable=False, server_default="")],
}


def upgrade() -> None:
    for table, cols in COLUMNS.items():
        for c in cols:
            op.add_column(table, c)
    op.create_index("ix_ti_indicators_expires_at", "ti_indicators", ["expires_at"])
    op.create_index("ix_incidents_stage", "incidents", ["stage"])
    op.create_table(
        "response_actions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kind", sa.String(32), nullable=False), sa.Column("target", sa.String(255), nullable=False),
        sa.Column("params", sa.JSON(), nullable=False), sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=True), sa.Column("alert_id", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(16), nullable=False), sa.Column("requires_approval", sa.Boolean(), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False), sa.Column("plan", sa.JSON(), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False), sa.Column("log", sa.JSON(), nullable=False),
        sa.Column("requested_by", sa.String(64), nullable=False), sa.Column("decided_by", sa.String(64), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True), sa.Column("decision_comment", sa.Text(), nullable=False),
        sa.Column("applied_by", sa.String(64), nullable=False), sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_response_actions_status_created", "response_actions", ["status", "created_at"])
    op.create_index("ix_response_actions_incident_id", "response_actions", ["incident_id"])
    op.create_index("ix_response_actions_idempotency_key", "response_actions", ["idempotency_key"])


def downgrade() -> None:
    op.drop_table("response_actions")
    op.drop_index("ix_incidents_stage", table_name="incidents")
    op.drop_index("ix_ti_indicators_expires_at", table_name="ti_indicators")
    for table, cols in COLUMNS.items():
        with op.batch_alter_table(table) as b:
            for c in cols:
                b.drop_column(c.name)
