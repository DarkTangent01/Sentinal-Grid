"""Remove the Network Topology module: drop its tables, its alert rules and alerts, and the capability / group-state
records of the removed "l3" SNMP group on switches. Downgrade recreates nothing (the module's code is gone).

Revision ID: 0024
Revises: 0023
Create Date: 2026-11-02 08:00:00
"""
import json

from alembic import op
import sqlalchemy as sa

revision = '0024'
down_revision = '0023'
branch_labels = None
depends_on = None

TABLES = ("topo_changes", "topo_jobs", "topo_links", "topo_nodes", "topo_settings", "topo_sites", "topo_addresses", "topo_arp", "topo_routes")
L3_METRICS = ("topology_ip_addresses", "topology_arp_table", "topology_route_table", "topology_vrf_interfaces")


def upgrade() -> None:
    for t in TABLES:
        op.execute(sa.text(f"DROP TABLE IF EXISTS {t}"))
    op.execute(sa.text("DELETE FROM alerts WHERE rule_key LIKE 'topology\\_%' ESCAPE '\\'"))
    op.execute(sa.text("DELETE FROM alert_rules WHERE key LIKE 'topology\\_%' ESCAPE '\\'"))
    conn = op.get_bind()
    cast = "CAST(:{} AS json)" if conn.dialect.name == "postgresql" else ":{}"
    for sid, caps, gs, health in conn.execute(sa.text("SELECT id, capabilities, group_state, health FROM switches")).all():
        caps = json.loads(caps) if isinstance(caps, str) else (caps or {})
        gs = json.loads(gs) if isinstance(gs, str) else (gs or {})
        health = json.loads(health) if isinstance(health, str) else (health or {})
        if any(k in caps for k in L3_METRICS) or "l3" in gs or "l3" in health:
            for k in L3_METRICS:
                caps.pop(k, None)
            gs.pop("l3", None)
            health.pop("l3", None)
            conn.execute(sa.text(f"UPDATE switches SET capabilities = {cast.format('c')}, group_state = {cast.format('g')}, health = {cast.format('h')} "
                                 "WHERE id = :i"), {"c": json.dumps(caps), "g": json.dumps(gs), "h": json.dumps(health), "i": sid})


def downgrade() -> None:
    pass
