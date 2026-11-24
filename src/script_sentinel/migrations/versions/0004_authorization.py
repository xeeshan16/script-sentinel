"""Add policies, the audit trail, script decisions and version approvals.

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-24
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

JSONType = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
Timestamp = sa.DateTime(timezone=True)

_COUNTERS = ("scripts_approved", "scripts_pending", "scripts_rejected")
_STATUSES = ("pending", "approved", "rejected")


def _enum(name: str, *values: str, length: int = 16) -> sa.Enum:
    return sa.Enum(*values, name=name, native_enum=False, create_constraint=True, length=length)


def _add_script_columns() -> None:
    # On SQLite this rebuilds `scripts`. env.py runs SQLite migrations with foreign keys
    # off (and checks them afterwards), so dropping the old table cascades nothing.
    with op.batch_alter_table("scripts") as batch:
        batch.add_column(
            sa.Column("decision", _enum("decision", "approved", "rejected"), nullable=True)
        )
        batch.add_column(
            sa.Column(
                "approval_scope", _enum("approval_scope", "pinned", "any_version"), nullable=True
            )
        )
        batch.add_column(sa.Column("status_reason", sa.String(512), nullable=True))
        batch.add_column(sa.Column("status_changed_at", Timestamp, nullable=True))
        batch.add_column(sa.Column("policy_id", sa.Uuid(), nullable=True))
        batch.add_column(
            sa.Column(
                "current_version_ids", JSONType, nullable=False, server_default=sa.text("'[]'")
            )
        )
        batch.create_foreign_key(
            "fk_scripts_policy_id_policies",
            "policies",
            ["policy_id"],
            ["id"],
            ondelete="SET NULL",
        )


def upgrade() -> None:
    op.create_table(
        "policies",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=False),
        sa.Column("kind", _enum("policy_kind", "origin", "prefix", "hash"), nullable=False),
        sa.Column("match", sa.String(2048), nullable=False),
        sa.Column(
            "change",
            _enum("change_policy", "pinned", "expected_to_change", length=32),
            nullable=False,
        ),
        sa.Column("ignore_query", JSONType, nullable=False),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(128), nullable=False),
        sa.Column("created_at", Timestamp, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_policies"),
        sa.ForeignKeyConstraint(
            ["site_id"], ["sites.id"], name="fk_policies_site_id_sites", ondelete="CASCADE"
        ),
        sa.UniqueConstraint("site_id", "kind", "match", name="uq_policies_site_kind_match"),
    )

    _add_script_columns()

    # script_versions is referenced by observations, fetches and findings: plain ADD COLUMN.
    op.add_column("script_versions", sa.Column("approved_at", Timestamp, nullable=True))
    op.add_column("script_versions", sa.Column("approved_by", sa.String(128), nullable=True))

    for counter in _COUNTERS:
        op.add_column("scans", sa.Column(counter, sa.Integer(), nullable=False, server_default="0"))

    # Nothing references these two, so SQLite may rebuild them.
    with op.batch_alter_table("script_observations") as batch:
        batch.add_column(
            sa.Column(
                "authorization_status",
                _enum("observation_authorization_status", *_STATUSES),
                nullable=True,
            )
        )
    with op.batch_alter_table("script_fetches") as batch:
        batch.drop_constraint("uq_script_fetches_scan_script", type_="unique")
        batch.create_unique_constraint("uq_script_fetches_scan_url", ["scan_id", "url"])

    op.create_table(
        "authorization_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("script_id", sa.Uuid(), nullable=True),
        sa.Column("policy_id", sa.Uuid(), nullable=True),
        sa.Column("locator", sa.String(2048), nullable=True),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("from_status", sa.String(16), nullable=True),
        sa.Column("to_status", sa.String(16), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("detail", JSONType, nullable=False),
        sa.Column("created_at", Timestamp, nullable=False),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("hash", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_authorization_events"),
        sa.ForeignKeyConstraint(
            ["site_id"],
            ["sites.id"],
            name="fk_authorization_events_site_id_sites",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("site_id", "seq", name="uq_authorization_events_site_seq"),
    )
    op.create_index("ix_authorization_events_script_id", "authorization_events", ["script_id"])


def downgrade() -> None:
    op.drop_index("ix_authorization_events_script_id", table_name="authorization_events")
    op.drop_table("authorization_events")
    # The old schema allows one fetch per script per scan. Where a query rule mapped
    # several URLs to one script, keep the fetch with the smallest URL.
    op.execute(
        "DELETE FROM script_fetches WHERE id IN ("
        "SELECT f.id FROM script_fetches f JOIN script_fetches g "
        "ON f.scan_id = g.scan_id AND f.script_id = g.script_id AND f.url > g.url)"
    )
    with op.batch_alter_table("script_fetches") as batch:
        batch.drop_constraint("uq_script_fetches_scan_url", type_="unique")
        batch.create_unique_constraint("uq_script_fetches_scan_script", ["scan_id", "script_id"])
    with op.batch_alter_table("script_observations") as batch:
        batch.drop_constraint("observation_authorization_status", type_="check")
        batch.drop_column("authorization_status")
    for counter in reversed(_COUNTERS):
        op.drop_column("scans", counter)
    op.drop_column("script_versions", "approved_by")
    op.drop_column("script_versions", "approved_at")
    with op.batch_alter_table("scripts") as batch:
        batch.drop_constraint("fk_scripts_policy_id_policies", type_="foreignkey")
        if op.get_bind().dialect.name == "sqlite":
            # Named after their enums; they would survive the rebuild otherwise.
            batch.drop_constraint("decision", type_="check")
            batch.drop_constraint("approval_scope", type_="check")
        for column in (
            "current_version_ids",
            "policy_id",
            "status_changed_at",
            "status_reason",
            "approval_scope",
            "decision",
        ):
            batch.drop_column(column)
    op.drop_table("policies")
