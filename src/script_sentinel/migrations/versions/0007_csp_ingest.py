"""Hourly CSP rollups and the Kafka consumer's applied offsets.

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-28
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

Timestamp = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "csp_rollups",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=False),
        sa.Column("bucket_start", Timestamp, nullable=False),
        sa.Column("effective_directive", sa.String(64), nullable=False),
        sa.Column("blocked", sa.String(255), nullable=False),
        sa.Column(
            "disposition",
            sa.Enum(
                "enforce",
                "report",
                "unknown",
                name="csp_disposition",
                native_enum=False,
                create_constraint=True,
                length=16,
            ),
            nullable=False,
        ),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.CheckConstraint("count >= 1", name="ck_csp_rollups_count"),
        sa.ForeignKeyConstraint(
            ["site_id"], ["sites.id"], name="fk_csp_rollups_site_id_sites", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_csp_rollups"),
        sa.UniqueConstraint(
            "site_id",
            "bucket_start",
            "effective_directive",
            "blocked",
            "disposition",
            name="uq_csp_rollups_bucket_key",
        ),
    )
    op.create_index("ix_csp_rollups_bucket_start", "csp_rollups", ["bucket_start"])
    op.create_table(
        "ingest_offsets",
        sa.Column("consumer_group", sa.String(128), nullable=False),
        sa.Column("topic", sa.String(249), nullable=False),
        sa.Column("partition", sa.Integer(), nullable=False, autoincrement=False),
        sa.Column("next_offset", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", Timestamp, nullable=False),
        sa.CheckConstraint("next_offset >= 0", name="ck_ingest_offsets_next_offset"),
        sa.PrimaryKeyConstraint("consumer_group", "topic", "partition", name="pk_ingest_offsets"),
    )


def downgrade() -> None:
    op.drop_table("ingest_offsets")
    op.drop_index("ix_csp_rollups_bucket_start", table_name="csp_rollups")
    op.drop_table("csp_rollups")
