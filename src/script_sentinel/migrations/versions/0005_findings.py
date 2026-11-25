"""Link findings to scans and previous versions; track who handled them.

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-25
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

Timestamp = sa.DateTime(timezone=True)


def upgrade() -> None:
    # Nothing references `findings`, so SQLite may rebuild it to add the foreign keys.
    with op.batch_alter_table("findings") as batch:
        batch.add_column(sa.Column("previous_version_id", sa.Uuid(), nullable=True))
        batch.add_column(sa.Column("scan_id", sa.Uuid(), nullable=True))
        batch.add_column(sa.Column("locator", sa.String(2048), nullable=True))
        batch.add_column(sa.Column("status_changed_at", Timestamp, nullable=True))
        batch.add_column(sa.Column("status_changed_by", sa.String(128), nullable=True))
        batch.add_column(sa.Column("status_note", sa.Text(), nullable=True))
        batch.create_foreign_key(
            "fk_findings_previous_version_id_script_versions",
            "script_versions",
            ["previous_version_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch.create_foreign_key(
            "fk_findings_scan_id_scans", "scans", ["scan_id"], ["id"], ondelete="SET NULL"
        )
        batch.create_index("ix_findings_scan_id", ["scan_id"])
    # `scans` is referenced by snapshots and fetches: plain ADD COLUMN, never a rebuild.
    op.add_column(
        "scans", sa.Column("findings_new", sa.Integer(), nullable=False, server_default="0")
    )


def downgrade() -> None:
    op.drop_column("scans", "findings_new")
    with op.batch_alter_table("findings") as batch:
        batch.drop_index("ix_findings_scan_id")
        batch.drop_constraint("fk_findings_scan_id_scans", type_="foreignkey")
        batch.drop_constraint("fk_findings_previous_version_id_script_versions", type_="foreignkey")
        for column in (
            "status_note",
            "status_changed_by",
            "status_changed_at",
            "locator",
            "scan_id",
            "previous_version_id",
        ):
            batch.drop_column(column)
