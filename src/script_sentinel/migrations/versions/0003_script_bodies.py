"""Add script fetches, version links on observations, SRI status and header snapshots.

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-23
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

JSONType = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
Timestamp = sa.DateTime(timezone=True)

_SRI_STATUSES = ("match", "mismatch", "no_supported_hash", "unverified")
_COUNTERS = ("scripts_fetched", "scripts_fetch_failed", "versions_new", "scripts_changed")


def _enum(name: str, *values: str, length: int = 16) -> sa.Enum:
    return sa.Enum(*values, name=name, native_enum=False, create_constraint=True, length=length)


def upgrade() -> None:
    for counter in _COUNTERS:
        op.add_column("scans", sa.Column(counter, sa.Integer(), nullable=False, server_default="0"))

    # Plain ADD COLUMN on both backends: on SQLite a table rebuild of page_snapshots would
    # cascade-delete the observations that reference it.
    op.add_column(
        "page_snapshots",
        sa.Column("security_headers", JSONType, nullable=False, server_default=sa.text("'{}'")),
    )
    op.add_column(
        "page_snapshots",
        sa.Column("meta_csp", JSONType, nullable=False, server_default=sa.text("'[]'")),
    )

    # Nothing references script_observations, so on SQLite batch mode may rebuild it
    # (needed to add a foreign key and a CHECK constraint there).
    with op.batch_alter_table("script_observations") as batch:
        batch.add_column(sa.Column("version_id", sa.Uuid(), nullable=True))
        batch.add_column(
            sa.Column("sri_status", _enum("sri_status", *_SRI_STATUSES, length=32), nullable=True)
        )
        batch.create_foreign_key(
            "fk_script_observations_version_id_script_versions",
            "script_versions",
            ["version_id"],
            ["id"],
            ondelete="SET NULL",
        )

    op.create_table(
        "script_fetches",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("script_id", sa.Uuid(), nullable=False),
        sa.Column("version_id", sa.Uuid(), nullable=True),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column(
            "outcome",
            _enum(
                "script_fetch_outcome",
                "ok",
                "http_error",
                "too_large",
                "bad_redirect",
                "fetch_error",
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("final_url", sa.String(2048), nullable=True),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("content_type", sa.String(255), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("elapsed_ms", sa.Integer(), nullable=False),
        sa.Column("error", sa.String(1024), nullable=True),
        sa.Column("new_version", sa.Boolean(), nullable=False),
        sa.Column("fetched_at", Timestamp, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_script_fetches"),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name="fk_script_fetches_scan_id_scans", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["script_id"],
            ["scripts.id"],
            name="fk_script_fetches_script_id_scripts",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["version_id"],
            ["script_versions.id"],
            name="fk_script_fetches_version_id_script_versions",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint("scan_id", "script_id", name="uq_script_fetches_scan_script"),
    )


def downgrade() -> None:
    op.drop_table("script_fetches")
    with op.batch_alter_table("script_observations") as batch:
        batch.drop_constraint(
            "fk_script_observations_version_id_script_versions", type_="foreignkey"
        )
        # The enum's CHECK constraint is named after the enum; on SQLite it would otherwise
        # survive the rebuild and point at the dropped column.
        batch.drop_constraint("sri_status", type_="check")
        batch.drop_column("sri_status")
        batch.drop_column("version_id")
    op.drop_column("page_snapshots", "meta_csp")
    op.drop_column("page_snapshots", "security_headers")
    for counter in reversed(_COUNTERS):
        op.drop_column("scans", counter)
