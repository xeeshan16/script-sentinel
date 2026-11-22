"""Add scans, page snapshots, script observations and sites.respect_robots.

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-22
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

JSONType = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
Timestamp = sa.DateTime(timezone=True)


def _enum(name: str, *values: str, length: int = 16) -> sa.Enum:
    return sa.Enum(*values, name=name, native_enum=False, create_constraint=True, length=length)


def upgrade() -> None:
    # Plain ALTER TABLE on both backends (SQLite 3.35+ can drop columns), so SQLite never
    # rebuilds the sites table, which would cascade deletes into everything that refers to it.
    op.add_column(
        "sites",
        sa.Column("respect_robots", sa.Boolean(), nullable=False, server_default=sa.true()),
    )

    op.create_table(
        "scans",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=False),
        sa.Column(
            "status",
            _enum("scan_status", "running", "completed", "partial", "failed"),
            nullable=False,
        ),
        sa.Column("trigger", _enum("scan_trigger", "cli", "api", "schedule"), nullable=False),
        sa.Column("started_at", Timestamp, nullable=False),
        sa.Column("finished_at", Timestamp, nullable=True),
        sa.Column("pages_total", sa.Integer(), nullable=False),
        sa.Column("pages_ok", sa.Integer(), nullable=False),
        sa.Column("pages_skipped", sa.Integer(), nullable=False),
        sa.Column("pages_failed", sa.Integer(), nullable=False),
        sa.Column("scripts_seen", sa.Integer(), nullable=False),
        sa.Column("scripts_new", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_scans"),
        sa.ForeignKeyConstraint(
            ["site_id"], ["sites.id"], name="fk_scans_site_id_sites", ondelete="CASCADE"
        ),
    )
    op.create_index("ix_scans_site_started", "scans", ["site_id", "started_at"])

    op.create_table(
        "page_snapshots",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("page_id", sa.Uuid(), nullable=True),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("payment_page", sa.Boolean(), nullable=False),
        sa.Column(
            "outcome",
            _enum(
                "snapshot_outcome",
                "ok",
                "robots_disallowed",
                "redirect_blocked",
                "http_error",
                "not_html",
                "too_large",
                "fetch_error",
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("final_url", sa.String(2048), nullable=True),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("content_type", sa.String(255), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("body_sha384", sa.String(96), nullable=True),
        sa.Column("elapsed_ms", sa.Integer(), nullable=False),
        sa.Column("error", sa.String(1024), nullable=True),
        sa.Column("warnings", JSONType, nullable=False),
        sa.Column("script_count", sa.Integer(), nullable=False),
        sa.Column("data_block_count", sa.Integer(), nullable=False),
        sa.Column("fetched_at", Timestamp, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_page_snapshots"),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name="fk_page_snapshots_scan_id_scans", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["page_id"], ["pages.id"], name="fk_page_snapshots_page_id_pages", ondelete="SET NULL"
        ),
    )
    op.create_index("ix_page_snapshots_page_fetched", "page_snapshots", ["page_id", "fetched_at"])

    op.create_table(
        "script_observations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("snapshot_id", sa.Uuid(), nullable=False),
        sa.Column("script_id", sa.Uuid(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column(
            "script_type", _enum("script_type", "classic", "module", "importmap"), nullable=False
        ),
        sa.Column("type_attribute", sa.String(128), nullable=True),
        sa.Column("integrity", sa.String(1024), nullable=True),
        sa.Column("crossorigin", sa.String(32), nullable=True),
        sa.Column("referrerpolicy", sa.String(64), nullable=True),
        sa.Column("nonce_digest", sa.String(16), nullable=True),
        sa.Column("is_async", sa.Boolean(), nullable=False),
        sa.Column("is_defer", sa.Boolean(), nullable=False),
        sa.Column("nomodule", sa.Boolean(), nullable=False),
        sa.Column("inline_sha384", sa.String(96), nullable=True),
        sa.Column("inline_size_bytes", sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_script_observations"),
        sa.ForeignKeyConstraint(
            ["snapshot_id"],
            ["page_snapshots.id"],
            name="fk_script_observations_snapshot_id_page_snapshots",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["script_id"],
            ["scripts.id"],
            name="fk_script_observations_script_id_scripts",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("snapshot_id", "position", name="uq_script_observations_snapshot_pos"),
    )
    op.create_index("ix_script_observations_script_id", "script_observations", ["script_id"])


def downgrade() -> None:
    op.drop_index("ix_script_observations_script_id", table_name="script_observations")
    op.drop_table("script_observations")
    op.drop_index("ix_page_snapshots_page_fetched", table_name="page_snapshots")
    op.drop_table("page_snapshots")
    op.drop_index("ix_scans_site_started", table_name="scans")
    op.drop_table("scans")
    op.drop_column("sites", "respect_robots")
