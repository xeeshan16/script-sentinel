"""Create sites, pages, scripts, script versions and findings.

Revision ID: 0001
Revises:
Create Date: 2026-11-21
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

JSONType = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
Timestamp = sa.DateTime(timezone=True)


def _enum(name: str, *values: str) -> sa.Enum:
    return sa.Enum(*values, name=name, native_enum=False, create_constraint=True, length=16)


def upgrade() -> None:
    op.create_table(
        "sites",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("allowed_origins", JSONType, nullable=False),
        sa.Column("scan_interval_hours", sa.Integer(), nullable=False),
        sa.Column("created_at", Timestamp, nullable=False),
        sa.Column("updated_at", Timestamp, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_sites"),
        sa.UniqueConstraint("name", name="uq_sites_name"),
        sa.CheckConstraint(
            "scan_interval_hours BETWEEN 1 AND 168", name="ck_sites_scan_interval_hours"
        ),
    )
    op.create_table(
        "pages",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=False),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("label", sa.String(128), nullable=True),
        sa.Column("payment_page", sa.Boolean(), nullable=False),
        sa.Column("created_at", Timestamp, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_pages"),
        sa.ForeignKeyConstraint(
            ["site_id"], ["sites.id"], name="fk_pages_site_id_sites", ondelete="CASCADE"
        ),
        sa.UniqueConstraint("site_id", "url", name="uq_pages_site_url"),
    )
    op.create_table(
        "scripts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=False),
        sa.Column("kind", _enum("script_kind", "external", "inline"), nullable=False),
        sa.Column("locator", sa.String(2048), nullable=False),
        sa.Column(
            "status",
            _enum("authorization_status", "pending", "approved", "rejected"),
            nullable=False,
        ),
        sa.Column("justification", sa.Text(), nullable=True),
        sa.Column("decided_by", sa.String(128), nullable=True),
        sa.Column("decided_at", Timestamp, nullable=True),
        sa.Column("first_seen_at", Timestamp, nullable=False),
        sa.Column("last_seen_at", Timestamp, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_scripts"),
        sa.ForeignKeyConstraint(
            ["site_id"], ["sites.id"], name="fk_scripts_site_id_sites", ondelete="CASCADE"
        ),
        sa.UniqueConstraint("site_id", "locator", name="uq_scripts_site_locator"),
    )
    op.create_table(
        "script_versions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("script_id", sa.Uuid(), nullable=False),
        sa.Column("sha384", sa.String(96), nullable=False),
        sa.Column("normalized_sha384", sa.String(96), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("content", sa.Text(), nullable=True),
        sa.Column("first_seen_at", Timestamp, nullable=False),
        sa.Column("last_seen_at", Timestamp, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_script_versions"),
        sa.ForeignKeyConstraint(
            ["script_id"],
            ["scripts.id"],
            name="fk_script_versions_script_id_scripts",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("script_id", "sha384", name="uq_script_versions_script_sha384"),
        sa.CheckConstraint("size_bytes >= 0", name="ck_script_versions_size_bytes"),
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=False),
        sa.Column("script_id", sa.Uuid(), nullable=True),
        sa.Column("version_id", sa.Uuid(), nullable=True),
        sa.Column("kind", sa.String(64), nullable=False),
        sa.Column(
            "severity",
            _enum("severity", "info", "low", "medium", "high", "critical"),
            nullable=False,
        ),
        sa.Column(
            "status", _enum("finding_status", "open", "acknowledged", "resolved"), nullable=False
        ),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("detail", JSONType, nullable=False),
        sa.Column("created_at", Timestamp, nullable=False),
        sa.Column("resolved_at", Timestamp, nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_findings"),
        sa.ForeignKeyConstraint(
            ["site_id"], ["sites.id"], name="fk_findings_site_id_sites", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["script_id"],
            ["scripts.id"],
            name="fk_findings_script_id_scripts",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["version_id"],
            ["script_versions.id"],
            name="fk_findings_version_id_script_versions",
            ondelete="SET NULL",
        ),
    )
    op.create_index("ix_findings_site_status", "findings", ["site_id", "status"])


def downgrade() -> None:
    op.drop_index("ix_findings_site_status", table_name="findings")
    op.drop_table("findings")
    op.drop_table("script_versions")
    op.drop_table("scripts")
    op.drop_table("pages")
    op.drop_table("sites")
