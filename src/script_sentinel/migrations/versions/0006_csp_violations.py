"""CSP violation reports, grouped by fingerprint.

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-27
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

Timestamp = sa.DateTime(timezone=True)


def _enum(name: str, *values: str, length: int = 16) -> sa.Enum:
    return sa.Enum(*values, name=name, native_enum=False, create_constraint=True, length=length)


def upgrade() -> None:
    op.create_table(
        "csp_violations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.Uuid(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("document_url", sa.String(2048), nullable=False),
        sa.Column("effective_directive", sa.String(64), nullable=False),
        sa.Column("blocked", sa.String(2048), nullable=False),
        sa.Column(
            "blocked_kind",
            _enum("csp_blocked_kind", "url", "keyword", "scheme", "none", "other"),
            nullable=False,
        ),
        sa.Column("blocked_host", sa.String(255), nullable=True),
        sa.Column(
            "disposition", _enum("csp_disposition", "enforce", "report", "unknown"), nullable=False
        ),
        sa.Column("source_file", sa.String(2048), nullable=True),
        sa.Column("line", sa.Integer(), nullable=True),
        sa.Column("column", sa.Integer(), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("sample", sa.String(64), nullable=True),
        sa.Column("original_policy", sa.Text(), nullable=True),
        sa.Column("policy_sha256", sa.String(64), nullable=True),
        sa.Column(
            "report_format",
            _enum("csp_report_format", "csp-report", "reporting-api"),
            nullable=False,
        ),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.Column("first_seen_at", Timestamp, nullable=False),
        sa.Column("last_seen_at", Timestamp, nullable=False),
        sa.CheckConstraint("count >= 1", name="ck_csp_violations_count"),
        sa.ForeignKeyConstraint(
            ["site_id"],
            ["sites.id"],
            name="fk_csp_violations_site_id_sites",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_csp_violations"),
        sa.UniqueConstraint("site_id", "fingerprint", name="uq_csp_violations_site_fingerprint"),
    )
    op.create_index(
        "ix_csp_violations_site_last_seen", "csp_violations", ["site_id", "last_seen_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_csp_violations_site_last_seen", table_name="csp_violations")
    op.drop_table("csp_violations")
