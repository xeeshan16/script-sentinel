"""The domain model: sites, pages, scripts, script versions and findings.

* A **site** is what you monitor: a name, the origins its pages may be fetched from and how
  often it is scanned.
* A **page** is one URL of a site that gets scanned, optionally marked as a payment page
  (the pages PCI DSS 6.4.3 and 11.6.1 are about).
* A **script** is one entry of a site's inventory: an external ``src`` URL or an inline
  block, with its authorization status and the justification for it.
* A **script version** is one distinct body a script has served, identified by its SHA-384.
  A script that changes on the vendor's CDN gets a new version.
* A **finding** is something a person should look at: an unapproved script, a changed
  body, a suspicious pattern.
"""

from __future__ import annotations

import base64
import enum
import uuid
from datetime import UTC, datetime
from typing import Any, ClassVar

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Text,
    TypeDecorator,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(UTC)


class UtcDateTime(TypeDecorator[datetime]):
    """A timezone-aware UTC timestamp on every backend.

    PostgreSQL stores ``timestamptz``; SQLite keeps no offset, so values are normalized to
    UTC on the way in and marked as UTC on the way out.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetimes are not accepted; use timezone-aware UTC")
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class ScriptKind(enum.StrEnum):
    EXTERNAL = "external"
    INLINE = "inline"


class AuthorizationStatus(enum.StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class Severity(enum.StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(enum.StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


def _enum(cls: type[enum.StrEnum], name: str) -> Enum:
    # VARCHAR plus a CHECK constraint: portable, and adding a value later is a plain
    # constraint change rather than an ALTER TYPE.
    return Enum(
        cls,
        name=name,
        native_enum=False,
        create_constraint=True,
        length=16,
        values_callable=lambda members: [m.value for m in members],
    )


JSONType = JSON().with_variant(JSONB(), "postgresql")

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
    type_annotation_map: ClassVar[dict[Any, Any]] = {
        datetime: UtcDateTime(),
        dict[str, Any]: JSONType,
        list[str]: JSONType,
    }


class Site(Base):
    __tablename__ = "sites"
    __table_args__ = (
        CheckConstraint(
            "scan_interval_hours BETWEEN 1 AND 168", name="ck_sites_scan_interval_hours"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    allowed_origins: Mapped[list[str]]
    scan_interval_hours: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)

    pages: Mapped[list[Page]] = relationship(
        back_populates="site", cascade="all, delete-orphan", passive_deletes=True
    )


class Page(Base):
    __tablename__ = "pages"
    __table_args__ = (UniqueConstraint("site_id", "url", name="uq_pages_site_url"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    site_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    url: Mapped[str] = mapped_column(String(2048))
    label: Mapped[str | None] = mapped_column(String(128))
    payment_page: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)

    site: Mapped[Site] = relationship(back_populates="pages")


class Script(Base):
    """One inventory entry. ``locator`` identifies it within its site.

    For an external script it is the absolute ``src`` URL. For an inline script it is the
    page URL plus the block's position, so an edited inline block is a new version of the
    same script rather than a new script.
    """

    __tablename__ = "scripts"
    __table_args__ = (UniqueConstraint("site_id", "locator", name="uq_scripts_site_locator"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    site_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    kind: Mapped[ScriptKind] = mapped_column(_enum(ScriptKind, "script_kind"))
    locator: Mapped[str] = mapped_column(String(2048))
    status: Mapped[AuthorizationStatus] = mapped_column(
        _enum(AuthorizationStatus, "authorization_status"), default=AuthorizationStatus.PENDING
    )
    justification: Mapped[str | None] = mapped_column(Text)
    decided_by: Mapped[str | None] = mapped_column(String(128))
    decided_at: Mapped[datetime | None]
    first_seen_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(default=utcnow)

    versions: Mapped[list[ScriptVersion]] = relationship(
        back_populates="script", cascade="all, delete-orphan", passive_deletes=True
    )


class ScriptVersion(Base):
    __tablename__ = "script_versions"
    __table_args__ = (
        UniqueConstraint("script_id", "sha384", name="uq_script_versions_script_sha384"),
        CheckConstraint("size_bytes >= 0", name="ck_script_versions_size_bytes"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    script_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scripts.id", ondelete="CASCADE"))
    # Hex digests: the exact bytes served, and the body after whitespace/comment
    # normalization (so a re-minified but otherwise identical file can be told apart).
    sha384: Mapped[str] = mapped_column(String(96))
    normalized_sha384: Mapped[str | None] = mapped_column(String(96))
    size_bytes: Mapped[int] = mapped_column(Integer)
    content: Mapped[str | None] = mapped_column(Text)
    first_seen_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(default=utcnow)

    script: Mapped[Script] = relationship(back_populates="versions")

    @property
    def sri(self) -> str:
        """The Subresource Integrity value for this body, e.g. ``sha384-…``."""
        return sri_from_sha384_hex(self.sha384)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (Index("ix_findings_site_status", "site_id", "status"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    site_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    script_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scripts.id", ondelete="SET NULL")
    )
    version_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("script_versions.id", ondelete="SET NULL")
    )
    kind: Mapped[str] = mapped_column(String(64))
    severity: Mapped[Severity] = mapped_column(_enum(Severity, "severity"))
    status: Mapped[FindingStatus] = mapped_column(
        _enum(FindingStatus, "finding_status"), default=FindingStatus.OPEN
    )
    title: Mapped[str] = mapped_column(String(256))
    detail: Mapped[dict[str, Any]] = mapped_column(default=dict)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    resolved_at: Mapped[datetime | None]


def sri_from_sha384_hex(hex_digest: str) -> str:
    """``sha384-<base64>`` from a hex SHA-384 digest."""
    raw = bytes.fromhex(hex_digest)
    if len(raw) != 48:
        raise ValueError("a SHA-384 digest is 48 bytes (96 hex characters)")
    return "sha384-" + base64.b64encode(raw).decode("ascii")
