"""The domain model: sites, pages, scripts, script versions and findings.

* A **site** is what you monitor: a name, the origins its pages may be fetched from and how
  often it is scanned.
* A **page** is one URL of a site that gets scanned, optionally marked as a payment page
  (the pages PCI DSS 6.4.3 and 11.6.1 are about).
* A **script** is one entry of a site's inventory: an external ``src`` URL or an inline
  block, with its authorization status and the justification for it.
* A **script version** is one distinct body a script has served, identified by its SHA-384.
  A script that changes on the vendor's CDN gets a new version.
* A **policy** authorizes scripts in bulk: everything from an origin or under a URL prefix,
  or any body with a given hash. Origin and prefix policies either pin the first body seen
  or accept that the vendor ships new ones ("expected to change"), and can drop
  cache-busting query parameters from the locator.
* An **authorization event** is one entry of a site's append-only, hash-chained audit trail:
  a decision, a policy change, or a script's status changing after a scan.
* A **finding** is something a scan noticed that a person should look at: a script that
  appeared, or one that serves a different body than last time, with the diff and a
  severity.
* A **script fetch** is one download of an external script during a scan: what came back
  and which version it was.
* A **scan** is one pass over a site's pages. Each page it fetched gets a **page
  snapshot** (what happened and when), and each script found on that page gets a **script
  observation** with the attributes it had at that moment. Snapshots are kept even after a
  page is removed, because they are the evidence that a check ran.
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
    text,
    true,
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


class Decision(enum.StrEnum):
    """What a person decided about a script. ``status`` is what applies right now."""

    APPROVED = "approved"
    REJECTED = "rejected"


class ApprovalScope(enum.StrEnum):
    PINNED = "pinned"  # the approved bodies only; a new body needs another look
    ANY_VERSION = "any_version"  # the vendor is expected to ship new bodies


class PolicyKind(enum.StrEnum):
    ORIGIN = "origin"  # external scripts from one origin
    PREFIX = "prefix"  # external scripts whose URL starts with a prefix
    HASH = "hash"  # any body (external or inline) with this SHA-384


class ChangePolicy(enum.StrEnum):
    PINNED = "pinned"  # approve the first body seen, flag any other
    EXPECTED_TO_CHANGE = "expected_to_change"


class Severity(enum.StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingKind(enum.StrEnum):
    SCRIPT_ADDED = "script.added"  # a script that appeared after the site's first scan
    SCRIPT_CHANGED = "script.changed"  # a script serving a body it didn't serve last time
    # A new body whose normalized form (comments and whitespace aside) is unchanged.
    SCRIPT_REFORMATTED = "script.reformatted"


class FindingStatus(enum.StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class ScanStatus(enum.StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"  # every page was inventoried or skipped by robots.txt
    PARTIAL = "partial"  # some pages failed
    FAILED = "failed"  # no page could be inventoried


class ScanTrigger(enum.StrEnum):
    CLI = "cli"
    API = "api"
    SCHEDULE = "schedule"


class SnapshotOutcome(enum.StrEnum):
    OK = "ok"
    ROBOTS_DISALLOWED = "robots_disallowed"
    REDIRECT_BLOCKED = "redirect_blocked"
    HTTP_ERROR = "http_error"
    NOT_HTML = "not_html"
    TOO_LARGE = "too_large"
    FETCH_ERROR = "fetch_error"

    @property
    def failed(self) -> bool:
        """Whether the page couldn't be inventoried for a reason someone should fix.

        A robots.txt refusal is a decision the site made, not a failure.
        """
        return self not in (SnapshotOutcome.OK, SnapshotOutcome.ROBOTS_DISALLOWED)


class ScriptFetchOutcome(enum.StrEnum):
    OK = "ok"
    HTTP_ERROR = "http_error"
    TOO_LARGE = "too_large"
    BAD_REDIRECT = "bad_redirect"  # redirected to something that isn't http(s)
    FETCH_ERROR = "fetch_error"


class SriStatus(enum.StrEnum):
    """What a browser would do with a script's ``integrity`` attribute."""

    MATCH = "match"
    MISMATCH = "mismatch"  # the browser refuses to run the script
    NO_SUPPORTED_HASH = "no_supported_hash"  # nothing usable: the script runs unchecked
    UNVERIFIED = "unverified"  # the body couldn't be fetched this scan


class ScriptType(enum.StrEnum):
    CLASSIC = "classic"
    MODULE = "module"
    IMPORTMAP = "importmap"


def _enum(cls: type[enum.StrEnum], name: str, length: int = 16) -> Enum:
    # VARCHAR plus a CHECK constraint: portable, and adding a value later is a plain
    # constraint change rather than an ALTER TYPE.
    return Enum(
        cls,
        name=name,
        native_enum=False,
        create_constraint=True,
        length=length,
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
        dict[str, list[str]]: JSONType,
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
    respect_robots: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())
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
    # A person's decision (with ``justification``, ``decided_by`` and ``decided_at``).
    # ``status`` is derived from it, the policies and the bodies currently served.
    decision: Mapped[Decision | None] = mapped_column(_enum(Decision, "decision"))
    approval_scope: Mapped[ApprovalScope | None] = mapped_column(
        _enum(ApprovalScope, "approval_scope")
    )
    # Why ``status`` is what it is, and the policy that authorized the script, if any.
    status_reason: Mapped[str | None] = mapped_column(String(512))
    status_changed_at: Mapped[datetime | None]
    policy_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("policies.id", ondelete="SET NULL")
    )
    # The bodies the script served the last time it was fetched successfully (version ids
    # as strings). A failed fetch leaves them alone, so a network error never flips status.
    current_version_ids: Mapped[list[str]] = mapped_column(
        default=list, server_default=text("'[]'")
    )

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
    # Hex digests: the exact bytes served, and the body with comments dropped and whitespace
    # collapsed (see jstokens.normalize), so a rebuild that only changed a banner comment or
    # indentation can be told apart from a change in the code.
    sha384: Mapped[str] = mapped_column(String(96))
    normalized_sha384: Mapped[str | None] = mapped_column(String(96))
    size_bytes: Mapped[int] = mapped_column(Integer)
    content: Mapped[str | None] = mapped_column(Text)
    first_seen_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(default=utcnow)
    # Set when a person (or a pinning policy) approved this exact body.
    approved_at: Mapped[datetime | None]
    approved_by: Mapped[str | None] = mapped_column(String(128))

    script: Mapped[Script] = relationship(back_populates="versions")

    @property
    def sri(self) -> str:
        """The Subresource Integrity value for this body, e.g. ``sha384-…``."""
        return sri_from_sha384_hex(self.sha384)


class Finding(Base):
    """Something a scan noticed that a person should look at.

    ``detail`` holds the evidence: for a change, the token diff, size and entropy deltas
    and the hosts and URLs the new body references that the old one didn't. ``locator``
    keeps the finding readable after its script is deleted (``script_id`` becomes NULL).
    """

    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_site_status", "site_id", "status"),
        Index("ix_findings_scan_id", "scan_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    site_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    script_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scripts.id", ondelete="SET NULL")
    )
    version_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("script_versions.id", ondelete="SET NULL")
    )
    # The body the script served before a change (NULL for a new script).
    previous_version_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("script_versions.id", ondelete="SET NULL")
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    locator: Mapped[str | None] = mapped_column(String(2048))
    kind: Mapped[str] = mapped_column(String(64))
    severity: Mapped[Severity] = mapped_column(_enum(Severity, "severity"))
    status: Mapped[FindingStatus] = mapped_column(
        _enum(FindingStatus, "finding_status"), default=FindingStatus.OPEN
    )
    title: Mapped[str] = mapped_column(String(256))
    detail: Mapped[dict[str, Any]] = mapped_column(default=dict)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    resolved_at: Mapped[datetime | None]
    # Who last acknowledged, resolved or reopened the finding, when, and why.
    status_changed_at: Mapped[datetime | None]
    status_changed_by: Mapped[str | None] = mapped_column(String(128))
    status_note: Mapped[str | None] = mapped_column(Text)


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (Index("ix_scans_site_started", "site_id", "started_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    site_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    status: Mapped[ScanStatus] = mapped_column(_enum(ScanStatus, "scan_status"))
    trigger: Mapped[ScanTrigger] = mapped_column(_enum(ScanTrigger, "scan_trigger"))
    started_at: Mapped[datetime] = mapped_column(default=utcnow)
    finished_at: Mapped[datetime | None]
    pages_total: Mapped[int] = mapped_column(Integer, default=0)
    pages_ok: Mapped[int] = mapped_column(Integer, default=0)
    pages_skipped: Mapped[int] = mapped_column(Integer, default=0)
    pages_failed: Mapped[int] = mapped_column(Integer, default=0)
    scripts_seen: Mapped[int] = mapped_column(Integer, default=0)
    scripts_new: Mapped[int] = mapped_column(Integer, default=0)
    # External scripts downloaded (or not) this scan, and the bodies it saw.
    scripts_fetched: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    scripts_fetch_failed: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    # Bodies never seen before, and how many of those belong to scripts that already had
    # a different body (a script that changed).
    versions_new: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    scripts_changed: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    # The authorization status of the scripts this scan saw, right after it.
    scripts_approved: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    scripts_pending: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    scripts_rejected: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    # Findings this scan raised (new scripts, changed bodies).
    findings_new: Mapped[int] = mapped_column(Integer, default=0, server_default="0")

    snapshots: Mapped[list[PageSnapshot]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="PageSnapshot.url",
    )
    script_fetches: Mapped[list[ScriptFetch]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="ScriptFetch.url",
    )


class PageSnapshot(Base):
    """What one scan saw on one page."""

    __tablename__ = "page_snapshots"
    __table_args__ = (Index("ix_page_snapshots_page_fetched", "page_id", "fetched_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    # SET NULL: the snapshot stays as evidence after the page is unregistered.
    page_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("pages.id", ondelete="SET NULL"))
    url: Mapped[str] = mapped_column(String(2048))
    payment_page: Mapped[bool] = mapped_column(Boolean, default=False)
    outcome: Mapped[SnapshotOutcome] = mapped_column(_enum(SnapshotOutcome, "snapshot_outcome", 32))
    final_url: Mapped[str | None] = mapped_column(String(2048))
    http_status: Mapped[int | None] = mapped_column(Integer)
    content_type: Mapped[str | None] = mapped_column(String(255))
    size_bytes: Mapped[int | None] = mapped_column(Integer)
    body_sha384: Mapped[str | None] = mapped_column(String(96))
    elapsed_ms: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(String(1024))
    warnings: Mapped[list[str]] = mapped_column(default=list)
    script_count: Mapped[int] = mapped_column(Integer, default=0)
    data_block_count: Mapped[int] = mapped_column(Integer, default=0)
    # Security-relevant response headers as served (see headers.py), and any CSP set with
    # <meta http-equiv="Content-Security-Policy">.
    security_headers: Mapped[dict[str, list[str]]] = mapped_column(
        default=dict, server_default=text("'{}'")
    )
    meta_csp: Mapped[list[str]] = mapped_column(default=list, server_default=text("'[]'"))
    fetched_at: Mapped[datetime] = mapped_column(default=utcnow)

    scan: Mapped[Scan] = relationship(back_populates="snapshots")
    observations: Mapped[list[ScriptObservation]] = relationship(
        back_populates="snapshot",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="ScriptObservation.position",
    )


class ScriptObservation(Base):
    """One script as it appeared on one page in one scan."""

    __tablename__ = "script_observations"
    __table_args__ = (
        UniqueConstraint("snapshot_id", "position", name="uq_script_observations_snapshot_pos"),
        Index("ix_script_observations_script_id", "script_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    snapshot_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("page_snapshots.id", ondelete="CASCADE")
    )
    script_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scripts.id", ondelete="CASCADE"))
    position: Mapped[int] = mapped_column(Integer)
    script_type: Mapped[ScriptType] = mapped_column(_enum(ScriptType, "script_type"))
    type_attribute: Mapped[str | None] = mapped_column(String(128))
    integrity: Mapped[str | None] = mapped_column(String(1024))
    crossorigin: Mapped[str | None] = mapped_column(String(32))
    referrerpolicy: Mapped[str | None] = mapped_column(String(64))
    # A short digest, never the nonce itself; enough to spot a nonce that never changes.
    nonce_digest: Mapped[str | None] = mapped_column(String(16))
    is_async: Mapped[bool] = mapped_column(Boolean, default=False)
    is_defer: Mapped[bool] = mapped_column(Boolean, default=False)
    nomodule: Mapped[bool] = mapped_column(Boolean, default=False)
    # Inline scripts: the body's SHA-384 and size.
    inline_sha384: Mapped[str | None] = mapped_column(String(96))
    inline_size_bytes: Mapped[int | None] = mapped_column(Integer)
    # The body this page got: the inline body, or the external script as fetched this scan.
    # NULL when an external script couldn't be fetched.
    version_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("script_versions.id", ondelete="SET NULL")
    )
    # External scripts with an integrity attribute: what the browser would do with it.
    sri_status: Mapped[SriStatus | None] = mapped_column(_enum(SriStatus, "sri_status", 32))
    # The script's authorization status when this scan finished (evidence for 6.4.3).
    authorization_status: Mapped[AuthorizationStatus | None] = mapped_column(
        _enum(AuthorizationStatus, "observation_authorization_status")
    )

    snapshot: Mapped[PageSnapshot] = relationship(back_populates="observations")
    script: Mapped[Script] = relationship()
    version: Mapped[ScriptVersion | None] = relationship()


class ScriptFetch(Base):
    """One download of an external script during a scan.

    A script referenced by several pages is fetched once per scan. Third-party scripts are
    fetched only because an allowlisted page references them, and never parsed as pages.
    """

    __tablename__ = "script_fetches"
    # One row per URL: a policy that drops cache-busting query parameters can map several
    # URLs to one script.
    __table_args__ = (UniqueConstraint("scan_id", "url", name="uq_script_fetches_scan_url"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    script_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scripts.id", ondelete="CASCADE"))
    version_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("script_versions.id", ondelete="SET NULL")
    )
    url: Mapped[str] = mapped_column(String(2048))
    outcome: Mapped[ScriptFetchOutcome] = mapped_column(
        _enum(ScriptFetchOutcome, "script_fetch_outcome", 32)
    )
    final_url: Mapped[str | None] = mapped_column(String(2048))
    http_status: Mapped[int | None] = mapped_column(Integer)
    content_type: Mapped[str | None] = mapped_column(String(255))
    size_bytes: Mapped[int | None] = mapped_column(Integer)
    elapsed_ms: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(String(1024))
    # Whether this scan saw this body for the first time (a new version of the script).
    new_version: Mapped[bool] = mapped_column(Boolean, default=False)
    fetched_at: Mapped[datetime] = mapped_column(default=utcnow)

    scan: Mapped[Scan] = relationship(back_populates="script_fetches")
    script: Mapped[Script] = relationship()
    version: Mapped[ScriptVersion | None] = relationship()


class Policy(Base):
    """A rule that authorizes scripts of a site without a decision per script."""

    __tablename__ = "policies"
    __table_args__ = (
        UniqueConstraint("site_id", "kind", "match", name="uq_policies_site_kind_match"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    site_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    kind: Mapped[PolicyKind] = mapped_column(_enum(PolicyKind, "policy_kind"))
    # A normalized origin, a URL prefix (always with a path), or a hex SHA-384.
    match: Mapped[str] = mapped_column(String(2048))
    change: Mapped[ChangePolicy] = mapped_column(_enum(ChangePolicy, "change_policy", 32))
    # Query parameters dropped from matching script URLs before they become locators, so
    # ``app.js?v=123`` and ``app.js?v=124`` are one script. ``*`` drops the whole query.
    ignore_query: Mapped[list[str]] = mapped_column(default=list)
    justification: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class AuthorizationEvent(Base):
    """One entry of a site's audit trail. Rows are only ever inserted.

    Each event carries the SHA-256 of the previous one (``prev_hash``) and of itself, so
    an edited, removed or reordered row breaks the chain (see audit.verify_chain).
    """

    __tablename__ = "authorization_events"
    __table_args__ = (
        UniqueConstraint("site_id", "seq", name="uq_authorization_events_site_seq"),
        Index("ix_authorization_events_script_id", "script_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    site_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    seq: Mapped[int] = mapped_column(Integer)
    # Plain ids, not foreign keys: the hash covers them, so they must never change, and
    # an event outlives the script or policy it mentions (``locator`` and ``detail`` keep
    # it readable).
    script_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    policy_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    locator: Mapped[str | None] = mapped_column(String(2048))
    action: Mapped[str] = mapped_column(String(32))
    actor: Mapped[str] = mapped_column(String(128))
    from_status: Mapped[str | None] = mapped_column(String(16))
    to_status: Mapped[str | None] = mapped_column(String(16))
    reason: Mapped[str | None] = mapped_column(Text)
    detail: Mapped[dict[str, Any]] = mapped_column(default=dict)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


def sri_from_sha384_hex(hex_digest: str) -> str:
    """``sha384-<base64>`` from a hex SHA-384 digest."""
    raw = bytes.fromhex(hex_digest)
    if len(raw) != 48:
        raise ValueError("a SHA-384 digest is 48 bytes (96 hex characters)")
    return "sha384-" + base64.b64encode(raw).decode("ascii")
