"""Request and response bodies for the REST API."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from script_sentinel.config import MAX_SCAN_INTERVAL_HOURS
from script_sentinel.db.models import (
    ApprovalScope,
    AuthorizationEvent,
    AuthorizationStatus,
    ChangePolicy,
    Decision,
    Finding,
    FindingStatus,
    Policy,
    PolicyKind,
    ScanStatus,
    ScanTrigger,
    ScriptFetchOutcome,
    ScriptKind,
    ScriptType,
    ScriptVersion,
    Severity,
    SnapshotOutcome,
    SriStatus,
)


class SiteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64, examples=["shop"])
    allowed_origins: list[str] = Field(
        min_length=1, max_length=50, examples=[["https://shop.example.com"]]
    )
    scan_interval_hours: int | None = Field(
        default=None,
        ge=1,
        le=MAX_SCAN_INTERVAL_HOURS,
        description="Defaults to SENTINEL_DEFAULT_SCAN_INTERVAL_HOURS.",
    )
    respect_robots: bool = Field(
        default=True,
        description="Ask each origin's robots.txt before fetching. Turn off for your own "
        "pages that robots.txt disallows for crawlers (checkout pages often are).",
    )


class SiteUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed_origins: list[str] | None = Field(default=None, min_length=1, max_length=50)
    scan_interval_hours: int | None = Field(default=None, ge=1, le=MAX_SCAN_INTERVAL_HOURS)
    respect_robots: bool | None = None


class SiteOut(BaseModel):
    id: uuid.UUID
    name: str
    allowed_origins: list[str]
    scan_interval_hours: int
    respect_robots: bool
    page_count: int
    payment_page_count: int
    created_at: datetime
    updated_at: datetime


class SiteList(BaseModel):
    sites: list[SiteOut]


class PageCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=1, max_length=2048, examples=["https://shop.example.com/checkout"])
    label: str | None = Field(default=None, max_length=128, examples=["checkout"])
    payment_page: bool = Field(default=False, description="In scope for PCI DSS 6.4.3 and 11.6.1.")


class PageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    url: str
    label: str | None
    payment_page: bool
    created_at: datetime


class PageList(BaseModel):
    site: str
    pages: list[PageOut]


class ErrorOut(BaseModel):
    detail: str


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    status: ScanStatus
    trigger: ScanTrigger
    started_at: datetime
    finished_at: datetime | None
    pages_total: int
    pages_ok: int
    pages_skipped: int
    pages_failed: int
    scripts_seen: int
    scripts_new: int
    scripts_fetched: int
    scripts_fetch_failed: int
    versions_new: int
    scripts_changed: int
    scripts_approved: int
    scripts_pending: int
    scripts_rejected: int
    findings_new: int


class ScanList(BaseModel):
    site: str
    scans: list[ScanOut]


class ObservationOut(BaseModel):
    position: int
    script_id: uuid.UUID
    kind: ScriptKind
    locator: str
    script_type: ScriptType
    type_attribute: str | None
    integrity: str | None
    crossorigin: str | None
    referrerpolicy: str | None
    has_nonce: bool
    is_async: bool
    is_defer: bool
    nomodule: bool
    inline_sha384: str | None
    inline_size_bytes: int | None
    version_id: uuid.UUID | None = Field(description="The body this page got, if known.")
    sha384: str | None = Field(description="Hex SHA-384 of that body.")
    sri: str | None = Field(
        description="sha384-<base64> of that body: an integrity value for external scripts, "
        "a CSP hash source for inline ones."
    )
    sri_status: SriStatus | None = Field(
        description="For scripts with an integrity attribute: what a browser would do."
    )
    authorization_status: AuthorizationStatus | None = Field(
        description="The script's authorization status when this scan finished."
    )


class SnapshotOut(BaseModel):
    url: str
    payment_page: bool
    outcome: SnapshotOutcome
    final_url: str | None
    http_status: int | None
    content_type: str | None
    size_bytes: int | None
    body_sha384: str | None
    elapsed_ms: int
    error: str | None
    warnings: list[str]
    data_block_count: int
    security_headers: dict[str, list[str]]
    meta_csp: list[str]
    fetched_at: datetime
    scripts: list[ObservationOut]


class ScriptFetchOut(BaseModel):
    script_id: uuid.UUID
    url: str
    outcome: ScriptFetchOutcome
    final_url: str | None
    http_status: int | None
    content_type: str | None
    size_bytes: int | None
    elapsed_ms: int
    error: str | None
    version_id: uuid.UUID | None
    sha384: str | None
    sri: str | None
    new_version: bool
    fetched_at: datetime


class ScanDetail(ScanOut):
    site: str
    pages: list[SnapshotOut]
    script_fetches: list[ScriptFetchOut]
    findings: list[FindingOut] = Field(description="Raised by this scan, most severe first.")


class VersionOut(BaseModel):
    id: uuid.UUID
    sha384: str
    normalized_sha384: str | None
    sri: str
    size_bytes: int
    first_seen_at: datetime
    last_seen_at: datetime
    approved_at: datetime | None = Field(description="When this exact body was approved.")
    approved_by: str | None = Field(description="Who approved it (policy:<id> for a policy).")

    @classmethod
    def of(cls, version: ScriptVersion) -> VersionOut:
        return cls(
            id=version.id,
            sha384=version.sha384,
            normalized_sha384=version.normalized_sha384,
            sri=version.sri,
            size_bytes=version.size_bytes,
            first_seen_at=version.first_seen_at,
            last_seen_at=version.last_seen_at,
            approved_at=version.approved_at,
            approved_by=version.approved_by,
        )


class ScriptOut(BaseModel):
    id: uuid.UUID
    kind: ScriptKind
    locator: str
    status: AuthorizationStatus
    status_reason: str | None = Field(description="Why the status is what it is.")
    status_changed_at: datetime | None
    policy_id: uuid.UUID | None = Field(description="The policy that authorized it, if any.")
    decision: Decision | None = Field(description="A person's decision, if any.")
    approval_scope: ApprovalScope | None
    justification: str | None
    decided_by: str | None
    decided_at: datetime | None
    first_seen_at: datetime
    last_seen_at: datetime
    version_count: int
    current_version: VersionOut | None = Field(description="The body seen most recently.")


class ScriptDetail(ScriptOut):
    versions: list[VersionOut] = Field(description="Every body seen, most recent first.")


class ScriptList(BaseModel):
    site: str
    scripts: list[ScriptOut]


_ACTOR = Field(
    min_length=1,
    max_length=128,
    description="Who is making the change. Recorded in the audit trail.",
    examples=["alice@example.com"],
)


class ApproveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actor: str = _ACTOR
    justification: str = Field(
        min_length=1,
        max_length=2000,
        description="Why the script is necessary (PCI DSS 6.4.3).",
        examples=["Payment form provided by our PSP; required for card entry."],
    )
    scope: ApprovalScope = Field(
        default=ApprovalScope.PINNED,
        description="pinned: the bodies served now; any_version: the vendor is expected to "
        "change the script.",
    )


class RejectIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actor: str = _ACTOR
    reason: str = Field(min_length=1, max_length=2000)


class PolicyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: PolicyKind
    match: str = Field(
        min_length=1,
        max_length=2048,
        description="An origin, a URL prefix, or a SHA-384 (hex or sha384-<base64>).",
        examples=["https://js.payments.example"],
    )
    change: ChangePolicy = Field(
        default=ChangePolicy.PINNED,
        description="pinned approves the first body seen and flags any other; "
        "expected_to_change accepts every body. Hash policies are always pinned.",
    )
    ignore_query: list[str] = Field(
        default_factory=list,
        max_length=20,
        description="Query parameters dropped from matching URLs before they become "
        "inventory locators (cache busters). ['*'] drops the whole query.",
        examples=[["v"]],
    )
    justification: str = Field(min_length=1, max_length=2000)
    actor: str = _ACTOR


class PolicyOut(BaseModel):
    id: uuid.UUID
    kind: PolicyKind
    match: str
    change: ChangePolicy
    ignore_query: list[str]
    justification: str
    created_by: str
    created_at: datetime

    @classmethod
    def of(cls, policy: Policy) -> PolicyOut:
        return cls(
            id=policy.id,
            kind=policy.kind,
            match=policy.match,
            change=policy.change,
            ignore_query=list(policy.ignore_query),
            justification=policy.justification,
            created_by=policy.created_by,
            created_at=policy.created_at,
        )


class PolicyList(BaseModel):
    site: str
    policies: list[PolicyOut]


class StatusChangeOut(BaseModel):
    script_id: uuid.UUID
    locator: str
    from_status: AuthorizationStatus | None
    to_status: AuthorizationStatus


class PolicyChangeOut(BaseModel):
    policy: PolicyOut | None = Field(description="The new policy (absent after a removal).")
    scripts_changed: list[StatusChangeOut]


class AuditEventOut(BaseModel):
    seq: int
    action: str
    actor: str
    script_id: uuid.UUID | None
    policy_id: uuid.UUID | None
    locator: str | None
    from_status: str | None
    to_status: str | None
    reason: str | None
    detail: dict[str, object]
    created_at: datetime
    prev_hash: str
    hash: str

    @classmethod
    def of(cls, event: AuthorizationEvent) -> AuditEventOut:
        return cls(
            seq=event.seq,
            action=event.action,
            actor=event.actor,
            script_id=event.script_id,
            policy_id=event.policy_id,
            locator=event.locator,
            from_status=event.from_status,
            to_status=event.to_status,
            reason=event.reason,
            detail=event.detail,
            created_at=event.created_at,
            prev_hash=event.prev_hash,
            hash=event.hash,
        )


class AuditList(BaseModel):
    site: str
    events: list[AuditEventOut]


class ChainOut(BaseModel):
    site: str
    ok: bool
    events: int = Field(description="Events verified (up to the first break, if any).")
    head_hash: str = Field(description="Hash of the last verified event; keep it elsewhere.")
    first_bad_seq: int | None
    problem: str | None


class FindingOut(BaseModel):
    id: uuid.UUID
    kind: str = Field(examples=["script.changed", "script.added", "script.reformatted"])
    severity: Severity
    status: FindingStatus
    title: str
    script_id: uuid.UUID | None
    locator: str | None
    version_id: uuid.UUID | None = Field(description="The body that raised it.")
    previous_version_id: uuid.UUID | None = Field(description="The body served before.")
    scan_id: uuid.UUID | None
    created_at: datetime
    resolved_at: datetime | None
    status_changed_at: datetime | None
    status_changed_by: str | None
    status_note: str | None

    @classmethod
    def of(cls, finding: Finding) -> FindingOut:
        return cls(
            id=finding.id,
            kind=finding.kind,
            severity=finding.severity,
            status=finding.status,
            title=finding.title,
            script_id=finding.script_id,
            locator=finding.locator,
            version_id=finding.version_id,
            previous_version_id=finding.previous_version_id,
            scan_id=finding.scan_id,
            created_at=finding.created_at,
            resolved_at=finding.resolved_at,
            status_changed_at=finding.status_changed_at,
            status_changed_by=finding.status_changed_by,
            status_note=finding.status_note,
        )


class FindingDetail(FindingOut):
    site: str
    detail: dict[str, Any] = Field(
        description="The evidence: reasons for the severity, pages, and for a change the "
        "token diff, size and entropy deltas and newly referenced hosts and URLs."
    )


class FindingList(BaseModel):
    site: str
    findings: list[FindingOut]


class FindingStatusIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actor: str = _ACTOR
    note: str | None = Field(
        default=None,
        max_length=2000,
        description="What was done or decided. Required to resolve a finding.",
    )


class HunkOut(BaseModel):
    old_line: int
    new_line: int
    removed: str
    added: str
    removed_tokens: int
    added_tokens: int
    before: str
    after: str
    truncated: bool


class DeltaOut(BaseModel):
    old: float
    new: float
    delta: float


class TokenStatsOut(BaseModel):
    old: int
    new: int
    removed: int
    added: int
    similarity: float


class DiffOut(BaseModel):
    script_id: uuid.UUID
    locator: str
    from_version: VersionOut
    to_version: VersionOut
    size: DeltaOut
    entropy: DeltaOut
    tokens: TokenStatsOut
    hosts_added: list[str]
    hosts_removed: list[str]
    urls_added: list[str]
    urls_removed: list[str]
    coarse: bool = Field(description="Parts were compared statement by statement.")
    hunk_count: int
    hunks: list[HunkOut]
