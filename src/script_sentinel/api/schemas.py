"""Request and response bodies for the REST API."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from script_sentinel.config import MAX_SCAN_INTERVAL_HOURS
from script_sentinel.db.models import (
    AuthorizationStatus,
    ScanStatus,
    ScanTrigger,
    ScriptKind,
    ScriptType,
    SnapshotOutcome,
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
    fetched_at: datetime
    scripts: list[ObservationOut]


class ScanDetail(ScanOut):
    site: str
    pages: list[SnapshotOut]


class ScriptOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    kind: ScriptKind
    locator: str
    status: AuthorizationStatus
    justification: str | None
    first_seen_at: datetime
    last_seen_at: datetime


class ScriptList(BaseModel):
    site: str
    scripts: list[ScriptOut]
