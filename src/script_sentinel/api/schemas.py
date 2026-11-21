"""Request and response bodies for the REST API."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from script_sentinel.config import MAX_SCAN_INTERVAL_HOURS


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


class SiteUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed_origins: list[str] | None = Field(default=None, min_length=1, max_length=50)
    scan_interval_hours: int | None = Field(default=None, ge=1, le=MAX_SCAN_INTERVAL_HOURS)


class SiteOut(BaseModel):
    id: uuid.UUID
    name: str
    allowed_origins: list[str]
    scan_interval_hours: int
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
