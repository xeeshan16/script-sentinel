"""Runtime settings, read from ``SENTINEL_*`` environment variables."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from script_sentinel import __version__

if TYPE_CHECKING:
    from script_sentinel.fetch import FetchLimits
    from script_sentinel.violations import IngestLimits

DEFAULT_DATABASE_URL = "postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel"

# PCI DSS 11.6.1 asks for tamper detection at least once every seven days.
MAX_SCAN_INTERVAL_HOURS = 168

DEFAULT_USER_AGENT = (
    f"script-sentinel/{__version__} (+https://github.com/xeeshan16/script-sentinel)"
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SENTINEL_", extra="ignore")

    database_url: str = Field(
        default=DEFAULT_DATABASE_URL,
        description="SQLAlchemy async URL. PostgreSQL (asyncpg) in production, SQLite "
        "(aiosqlite) for tests and local trials.",
    )
    default_scan_interval_hours: int = Field(
        default=MAX_SCAN_INTERVAL_HOURS,
        ge=1,
        le=MAX_SCAN_INTERVAL_HOURS,
        description="Scan interval for sites that don't set their own.",
    )
    log_level: Literal["debug", "info", "warning", "error"] = "info"
    user_agent: str = Field(
        default=DEFAULT_USER_AGENT,
        min_length=1,
        max_length=256,
        description="User-Agent for page fetches. The part before the first '/' is the "
        "robots.txt product token.",
    )
    fetch_timeout_seconds: float = Field(
        default=10.0, gt=0, le=120, description="Deadline for fetching one page."
    )
    max_page_bytes: int = Field(
        default=2 * 1024 * 1024,
        ge=1024,
        le=64 * 1024 * 1024,
        description="Pages larger than this are reported as too_large instead of parsed.",
    )
    max_script_bytes: int = Field(
        default=5 * 1024 * 1024,
        ge=1024,
        le=64 * 1024 * 1024,
        description="External scripts larger than this are reported as too_large, not hashed.",
    )
    max_redirects: int = Field(default=5, ge=0, le=20)
    scan_concurrency: int = Field(
        default=4, ge=1, le=64, description="Pages fetched at once during a scan."
    )

    csp_max_body_bytes: int = Field(
        default=64 * 1024,
        ge=1024,
        le=1024 * 1024,
        description="Larger CSP report requests are refused with 413 before being parsed.",
    )
    csp_max_reports_per_request: int = Field(
        default=100,
        ge=1,
        le=1000,
        description="Reports read from one Reporting API batch; the rest count as dropped.",
    )
    csp_reports_per_minute: int = Field(
        default=600,
        ge=1,
        le=1_000_000,
        description="Sustained CSP reports accepted per site per minute (per API process).",
    )
    csp_burst: int = Field(
        default=300,
        ge=1,
        le=1_000_000,
        description="Reports a site may send at once before the rate limit applies.",
    )
    csp_max_groups_per_site: int = Field(
        default=10_000,
        ge=1,
        le=10_000_000,
        description="Distinct violation groups kept per site; new ones beyond it are dropped.",
    )

    @model_validator(mode="after")
    def _burst_covers_a_batch(self) -> Settings:
        if self.csp_burst < self.csp_max_reports_per_request:
            raise ValueError(
                "csp_burst must be at least csp_max_reports_per_request, or a full batch "
                "could never be accepted"
            )
        return self

    def ingest_limits(self) -> IngestLimits:
        from script_sentinel.violations import IngestLimits

        return IngestLimits(
            max_reports=self.csp_max_reports_per_request,
            max_groups=self.csp_max_groups_per_site,
        )

    def fetch_limits(self) -> FetchLimits:
        from script_sentinel.fetch import FetchLimits

        return FetchLimits(
            timeout_seconds=self.fetch_timeout_seconds,
            max_page_bytes=self.max_page_bytes,
            max_redirects=self.max_redirects,
            user_agent=self.user_agent,
            max_script_bytes=self.max_script_bytes,
        )
