"""Runtime settings, read from ``SENTINEL_*`` environment variables."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from script_sentinel import __version__

if TYPE_CHECKING:
    from script_sentinel.fetch import FetchLimits

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
    max_redirects: int = Field(default=5, ge=0, le=20)
    scan_concurrency: int = Field(
        default=4, ge=1, le=64, description="Pages fetched at once during a scan."
    )

    def fetch_limits(self) -> FetchLimits:
        from script_sentinel.fetch import FetchLimits

        return FetchLimits(
            timeout_seconds=self.fetch_timeout_seconds,
            max_page_bytes=self.max_page_bytes,
            max_redirects=self.max_redirects,
            user_agent=self.user_agent,
        )
