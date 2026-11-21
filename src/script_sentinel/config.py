"""Runtime settings, read from ``SENTINEL_*`` environment variables."""

from __future__ import annotations

from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_DATABASE_URL = "postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel"

# PCI DSS 11.6.1 asks for tamper detection at least once every seven days.
MAX_SCAN_INTERVAL_HOURS = 168


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
