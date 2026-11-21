from __future__ import annotations

import os
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from script_sentinel.app import create_app
from script_sentinel.config import Settings
from script_sentinel.db import make_engine, make_sessionmaker, migrate

# Integration tests against real PostgreSQL run when this is set (CI sets it); otherwise
# the same tests run against SQLite only.
POSTGRES_URL = os.environ.get("SENTINEL_TEST_DATABASE_URL")


@pytest.fixture
def sqlite_url(tmp_path: Path) -> str:
    """A migrated, empty SQLite database file."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'sentinel.db'}"
    migrate.upgrade(url)
    return url


@pytest.fixture(params=["sqlite", pytest.param("postgres", marks=pytest.mark.postgres)])
def database_url(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[str]:
    """A migrated, empty database: SQLite always, PostgreSQL when configured."""
    if request.param == "sqlite":
        url = f"sqlite+aiosqlite:///{tmp_path / 'sentinel.db'}"
        migrate.upgrade(url)
        yield url
        return
    if not POSTGRES_URL:
        pytest.skip("set SENTINEL_TEST_DATABASE_URL to run PostgreSQL integration tests")
    migrate.downgrade(POSTGRES_URL, "base")
    migrate.upgrade(POSTGRES_URL)
    yield POSTGRES_URL


@pytest.fixture
async def session(database_url: str) -> AsyncIterator[AsyncSession]:
    """A session on a fresh database. Tests commit explicitly when they need to."""
    engine = make_engine(database_url)
    try:
        async with make_sessionmaker(engine)() as s:
            yield s
    finally:
        await engine.dispose()


@pytest.fixture
def client(database_url: str) -> Iterator[TestClient]:
    app = create_app(Settings(database_url=database_url, default_scan_interval_hours=24))
    with TestClient(app) as c:
        yield c
