from __future__ import annotations

import asyncio
from typing import Any

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import inspect
from sqlalchemy.engine import Connection

from script_sentinel.db import make_engine, migrate
from script_sentinel.db.models import Base

TABLES = {"sites", "pages", "scripts", "script_versions", "findings"}


def _diff(connection: Connection) -> list[Any]:
    context = MigrationContext.configure(connection, opts={"compare_type": True})
    return list(compare_metadata(context, Base.metadata))


def _tables(connection: Connection) -> set[str]:
    return set(inspect(connection).get_table_names()) - {"alembic_version"}


async def test_models_match_the_migrations(database_url: str) -> None:
    """The ORM models and the hand-written migrations describe the same schema."""
    engine = make_engine(database_url)
    try:
        async with engine.connect() as conn:
            assert await conn.run_sync(_diff) == []
    finally:
        await engine.dispose()


def _tables_in(database_url: str) -> set[str]:
    async def main() -> set[str]:
        engine = make_engine(database_url)
        try:
            async with engine.connect() as conn:
                return await conn.run_sync(_tables)
        finally:
            await engine.dispose()

    return asyncio.run(main())


def test_upgrade_and_downgrade_round_trip(database_url: str) -> None:
    # Synchronous on purpose: Alembic's env.py starts its own event loop.
    assert _tables_in(database_url) == TABLES
    migrate.downgrade(database_url, "base")
    assert _tables_in(database_url) == set()
    migrate.upgrade(database_url)
    assert _tables_in(database_url) == TABLES


def test_current_prints_the_revision(sqlite_url: str, capsys: pytest.CaptureFixture[str]) -> None:
    migrate.current(sqlite_url)
    assert "0001" in capsys.readouterr().out
