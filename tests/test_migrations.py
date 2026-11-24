from __future__ import annotations

import asyncio
from typing import Any

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import inspect, text
from sqlalchemy.engine import Connection

from script_sentinel import authorization, scanner, sites
from script_sentinel.db import make_engine, make_sessionmaker, migrate
from script_sentinel.db.models import Base, PolicyKind, ScanTrigger
from script_sentinel.fetch import PageFetcher
from tests.conftest import FixtureSite

TABLES = {
    "sites",
    "pages",
    "scripts",
    "script_versions",
    "findings",
    "scans",
    "page_snapshots",
    "script_observations",
    "script_fetches",
    "policies",
    "authorization_events",
}


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
    assert "0004" in capsys.readouterr().out


def _counts(database_url: str) -> dict[str, int]:
    async def main() -> dict[str, int]:
        engine = make_engine(database_url)
        try:
            async with engine.connect() as conn:
                return {
                    table: (await conn.execute(text(f"SELECT count(*) FROM {table}"))).scalar_one()
                    for table in (
                        "scripts",
                        "script_versions",
                        "script_observations",
                        "script_fetches",
                    )
                }
        finally:
            await engine.dispose()

    return asyncio.run(main())


def test_0004_keeps_existing_data_both_ways(
    database_url: str, fixture_site: FixtureSite, cdn: FixtureSite
) -> None:
    """Rebuilding `scripts` on SQLite must not cascade into the tables that reference it."""
    tag = cdn.url("/tag.js")
    for query in ("v=1", "v=2"):
        cdn.set(f"/tag.js?{query}", f"tag('{query}');", content_type="text/javascript")
    fixture_site.page("/", f'<script src="{tag}?v=1"></script><script src="{tag}?v=2"></script>')

    async def scan() -> None:
        engine = make_engine(database_url)
        try:
            async with make_sessionmaker(engine)() as session, session.begin():
                await sites.create_site(
                    session,
                    name="shop",
                    allowed_origins=[fixture_site.origin],
                    scan_interval_hours=24,
                )
                await sites.add_page(session, "shop", url=fixture_site.url("/"))
                await authorization.create_policy(
                    session,
                    "shop",
                    kind=PolicyKind.ORIGIN,
                    match=cdn.origin,
                    ignore_query=["v"],
                    actor="test",
                    justification="one script, two URLs",
                )
                async with PageFetcher() as fetcher:
                    await scanner.scan_site(session, "shop", fetcher, trigger=ScanTrigger.CLI)
        finally:
            await engine.dispose()

    asyncio.run(scan())
    before = _counts(database_url)
    assert before == {
        "scripts": 1,
        "script_versions": 2,
        "script_observations": 2,
        "script_fetches": 2,
    }
    migrate.downgrade(database_url, "0003")
    # Only the second fetch of the same script in one scan can't be kept.
    assert _counts(database_url) == {**before, "script_fetches": 1}
    migrate.upgrade(database_url)
    assert _counts(database_url) == {**before, "script_fetches": 1}
