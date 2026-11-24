"""Database engine and session helpers."""

from __future__ import annotations

from typing import Any

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


def make_engine(
    database_url: str, *, sqlite_foreign_keys: bool = True, **kwargs: Any
) -> AsyncEngine:
    """An async engine. SQLite connections get foreign keys switched on.

    Migrations pass ``sqlite_foreign_keys=False``: rebuilding a table on SQLite drops the
    old one, and with foreign keys on that would cascade into every referencing table.
    """
    engine = create_async_engine(database_url, **kwargs)
    if engine.dialect.name == "sqlite" and sqlite_foreign_keys:

        @event.listens_for(engine.sync_engine, "connect")
        def _sqlite_pragmas(dbapi_connection: Any, _record: Any) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


def make_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)
