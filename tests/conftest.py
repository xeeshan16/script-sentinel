from __future__ import annotations

import os
import threading
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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


@dataclass
class Route:
    body: bytes
    status: int = 200
    headers: dict[str, str] = field(default_factory=dict)


class FixtureSite:
    """A real HTTP server on 127.0.0.1 serving routes that tests can change mid-test."""

    def __init__(self) -> None:
        self.routes: dict[str, Route] = {}
        self.requests: list[tuple[str, str]] = []  # (path, user agent)
        site = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                site.requests.append((self.path, self.headers.get("user-agent", "")))
                route = site.routes.get(self.path) or Route(b"not found", 404)
                self.send_response(route.status)
                headers = {"content-type": "text/html; charset=utf-8", **route.headers}
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header("content-length", str(len(route.body)))
                self.end_headers()
                self.wfile.write(route.body)

            def log_message(self, format: str, *args: object) -> None:
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self.origin = f"http://127.0.0.1:{self._server.server_address[1]}"
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def url(self, path: str) -> str:
        return self.origin + path

    def page(self, path: str, html: str) -> None:
        self.routes[path] = Route(html.encode("utf-8"))

    def set(self, path: str, body: bytes | str, status: int = 200, **headers: str) -> None:
        """Serve ``body`` at ``path``; ``content_type="..."`` sets the content-type header."""
        raw = body.encode("utf-8") if isinstance(body, str) else body
        self.routes[path] = Route(
            raw, status, {key.replace("_", "-"): value for key, value in headers.items()}
        )

    def paths(self) -> list[str]:
        return [path for path, _ in self.requests]


@pytest.fixture
def fixture_site() -> Iterator[FixtureSite]:
    site = FixtureSite()
    site.start()
    try:
        yield site
    finally:
        site.stop()


@pytest.fixture
def cdn() -> Iterator[FixtureSite]:
    """A second local server: a different origin, standing in for a vendor's CDN."""
    site = FixtureSite()
    site.start()
    try:
        yield site
    finally:
        site.stop()
