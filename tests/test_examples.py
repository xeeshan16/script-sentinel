"""The fixture site in examples/ behaves the way the README's quick start says."""

from __future__ import annotations

import functools
import threading
from collections.abc import Iterator
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from typer.testing import CliRunner

from script_sentinel.cli import app

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "fixture-site"


class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture
def example_origin() -> Iterator[str]:
    handler = functools.partial(_QuietHandler, directory=str(EXAMPLE))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def test_quick_start_against_the_fixture_site(sqlite_url: str, example_origin: str) -> None:
    runner = CliRunner()
    url = ["--url", sqlite_url]

    def run(*args: str) -> tuple[int, str]:
        result = runner.invoke(app, [*args, *url])
        return result.exit_code, result.stdout

    assert run("sites", "add", "shop", "--origin", example_origin)[0] == 0
    assert run("pages", "add", "shop", f"{example_origin}/index.html")[0] == 0
    assert run("pages", "add", "shop", f"{example_origin}/checkout.html", "--payment")[0] == 0

    code, out = run("scan", "run", "shop")
    assert code == 0
    assert "(2 pages: 1 ok, 1 skipped)" in out.splitlines()[0]
    assert "inventory: 3 scripts seen, 3 new (pending approval)" in out

    assert run("sites", "update", "shop", "--ignore-robots")[0] == 0
    code, out = run("scan", "run", "shop")
    assert code == 0
    assert "(2 pages: 2 ok)" in out.splitlines()[0]
    assert "inventory: 7 scripts seen, 4 new (pending approval)" in out
    assert "https://js.payments.test/v3/elements.js  (classic, integrity)" in out

    code, out = run("scripts", "list", "shop")
    assert len(out.splitlines()) == 7
