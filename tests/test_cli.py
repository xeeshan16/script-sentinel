from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from script_sentinel import __version__
from script_sentinel.cli import app

runner = CliRunner()
SHOP = "https://shop.example.com"


def _invoke(*args: str, input: str | None = None) -> tuple[int, str]:
    result = runner.invoke(app, list(args), input=input)
    return result.exit_code, result.output


def test_version() -> None:
    assert _invoke("version") == (0, f"{__version__}\n")


def test_db_commands(tmp_path: Path) -> None:
    url = f"sqlite+aiosqlite:///{tmp_path / 'cli.db'}"
    assert _invoke("db", "upgrade", "--url", url) == (0, "database upgraded to head\n")
    assert _invoke("db", "current", "--url", url) == (0, "0001 (head)\n")
    assert _invoke("db", "downgrade", "base", "--url", url) == (
        0,
        "database downgraded to base\n",
    )
    assert _invoke("db", "current", "--url", url) == (0, "")


def test_database_url_comes_from_the_environment(
    sqlite_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SENTINEL_DATABASE_URL", sqlite_url)
    code, out = _invoke("sites", "list")
    assert code == 0
    assert "no sites yet" in out


def test_sites_and_pages(sqlite_url: str) -> None:
    url = ("--url", sqlite_url)
    code, out = _invoke("sites", "add", "shop", "-o", SHOP, "-o", "http://localhost:8000", *url)
    assert code == 0
    assert out == f"added site shop: http://localhost:8000, {SHOP} (scan every 168h)\n"

    code, out = _invoke(
        "pages", "add", "shop", SHOP + "/checkout", "--payment", "--label", "checkout", *url
    )
    assert (code, out) == (0, f"added page {SHOP}/checkout (payment page)\n")
    assert _invoke("pages", "add", "shop", "http://localhost:8000/", *url)[0] == 0

    code, out = _invoke("pages", "list", "shop", *url)
    assert out.splitlines() == [
        "         http://localhost:8000/",
        f"payment  {SHOP}/checkout  (checkout)",
    ]
    code, out = _invoke("pages", "list", "shop", "--json", *url)
    assert json.loads(out)[1] == {
        "url": f"{SHOP}/checkout",
        "label": "checkout",
        "payment_page": True,
    }

    code, out = _invoke("sites", "list", *url)
    assert out.startswith("shop                 pages=2    payment=1    every 168h")
    code, out = _invoke("sites", "list", "--json", *url)
    assert json.loads(out) == [
        {
            "name": "shop",
            "allowed_origins": ["http://localhost:8000", SHOP],
            "scan_interval_hours": 168,
            "pages": 2,
            "payment_pages": 1,
        }
    ]

    assert _invoke("pages", "remove", "shop", "http://localhost:8000/", *url)[0] == 0
    # Without --yes the removal asks first; answering "n" keeps the site.
    assert _invoke("sites", "remove", "shop", *url, input="n\n")[0] == 1
    assert _invoke("sites", "remove", "shop", "--yes", *url) == (0, "removed site shop\n")


def test_errors_exit_non_zero(sqlite_url: str) -> None:
    url = ("--url", sqlite_url)
    assert _invoke("sites", "add", "shop", "-o", SHOP, "--interval-hours", "6", *url)[0] == 0
    code, out = _invoke("sites", "add", "shop", "-o", SHOP, *url)
    assert code == 1
    assert "already exists" in out
    code, out = _invoke("pages", "add", "shop", "https://evil.test/", *url)
    assert code == 2
    assert "not on an allowed origin" in out
    assert _invoke("pages", "list", "nope", *url)[0] == 1
    # Typer validates the interval before anything touches the database.
    assert _invoke("sites", "add", "blog", "-o", SHOP, "--interval-hours", "500", *url)[0] == 2
