from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from script_sentinel import __version__
from script_sentinel.cli import app
from tests.conftest import FixtureSite

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
    assert _invoke("db", "current", "--url", url) == (0, "0002 (head)\n")
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


def test_robots_options(sqlite_url: str) -> None:
    url = ("--url", sqlite_url)
    code, out = _invoke("sites", "add", "shop", "-o", SHOP, "--ignore-robots", *url)
    assert (code, out) == (0, f"added site shop: {SHOP} (scan every 168h, robots.txt ignored)\n")
    code, out = _invoke(
        "sites", "update", "shop", "--respect-robots", "--interval-hours", "12", *url
    )
    assert (code, out) == (0, "updated site shop: scan every 12h, robots.txt respected\n")
    code, out = _invoke("sites", "update", "shop", "--ignore-robots", *url)
    assert out == "updated site shop: scan every 12h, robots.txt ignored\n"
    assert _invoke("sites", "update", "nope", "--ignore-robots", *url)[0] == 1


def test_scan_run_list_show_and_scripts(sqlite_url: str, fixture_site: FixtureSite) -> None:
    url = ("--url", sqlite_url)
    origin = fixture_site.origin
    fixture_site.set("/robots.txt", "User-agent: *\nDisallow: /checkout\n")
    fixture_site.page(
        "/checkout",
        '<script src="/app.js" integrity="sha384-x" defer></script>'
        '<script nonce="n">pay()</script><script src="javascript:x()"></script>',
    )
    fixture_site.page("/", '<script src="/app.js"></script>')
    assert _invoke("scan", "list", "nope", *url)[0] == 1
    _invoke("sites", "add", "shop", "-o", origin, *url)
    _invoke("pages", "add", "shop", origin + "/checkout", "--payment", *url)
    _invoke("pages", "add", "shop", origin + "/", *url)

    assert _invoke("scan", "list", "shop", *url) == (
        0,
        "no scans of shop yet; run one with: sentinel scan run shop\n",
    )
    assert _invoke("scripts", "list", "shop", *url)[1].startswith("no scripts recorded")

    # robots.txt keeps the payment page out; the CLI says how to opt out.
    result = runner.invoke(app, ["scan", "run", "shop", *url])
    assert result.exit_code == 0
    assert f"  robots   {origin}/checkout [payment]  disallowed by robots.txt" in result.stdout
    assert "sentinel sites update shop --ignore-robots" in result.stderr

    _invoke("sites", "update", "shop", "--ignore-robots", *url)
    code, out = _invoke("scan", "run", "shop", *url)
    assert code == 0
    lines = out.splitlines()
    assert lines[0].startswith("scan ")
    assert "of shop: completed in " in lines[0]
    assert lines[0].endswith("(2 pages: 2 ok)")
    assert lines[1:] == [
        f"  ok       {origin}/  200  1 scripts",
        f"        {origin}/app.js  (classic)",
        f"  ok       {origin}/checkout [payment]  200  2 scripts (1 new)",
        f"        {origin}/app.js  (classic, integrity)",
        f"      + {origin}/checkout#inline-1  (classic, nonce)",
        "      ! skipped <script> with a javascript: src that can't be fetched: javascript:x()",
        "inventory: 2 scripts seen, 1 new (pending approval)",
    ]

    code, out = _invoke("scan", "list", "shop", *url)
    rows = out.splitlines()
    assert len(rows) == 2
    assert "completed cli" in rows[0]
    assert "pages ok=2 skipped=0 failed=0  scripts=2 new=1" in rows[0]
    listed = json.loads(_invoke("scan", "list", "shop", "--json", "--limit", "1", *url)[1])
    assert len(listed) == 1
    assert listed[0]["scripts_seen"] == 2

    scan_id = listed[0]["id"]
    code, out = _invoke("scan", "show", scan_id, *url)
    assert code == 0
    assert "+" not in out.split("\n", 1)[1]
    shown = json.loads(_invoke("scan", "show", scan_id, "--json", *url)[1])
    assert shown["id"] == scan_id
    assert shown["status"] == "completed"
    assert shown["pages"] == {"total": 2, "ok": 2, "skipped": 0, "failed": 0}
    checkout = shown["snapshots"][1]
    assert checkout["scripts"][1]["has_nonce"] is True
    assert checkout["warnings"] == [
        "skipped <script> with a javascript: src that can't be fetched: javascript:x()"
    ]

    code, out = _invoke("scripts", "list", "shop", *url)
    assert out.splitlines() == [
        f"pending   external  {origin}/app.js",
        f"pending   inline    {origin}/checkout#inline-1",
    ]
    scripts = json.loads(_invoke("scripts", "list", "shop", "--json", *url)[1])
    assert [s["kind"] for s in scripts] == ["external", "inline"]

    assert _invoke("scan", "show", "not-an-id", *url)[0] == 2
    code, out = _invoke("scan", "show", "00000000-0000-0000-0000-000000000000", *url)
    assert code == 1
    assert "not found" in out


def test_scan_run_exits_3_when_pages_fail(sqlite_url: str, fixture_site: FixtureSite) -> None:
    url = ("--url", sqlite_url)
    fixture_site.set("/", "down", 503)
    _invoke("sites", "add", "shop", "-o", fixture_site.origin, "--ignore-robots", *url)
    _invoke("pages", "add", "shop", fixture_site.url("/"), *url)
    code, out = _invoke("scan", "run", "shop", *url)
    assert code == 3
    assert f"  http     {fixture_site.url('/')}  HTTP 503" in out
    assert out.splitlines()[0].endswith("(1 pages: 0 ok, 1 failed)")
    assert ": failed in " in out.splitlines()[0]
    code, out = _invoke("scan", "run", "shop", "--json", *url)
    assert code == 3
    assert json.loads(out)["snapshots"][0]["outcome"] == "http_error"


def test_scan_run_needs_pages(sqlite_url: str) -> None:
    url = ("--url", sqlite_url)
    _invoke("sites", "add", "shop", "-o", SHOP, *url)
    code, out = _invoke("scan", "run", "shop", *url)
    assert code == 2
    assert "has no pages to scan" in out
