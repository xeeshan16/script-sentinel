from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from script_sentinel import __version__
from script_sentinel.cli import app
from script_sentinel.sri import integrity_value
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
    assert _invoke("db", "current", "--url", url) == (0, "0004 (head)\n")
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
    app_v1 = b"boot();\n"
    fixture_site.set("/robots.txt", "User-agent: *\nDisallow: /checkout\n")
    fixture_site.set("/app.js", app_v1, content_type="text/javascript")
    fixture_site.page(
        "/checkout",
        '<script src="/app.js" integrity="sha384-x" defer></script>'
        '<script nonce="n">pay()</script><script src="javascript:x()"></script>',
    )
    fixture_site.set(
        "/",
        '<script src="/app.js"></script>',
        content_security_policy_report_only="script-src 'self'",
        x_content_type_options="nosniff",
    )
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
    assert "bodies: 1 external fetched, 0 failed; 1 new versions, 0 scripts changed" in (
        result.stdout
    )

    sri_v1 = integrity_value(app_v1)
    _invoke("sites", "update", "shop", "--ignore-robots", *url)
    result = runner.invoke(app, ["scan", "run", "shop", *url])
    assert result.exit_code == 0
    lines = result.stdout.splitlines()
    assert lines[0].startswith("scan ")
    assert "of shop: completed in " in lines[0]
    assert lines[0].endswith("(2 pages: 2 ok)")
    inline_sri = integrity_value(b"pay()")
    assert lines[1:] == [
        f"  ok       {origin}/  200  1 scripts",
        "      headers: CSP report-only, nosniff",
        f"        {origin}/app.js  (classic)  {sri_v1[:22]}…",
        f"  ok       {origin}/checkout [payment]  200  2 scripts (1 new)",
        "      headers: no security headers",
        f"        {origin}/app.js  (classic, INTEGRITY MISMATCH)  {sri_v1[:22]}…",
        f"      + {origin}/checkout#inline-1  (classic, nonce)  {inline_sri[:22]}…",
        "      ! skipped <script> with a javascript: src that can't be fetched: javascript:x()",
        "inventory: 2 scripts seen, 1 new (pending approval)",
        "bodies: 1 external fetched, 0 failed; 1 new versions, 0 scripts changed",
    ]
    assert "1 script tags fail their integrity check" in result.stderr

    # The vendor ships a new body: a new version of the same script, marked "~".
    fixture_site.set("/app.js", b"boot(2);\n", content_type="text/javascript")
    code, out = _invoke("scan", "run", "shop", *url)
    assert code == 0
    assert f"      ~ {origin}/app.js  (classic)  " in out
    assert "bodies: 1 external fetched, 0 failed; 1 new versions, 1 scripts changed" in out

    code, out = _invoke("scan", "list", "shop", *url)
    rows = out.splitlines()
    assert len(rows) == 3
    assert "completed cli" in rows[0]
    assert "pages ok=2 skipped=0 failed=0  scripts=2 new=0" in rows[0]
    listed = json.loads(_invoke("scan", "list", "shop", "--json", "--limit", "1", *url)[1])
    assert len(listed) == 1
    assert listed[0]["scripts_seen"] == 2

    scan_id = listed[0]["id"]
    code, out = _invoke("scan", "show", scan_id, *url)
    assert code == 0
    assert not [line for line in out.splitlines() if line.startswith(("      +", "      ~"))]
    shown = json.loads(_invoke("scan", "show", scan_id, "--json", *url)[1])
    assert shown["id"] == scan_id
    assert shown["status"] == "completed"
    assert shown["pages"] == {"total": 2, "ok": 2, "skipped": 0, "failed": 0}
    assert shown["scripts"] == {
        "seen": 2,
        "new": 0,
        "fetched": 1,
        "fetch_failed": 0,
        "versions_new": 1,
        "changed": 1,
    }
    home, checkout = shown["snapshots"]
    assert home["security_headers"] == {
        "content-security-policy-report-only": ["script-src 'self'"],
        "x-content-type-options": ["nosniff"],
    }
    assert checkout["scripts"][0]["sri_status"] == "mismatch"
    assert checkout["scripts"][1]["has_nonce"] is True
    assert checkout["scripts"][1]["sri"] == inline_sri
    assert checkout["warnings"] == [
        "skipped <script> with a javascript: src that can't be fetched: javascript:x()"
    ]
    (fetch,) = shown["script_fetches"]
    assert (fetch["url"], fetch["outcome"], fetch["new_version"]) == (
        origin + "/app.js",
        "ok",
        True,
    )
    assert fetch["sri"] == integrity_value(b"boot(2);\n")

    code, out = _invoke("scripts", "list", "shop", *url)
    sri_v2 = integrity_value(b"boot(2);\n")
    assert out.splitlines() == [
        f"pending   external  v2   {sri_v2[:22] + '…':<25} {origin}/app.js",
        f"pending   inline    v1   {inline_sri[:22] + '…':<25} {origin}/checkout#inline-1",
    ]
    scripts = json.loads(_invoke("scripts", "list", "shop", "--json", *url)[1])
    assert [(s["kind"], s["version_count"]) for s in scripts] == [("external", 2), ("inline", 1)]

    code, out = _invoke("scripts", "show", "shop", origin + "/app.js", *url)
    assert code == 0
    lines = out.splitlines()
    assert lines[0] == f"{origin}/app.js"
    assert lines[1] == "  kind: external   status: pending"
    assert lines[3] == "  versions (2, most recently seen first):"
    assert lines[4].endswith(f"       9 bytes  {sri_v2}")
    assert lines[5].endswith(f"       8 bytes  {sri_v1}")
    assert lines[6:] == [
        "  pin the current body with:",
        f'    <script src="{origin}/app.js" integrity="{sri_v2}" crossorigin="anonymous"></script>',
    ]
    code, out = _invoke("scripts", "show", "shop", origin + "/checkout#inline-1", *url)
    assert out.splitlines()[-1] == f"  CSP hash source for the current body: '{inline_sri}'"
    shown_script = json.loads(
        _invoke("scripts", "show", "shop", origin + "/app.js", "--json", *url)[1]
    )
    assert [v["sri"] for v in shown_script["versions"]] == [sri_v2, sri_v1]
    assert shown_script["current_sri"] == sri_v2
    code, out = _invoke("scripts", "show", "shop", origin + "/nope.js", *url)
    assert code == 1
    assert "sentinel scripts list shop" in out

    assert _invoke("scan", "show", "not-an-id", *url)[0] == 2
    code, out = _invoke("scan", "show", "00000000-0000-0000-0000-000000000000", *url)
    assert code == 1
    assert "not found" in out


def test_scan_run_reports_scripts_it_could_not_fetch(
    sqlite_url: str, fixture_site: FixtureSite
) -> None:
    url = ("--url", sqlite_url)
    fixture_site.page(
        "/",
        '<script src="/gone.js" integrity="sha384-abc"></script>'
        '<script integrity="sha384-abc">x()</script>',
    )
    _invoke("sites", "add", "shop", "-o", fixture_site.origin, *url)
    _invoke("pages", "add", "shop", fixture_site.url("/"), *url)
    result = runner.invoke(app, ["scan", "run", "shop", *url])
    assert result.exit_code == 0  # the page itself was inventoried
    assert (
        f"      + {fixture_site.url('/gone.js')}  (classic, integrity unverified, "
        "not fetched: HTTP 404)"
    ) in result.stdout
    assert "bodies: 0 external fetched, 1 failed; 1 new versions" in result.stdout
    assert "1 external scripts could not be fetched" in result.stderr
    # integrity on an inline script is ignored by browsers; it's only shown as present.
    assert f"      + {fixture_site.url('/#inline-1')}  (classic, integrity)  " in result.stdout
    # Next time the script is already known, and the failure is marked with "!".
    out = _invoke("scan", "run", "shop", *url)[1]
    assert f"      ! {fixture_site.url('/gone.js')}  (classic, integrity unverified" in out
    out = _invoke("scripts", "show", "shop", fixture_site.url("/gone.js"), *url)[1]
    assert out.splitlines()[-1] == "  no body recorded yet (the script could not be fetched)"
    assert "(no body yet)" in _invoke("scripts", "list", "shop", *url)[1]


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
