"""The fixture shop in examples/ behaves the way the README's quick start says."""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import httpx
import pytest
from typer.testing import CliRunner

from script_sentinel.cli import app
from script_sentinel.sri import integrity_value

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _load_serve() -> ModuleType:
    spec = importlib.util.spec_from_file_location("fixture_serve", EXAMPLES / "serve.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look the module up while decorating
    spec.loader.exec_module(module)
    return module


serve = _load_serve()


@pytest.fixture
def demo() -> Iterator[serve.Demo]:  # type: ignore[name-defined]
    with serve.start() as running:
        yield running


def test_fixture_servers(demo: serve.Demo) -> None:  # type: ignore[name-defined]
    home = httpx.get(f"{demo.site_origin}/")
    assert home.status_code == 200
    assert "{{CDN}}" not in home.text
    assert f'src="{demo.cdn_origin}/analytics/v2/tag.js"' in home.text
    assert home.headers["x-content-type-options"] == "nosniff"
    checkout = httpx.get(f"{demo.site_origin}/checkout.html")
    assert demo.cdn_origin in checkout.headers["content-security-policy-report-only"]
    assert httpx.get(f"{demo.site_origin}/nope.html").status_code == 404
    module = httpx.get(f"{demo.site_origin}/js/checkout.mjs")
    assert module.headers["content-type"] == "text/javascript"
    tag = httpx.get(f"{demo.cdn_origin}/analytics/v2/tag.js")
    assert tag.headers["content-type"] == "text/javascript"


def test_checkout_pins_the_payments_library_with_its_real_hash() -> None:
    body = (EXAMPLES / "fixture-cdn" / "payments" / "v3" / "elements.js").read_bytes()
    checkout = (EXAMPLES / "fixture-site" / "checkout.html").read_text()
    assert f'integrity="{integrity_value(body)}"' in checkout


def test_quick_start_against_the_fixture_site(
    sqlite_url: str,
    demo: serve.Demo,  # type: ignore[name-defined]
) -> None:
    runner = CliRunner()
    url = ["--url", sqlite_url]
    site = demo.site_origin

    def run(*args: str) -> tuple[int, str]:
        result = runner.invoke(app, [*args, *url])
        return result.exit_code, result.stdout

    assert run("sites", "add", "shop", "--origin", site)[0] == 0
    assert run("pages", "add", "shop", f"{site}/index.html")[0] == 0
    assert run("pages", "add", "shop", f"{site}/checkout.html", "--payment")[0] == 0

    code, out = run("scan", "run", "shop")
    assert code == 0
    assert "(2 pages: 1 ok, 1 skipped)" in out.splitlines()[0]
    assert "inventory: 3 scripts seen, 3 new (pending approval)" in out
    assert "bodies: 2 external fetched, 0 failed; 3 new versions, 0 scripts changed" in out

    assert run("sites", "update", "shop", "--ignore-robots")[0] == 0
    code, out = run("scan", "run", "shop")
    assert code == 0
    assert "(2 pages: 2 ok)" in out.splitlines()[0]
    assert "inventory: 7 scripts seen, 4 new (pending approval)" in out
    assert "bodies: 4 external fetched, 0 failed; 4 new versions, 0 scripts changed" in out
    assert "      headers: CSP report-only, nosniff, Referrer-Policy" in out
    assert f"{demo.cdn_origin}/payments/v3/elements.js  (classic, integrity ok)" in out

    code, out = run("scripts", "list", "shop")
    assert len(out.splitlines()) == 7
    code, out = run("scripts", "show", "shop", f"{demo.cdn_origin}/analytics/v2/tag.js")
    assert code == 0
    assert "pin the current body with:" in out
