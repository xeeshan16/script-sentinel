from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from typer.testing import CliRunner

from script_sentinel.cli import app
from script_sentinel.sri import integrity_value
from tests.conftest import FixtureSite

runner = CliRunner()


def _invoke(*args: str, env: dict[str, str] | None = None) -> tuple[int, str]:
    result = runner.invoke(app, list(args), env=env)
    return result.exit_code, result.output


@pytest.fixture
def shop(
    sqlite_url: str, fixture_site: FixtureSite, cdn: FixtureSite
) -> tuple[list[str], str, str]:
    """A scanned shop: (--url args, vendor script URL, inline locator)."""
    url = ["--url", sqlite_url]
    vendor = cdn.url("/sdk/widget.js")
    cdn.set("/sdk/widget.js", b"widget(1);", content_type="text/javascript")
    fixture_site.page("/checkout", f'<script src="{vendor}"></script><script>pay();</script>')
    _invoke("sites", "add", "shop", "-o", fixture_site.origin, *url)
    _invoke("pages", "add", "shop", fixture_site.url("/checkout"), "--payment", *url)
    return url, vendor, fixture_site.url("/checkout#inline-1")


def test_decisions_and_the_scan_gate(shop: tuple[list[str], str, str], cdn: FixtureSite) -> None:
    url, vendor, inline = shop
    result = runner.invoke(app, ["scan", "run", "shop", "--fail-on-unauthorized", *url])
    assert result.exit_code == 4
    assert "authorization: 0 approved, 2 pending, 0 rejected" in result.stdout
    assert "payment pages run 2 scripts that are not approved" in result.stderr

    code, out = _invoke(
        "scripts", "approve", "shop", vendor, "-j", "PSP card widget.", "--actor", "alice", *url
    )
    assert (code, out) == (0, f"approved: {vendor}\n  why: approved by alice\n")
    code, out = _invoke(
        "scripts",
        "approve",
        "shop",
        inline,
        "-j",
        "Checkout bootstrap.",
        *url,
        env={"SENTINEL_ACTOR": "ci-bot"},
    )
    assert out.splitlines()[1] == "  why: approved by ci-bot"
    scan = json.loads(_invoke("scan", "run", "shop", "--json", "--fail-on-unauthorized", *url)[1])
    assert scan["authorization"] == {"approved": 2, "pending": 0, "rejected": 0}
    assert {s["authorization_status"] for s in scan["snapshots"][0]["scripts"]} == {"approved"}

    code, out = _invoke("scripts", "show", "shop", vendor, *url)
    lines = out.splitlines()
    assert lines[1:3] == ["  kind: external   status: approved", "  why: approved by alice"]
    assert lines[3].startswith("  decision: approved, pinned by alice at ")
    assert lines[4] == "  justification: PSP card widget."
    assert lines[7].endswith(f"{integrity_value(b'widget(1);')}  approved by alice")
    shown = json.loads(_invoke("scripts", "show", "shop", vendor, "--json", *url)[1])
    assert (shown["decision"], shown["approval_scope"], shown["decided_by"]) == (
        "approved",
        "pinned",
        "alice",
    )
    assert shown["versions"][0]["approved_by"] == "alice"

    # A new vendor body lapses the pinned approval, and the gate fails again.
    cdn.set("/sdk/widget.js", b"widget(2);", content_type="text/javascript")
    code, out = _invoke("scan", "run", "shop", "--fail-on-unauthorized", *url)
    assert code == 4
    assert f"~ {vendor}  (classic, pending)" in out

    code, out = _invoke("scripts", "reject", "shop", vendor, "-r", "Unreviewed.", *url)
    assert out.startswith(f"rejected: {vendor}")
    code, out = _invoke("scripts", "reset", "shop", vendor, "-r", "Reviewing.", *url)
    assert out.startswith(f"pending: {vendor}")
    assert _invoke("scripts", "reset", "shop", vendor, "-r", "again", *url)[0] == 1
    assert _invoke("scripts", "approve", "shop", vendor, "-j", " ", *url)[0] == 2
    assert _invoke("scripts", "approve", "shop", "nope.js", "-j", "x", *url)[0] == 1

    code, out = _invoke("audit", "list", "shop", "--script", vendor, *url)
    rows = [line for line in out.splitlines() if line.startswith("#")]
    assert [row.split()[3] for row in rows] == [
        "script.reset",
        "script.rejected",
        "script.status_changed",
        "script.approved",
        "script.status_changed",
    ]
    assert "new -> pending" in rows[-1]
    assert "      Unreviewed." in out
    events = json.loads(_invoke("audit", "list", "shop", "--json", "--limit", "2", *url)[1])
    assert [e["seq"] for e in events] == [7, 6]
    assert _invoke("audit", "verify", "shop", *url)[1].startswith(
        "audit trail of shop is intact: 7 events, head "
    )


def test_policies_commands(shop: tuple[list[str], str, str], cdn: FixtureSite) -> None:
    url, vendor, inline = shop
    assert _invoke("policies", "list", "shop", *url)[1].startswith("no policies for shop")
    _invoke("scan", "run", "shop", *url)

    code, out = _invoke(
        "policies",
        "add",
        "shop",
        "--prefix",
        cdn.url("/sdk"),
        "--expected-to-change",
        "--ignore-query",
        "v",
        "-j",
        "PSP SDK.",
        "--actor",
        "alice",
        *url,
    )
    assert code == 0
    lines = out.splitlines()
    assert lines[0].startswith("added policy ")
    assert lines[0].endswith(f": prefix policy {cdn.url('/sdk')}")
    assert lines[1:] == [
        f"  pending -> approved: {vendor}  "
        f"(approved by prefix policy {cdn.url('/sdk')} (expected to change))"
    ]

    added = json.loads(
        _invoke(
            "policies",
            "add",
            "shop",
            "--hash",
            integrity_value(b"pay();"),
            "-j",
            "Bootstrap.",
            "--json",
            *url,
        )[1]
    )
    assert added["policy"]["kind"] == "hash"
    assert added["scripts_changed"] == [
        {"locator": inline, "from_status": "pending", "to_status": "approved"}
    ]
    code, out = _invoke(
        "policies", "add", "shop", "--origin", cdn.origin, "-j", "Nothing new.", *url
    )
    assert out.splitlines()[1] == "  no script changed status"

    listed = json.loads(_invoke("policies", "list", "shop", "--json", *url)[1])
    assert [p["kind"] for p in listed] == ["prefix", "hash", "origin"]
    code, out = _invoke("policies", "list", "shop", *url)
    assert "expected_to_change" in out
    assert "  ignore query: v" in out
    assert "    PSP SDK. (alice, " in out

    prefix_id = listed[0]["id"]
    code, out = _invoke("policies", "remove", "shop", prefix_id, "-r", "Offboarded.", *url)
    assert out.splitlines() == [
        f"removed policy {prefix_id}",
        # The origin policy takes over: it pins the first body seen.
        f"  approved -> approved: {vendor}  "
        f"(approved by origin policy {cdn.origin}, pinned to the first body seen)",
    ]
    assert _invoke("policies", "remove", "shop", "not-an-id", "-r", "x", *url)[0] == 2
    assert _invoke("policies", "remove", "shop", prefix_id, "-r", "x", *url)[0] == 1

    for args in (
        ["policies", "add", "shop", "-j", "x"],
        ["policies", "add", "shop", "--origin", cdn.origin, "--hash", "x", "-j", "x"],
    ):
        code, out = _invoke(*args, *url)
        assert code == 2
        assert "exactly one of --origin, --prefix or --hash" in out
    assert _invoke("policies", "add", "shop", "--hash", "abc", "-j", "x", *url)[0] == 2
    assert _invoke("policies", "add", "shop", "--origin", cdn.origin, "-j", "x", *url)[0] == 1

    code, out = _invoke("audit", "list", "shop", *url)
    assert "policy.removed        " in out
    assert f"prefix {cdn.url('/sdk')}" in out


def test_audit_verify_reports_a_broken_chain(
    sqlite_url: str, shop: tuple[list[str], str, str]
) -> None:
    url, _, _ = shop
    assert _invoke("audit", "list", "shop", *url)[1] == "no audit events for shop yet\n"
    verified = json.loads(_invoke("audit", "verify", "shop", "--json", *url)[1])
    assert (verified["ok"], verified["events"]) == (True, 0)

    _invoke("scan", "run", "shop", *url)
    engine = create_engine(sqlite_url.replace("+aiosqlite", ""))
    with engine.begin() as conn:
        conn.execute(text("UPDATE authorization_events SET reason = 'edited' WHERE seq = 1"))
    engine.dispose()
    result = runner.invoke(app, ["audit", "verify", "shop", *url])
    assert result.exit_code == 1
    assert "audit trail of shop is BROKEN at event 1" in result.stderr
    code, out = _invoke("audit", "verify", "shop", "--json", *url)
    assert code == 1
    assert json.loads(out)["first_bad_seq"] == 1
    assert _invoke("audit", "verify", "nope", *url)[0] == 1


def test_actor_defaults_to_the_login_name(
    shop: tuple[list[str], str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    url, vendor, _ = shop
    _invoke("scan", "run", "shop", *url)
    monkeypatch.delenv("SENTINEL_ACTOR", raising=False)
    monkeypatch.setattr("getpass.getuser", lambda: "zeeshan")
    out = _invoke("scripts", "approve", "shop", vendor, "-j", "ok", "--any-version", *url)[1]
    assert out.splitlines()[1] == "  why: approved by zeeshan for any version"


def test_audit_list_for_an_unknown_script(tmp_path: Path) -> None:
    url = f"sqlite+aiosqlite:///{tmp_path / 'a.db'}"
    _invoke("db", "upgrade", "--url", url)
    _invoke("sites", "add", "shop", "-o", "https://shop.example.com", "--url", url)
    code, out = _invoke("audit", "list", "shop", "--script", "x.js", "--url", url)
    assert code == 1
    assert "no script 'x.js'" in out


def test_rows_from_before_authorization_existed(
    sqlite_url: str, shop: tuple[list[str], str, str]
) -> None:
    """Scans and scripts recorded before 0004 have no status reason or recorded status."""
    url, vendor, _ = shop
    _invoke("scan", "run", "shop", *url)
    engine = create_engine(sqlite_url.replace("+aiosqlite", ""))
    with engine.begin() as conn:
        conn.execute(text("UPDATE scripts SET status_reason = NULL"))
        conn.execute(text("UPDATE script_observations SET authorization_status = NULL"))
        conn.execute(text("UPDATE authorization_events SET reason = NULL"))
    engine.dispose()

    scan_id = json.loads(_invoke("scan", "list", "shop", "--json", *url)[1])[0]["id"]
    out = _invoke("scan", "show", scan_id, *url)[1]
    assert f"  {vendor}  (classic)  " in out
    out = _invoke("scripts", "show", "shop", vendor, *url)[1]
    assert "why:" not in out
    out = _invoke("audit", "list", "shop", *url)[1]
    assert len(out.splitlines()) == 2  # one line per event, no reason lines
