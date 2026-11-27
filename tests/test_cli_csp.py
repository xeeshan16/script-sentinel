from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from script_sentinel.cli import app

runner = CliRunner()
EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "csp-reports"
LEGACY = str(EXAMPLES / "report-uri.json")
BATCH = str(EXAMPLES / "reporting-api.json")


def _invoke(
    *args: str, stdin: bytes | None = None, env: dict[str, str] | None = None
) -> tuple[int, str]:
    result = runner.invoke(app, list(args), input=stdin, env=env)
    return result.exit_code, result.output


@pytest.fixture
def url(sqlite_url: str) -> list[str]:
    url = ["--url", sqlite_url]
    assert _invoke("sites", "add", "shop", "-o", "https://shop.example.com", *url)[0] == 0
    return url


def test_ingest_prints_what_was_counted_and_dropped(url: list[str]) -> None:
    code, out = _invoke("csp", "ingest", "shop", LEGACY, *url)
    assert code == 0, out
    assert out == "csp-report: 1 received, 1 accepted (1 new groups, 0 updated)\n"
    code, out = _invoke("csp", "ingest", "shop", BATCH, *url)
    assert code == 0, out
    assert "reporting-api: 6 received, 3 accepted (2 new groups, 0 updated)" in out
    assert "dropped: not_csp 1, foreign_document 1, extension 1" in out


def test_ingest_json_and_stdin_and_format(url: list[str]) -> None:
    body = Path(BATCH).read_bytes()
    code, out = _invoke(
        "csp", "ingest", "shop", "-", "--format", "reporting-api", "--json", *url, stdin=body
    )
    assert code == 0, out
    result = json.loads(out)
    assert (result["accepted"], result["groups_new"]) == (3, 2)
    code, out = _invoke("csp", "ingest", "shop", BATCH, "--json", *url)
    assert json.loads(out)["groups_updated"] == 2


def test_ingest_errors(url: list[str], tmp_path: Path) -> None:
    code, out = _invoke("csp", "ingest", "shop", BATCH, "--format", "xml", *url)
    assert code == 2
    assert "--format is one of auto, csp-report, reporting-api" in out
    code, out = _invoke("csp", "ingest", "shop", str(tmp_path / "missing.json"), *url)
    assert code == 2
    assert "cannot read" in out
    # A batch given as a report-uri payload contradicts its format.
    code, out = _invoke("csp", "ingest", "shop", BATCH, "--format", "csp-report", *url)
    assert code == 2
    assert "csp-report" in out
    big = tmp_path / "big.json"
    big.write_bytes(b" " * 2048)
    code, out = _invoke(
        "csp", "ingest", "shop", str(big), *url, env={"SENTINEL_CSP_MAX_BODY_BYTES": "1024"}
    )
    assert code == 2
    assert "SENTINEL_CSP_MAX_BODY_BYTES" in out
    code, out = _invoke("csp", "ingest", "nope", BATCH, *url)
    assert code == 1
    assert "not found" in out


def test_violations_lists_groups(url: list[str]) -> None:
    code, out = _invoke("csp", "violations", "shop", *url)
    assert (code, out) == (0, "no CSP violations recorded for shop\n")
    _invoke("csp", "ingest", "shop", LEGACY, *url)
    _invoke("csp", "ingest", "shop", BATCH, *url)
    code, out = _invoke("csp", "violations", "shop", "--order", "count", *url)
    assert code == 0, out
    lines = out.splitlines()
    assert lines[0] == "3 groups, 4 reports"
    assert lines[1].split() == [
        "2x",
        "enforce",
        "connect-src",
        "https://collect.skim.test/beacon",
    ]
    assert (
        "on https://shop.example.com/checkout from https://cdn.vendor.test/analytics/v2/tag.js:1"
        in lines[2]
    )
    assert "sample: window.dataLayer=window.dataLayer||[];fu" in out
    assert "from line" not in out

    code, out = _invoke(
        "csp", "violations", "shop", "--disposition", "REPORT", "--limit", "1", *url
    )
    assert code == 0, out
    assert out.splitlines()[0] == "1 groups, 1 reports"
    assert "https://collect.skim.test/c.js" in out

    code, out = _invoke("csp", "violations", "shop", "--limit", "1", "--json", *url)
    body = json.loads(out)
    assert (body["total_groups"], len(body["violations"])) == (3, 1)
    code, out = _invoke("csp", "violations", "shop", "--limit", "1", *url)
    assert "(showing 1)" in out.splitlines()[0]

    code, out = _invoke(
        "csp",
        "violations",
        "shop",
        "--directive",
        "script-src-elem",
        "--host",
        "collect.skim.test",
        *url,
    )
    assert out.splitlines()[0] == "1 groups, 1 reports"


def test_violations_without_a_source_file(url: list[str], tmp_path: Path) -> None:
    payload = tmp_path / "inline.json"
    payload.write_text(
        json.dumps(
            [
                {
                    "type": "csp-violation",
                    "body": {
                        "documentURL": "https://shop.example.com/",
                        "effectiveDirective": "script-src-elem",
                        "blockedURL": "inline",
                        "lineNumber": 7,
                    },
                },
                {
                    "type": "csp-violation",
                    "body": {
                        "documentURL": "https://shop.example.com/",
                        "effectiveDirective": "img-src",
                        "blockedURL": "data",
                    },
                },
            ]
        )
    )
    _invoke("csp", "ingest", "shop", str(payload), *url)
    code, out = _invoke("csp", "violations", "shop", *url)
    assert code == 0, out
    assert "on https://shop.example.com/ from line 7" in out
    assert "unknown  img-src          data:" in out


def test_violation_json_has_every_field(url: list[str]) -> None:
    _invoke("csp", "ingest", "shop", LEGACY, *url)
    _, out = _invoke("csp", "violations", "shop", "--json", *url)
    (group,) = json.loads(out)["violations"]
    assert group["document_url"] == "https://shop.example.com/checkout"
    assert group["blocked_kind"] == "url"
    assert group["disposition"] == "report"
    assert group["report_format"] == "csp-report"
    assert (group["line"], group["column"], group["status_code"]) == (1, 1840, 200)


def test_show_one_group(url: list[str]) -> None:
    _invoke("csp", "ingest", "shop", BATCH, *url)
    _, out = _invoke("csp", "violations", "shop", "--order", "count", "--json", *url)
    beacon, *rest = json.loads(out)["violations"]
    (inline,) = [g for g in rest if g["blocked"] == "inline"]
    code, out = _invoke("csp", "show", "shop", inline["id"], *url)
    assert "source:      https://shop.example.com/:14:9" in out
    assert "sample:      window.dataLayer=window.dataLayer||[];fu" in out
    code, out = _invoke("csp", "show", "shop", beacon["id"], *url)
    assert code == 0, out
    assert f"CSP violation {beacon['id']} (shop): reported 2 times" in out
    assert "directive:   connect-src (enforce)" in out
    assert "blocked:     https://collect.skim.test/beacon [url] (host collect.skim.test)" in out
    assert "source:      https://cdn.vendor.test/analytics/v2/tag.js:1:4120" in out
    assert "policy:      default-src 'self'; connect-src 'self' https://pay.vendor.test" in out
    code, out = _invoke("csp", "show", "shop", beacon["id"], "--json", *url)
    assert json.loads(out)["original_policy"].startswith("default-src")


def test_show_a_group_with_nothing_optional(url: list[str], tmp_path: Path) -> None:
    payload = tmp_path / "bare.json"
    payload.write_text(
        json.dumps(
            {
                "csp-report": {
                    "document-uri": "https://shop.example.com/",
                    "violated-directive": "img-src",
                    "blocked-uri": "data",
                }
            }
        )
    )
    _invoke("csp", "ingest", "shop", str(payload), *url)
    _, out = _invoke("csp", "violations", "shop", "--json", *url)
    (group,) = json.loads(out)["violations"]
    code, out = _invoke("csp", "show", "shop", group["id"], *url)
    assert code == 0, out
    assert "blocked:     data: [scheme]\n" in out
    assert "source:" not in out
    assert "sample:" not in out
    assert "policy:" not in out


def test_show_errors(url: list[str]) -> None:
    code, out = _invoke("csp", "show", "shop", "nope", *url)
    assert code == 2
    assert "is not a violation id" in out
    code, out = _invoke("csp", "show", "shop", "00000000-0000-0000-0000-000000000000", *url)
    assert code == 1
    assert "not found" in out
