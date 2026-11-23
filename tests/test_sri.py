from __future__ import annotations

import base64
import hashlib

import httpx
import pytest

from script_sentinel.db.models import SriStatus
from script_sentinel.headers import capture_security_headers, describe
from script_sentinel.sri import (
    IntegrityHash,
    body_digests,
    check_integrity,
    integrity_value,
    parse_integrity,
    strongest,
)

BODY = b"alert('hello');\n"


def b64(algorithm: str, body: bytes = BODY) -> str:
    return base64.b64encode(hashlib.new(algorithm, body).digest()).decode()


def test_integrity_value() -> None:
    assert integrity_value(BODY) == f"sha384-{b64('sha384')}"
    assert integrity_value(BODY, "sha256") == f"sha256-{b64('sha256')}"
    with pytest.raises(ValueError, match="unsupported"):
        integrity_value(BODY, "md5")
    assert body_digests(BODY) == {a: b64(a) for a in ("sha256", "sha384", "sha512")}


def test_parse_integrity_skips_what_browsers_skip() -> None:
    value = f"  md5-abc SHA256-{b64('sha256')}?opt=1 \t garbage sha512-{b64('sha512')} sha384-  "
    assert parse_integrity(value) == [
        IntegrityHash("sha256", b64("sha256")),
        IntegrityHash("sha512", b64("sha512")),
    ]
    assert parse_integrity("") == []


def test_only_the_strongest_algorithm_counts() -> None:
    hashes = parse_integrity(f"sha256-{b64('sha256')} sha384-AAAA sha384-BBBB")
    assert [h.digest for h in strongest(hashes)] == ["AAAA", "BBBB"]
    assert strongest([]) == []


@pytest.mark.parametrize(
    ("value", "status"),
    [
        (f"sha384-{b64('sha384')}", SriStatus.MATCH),
        (f"sha384-wrong sha384-{b64('sha384')}", SriStatus.MATCH),  # any strongest one
        (f"sha256-{b64('sha256')} sha512-{b64('sha512')}", SriStatus.MATCH),
        # The good sha256 doesn't help: sha384 is stronger, and it doesn't match.
        (f"sha256-{b64('sha256')} sha384-{b64('sha384', b'other')}", SriStatus.MISMATCH),
        (f"sha384-{b64('sha384', b'other')}", SriStatus.MISMATCH),
        ("md5-abc", SriStatus.NO_SUPPORTED_HASH),
        ("not an integrity value", SriStatus.NO_SUPPORTED_HASH),
    ],
)
def test_check_integrity(value: str, status: SriStatus) -> None:
    assert check_integrity(value, BODY) is status


def test_digests_are_compared_exactly() -> None:
    # A body whose digest uses the characters base64 and base64url disagree on.
    body = next(b for i in range(100) if set(b64("sha384", b := str(i).encode())) & {"+", "/"})
    url_safe = b64("sha384", body).replace("+", "-").replace("/", "_")
    assert check_integrity(f"sha384-{url_safe}", body) is SriStatus.MISMATCH
    assert check_integrity(f"sha384-{b64('sha384', body)}", body) is SriStatus.MATCH


def test_capture_security_headers() -> None:
    headers = httpx.Headers(
        [
            ("Content-Security-Policy", "default-src 'self'"),
            ("content-security-policy", " script-src 'none' "),
            ("Strict-Transport-Security", "max-age=63072000"),
            ("X-Content-Type-Options", "nosniff"),
            ("Server", "nginx"),
            *[("Report-To", f'{{"group": "g{i}"}}') for i in range(12)],
            ("Permissions-Policy", "x" * 10_000),
        ]
    )
    captured = capture_security_headers(headers)
    assert captured["content-security-policy"] == ["default-src 'self'", "script-src 'none'"]
    assert captured["strict-transport-security"] == ["max-age=63072000"]
    assert "server" not in captured
    assert len(captured["report-to"]) == 8
    assert len(captured["permissions-policy"][0]) == 8192
    assert capture_security_headers(httpx.Headers()) == {}


def test_describe() -> None:
    assert describe({}, []) == "no security headers"
    everything = {
        "content-security-policy": ["a"],
        "content-security-policy-report-only": ["b"],
        "integrity-policy": ["blocked-destinations=(script)"],
        "integrity-policy-report-only": ["blocked-destinations=(script)"],
        "strict-transport-security": ["max-age=1"],
        "x-content-type-options": ["NoSniff"],
        "x-frame-options": ["DENY"],
        "referrer-policy": ["no-referrer"],
        "permissions-policy": ["camera=()"],
    }
    assert describe(everything, ["script-src 'self'"]) == (
        "CSP, CSP (meta), CSP report-only, Integrity-Policy, Integrity-Policy report-only, "
        "HSTS, nosniff, X-Frame-Options, Referrer-Policy, Permissions-Policy"
    )
    assert describe({"x-content-type-options": ["sniff"]}, []) == "no security headers"
