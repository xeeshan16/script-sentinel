from __future__ import annotations

import pytest

from script_sentinel.origins import (
    MAX_URL_LENGTH,
    InvalidUrlError,
    Origin,
    is_allowed,
    normalize_origins,
    normalize_page_url,
    origin_of,
    parse_origin,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://shop.example.com", "https://shop.example.com"),
        ("https://shop.example.com/", "https://shop.example.com"),
        ("HTTPS://Shop.Example.COM", "https://shop.example.com"),
        ("https://shop.example.com:443", "https://shop.example.com"),
        ("http://shop.example.com:80", "http://shop.example.com"),
        ("https://shop.example.com:8443", "https://shop.example.com:8443"),
        ("http://localhost:8000", "http://localhost:8000"),
        ("https://shop.example.com.", "https://shop.example.com"),
        ("http://127.0.0.1:9000", "http://127.0.0.1:9000"),
        ("http://[::1]:9000", "http://[::1]:9000"),
        ("http://[0:0:0:0:0:0:0:1]", "http://[::1]"),
        ("https://bücher.example", "https://xn--bcher-kva.example"),
        ("  https://shop.example.com  ", "https://shop.example.com"),
    ],
)
def test_parse_origin_normalizes(raw: str, expected: str) -> None:
    assert str(parse_origin(raw)) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "shop.example.com",
        "ftp://shop.example.com",
        "javascript:alert(1)",
        "data:text/html,hi",
        "https://",
        "https://.",
        "https://shop.example.com/checkout",
        "https://shop.example.com/?a=1",
        "https://shop.example.com/#top",
        "https://user:pass@shop.example.com",
        "https://user@shop.example.com",
        "https://shop.example.com:99999",
        "https://shop.example.com:abc",
        "https://shop example.com",
        "https://shop.exa\nmple.com",
        "https://" + "a" * 64 + ".example",
        "https://a..example",
    ],
)
def test_parse_origin_rejects(raw: str) -> None:
    with pytest.raises(InvalidUrlError):
        parse_origin(raw)


def test_parse_origin_rejects_non_strings() -> None:
    with pytest.raises(InvalidUrlError):
        parse_origin(None)  # type: ignore[arg-type]


def test_rejects_overlong_urls() -> None:
    with pytest.raises(InvalidUrlError, match="longer than"):
        origin_of("https://shop.example.com/" + "a" * MAX_URL_LENGTH)


def test_credentials_are_not_echoed_back() -> None:
    with pytest.raises(InvalidUrlError) as info:
        origin_of("https://admin:hunter2@shop.example.com/")
    assert "hunter2" not in str(info.value)


def test_origin_str_and_ordering() -> None:
    assert str(Origin("https", "a.example")) == "https://a.example"
    assert str(Origin("http", "::1", 8080)) == "http://[::1]:8080"
    assert sorted([Origin("https", "b.example"), Origin("http", "z.example")])[0].scheme == "http"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://Shop.Example.com", "https://shop.example.com/"),
        (
            "https://shop.example.com:443/Checkout?step=2#pay",
            "https://shop.example.com/Checkout?step=2",
        ),
        ("http://localhost:8000/cart", "http://localhost:8000/cart"),
        ("https://shop.example.com/a%20b", "https://shop.example.com/a%20b"),
    ],
)
def test_normalize_page_url(raw: str, expected: str) -> None:
    assert normalize_page_url(raw) == expected


def test_normalize_origins_dedupes_and_sorts() -> None:
    assert normalize_origins(
        ["https://b.example", "https://B.example/", "http://a.example:80"]
    ) == ["http://a.example", "https://b.example"]


def test_normalize_origins_needs_one() -> None:
    with pytest.raises(InvalidUrlError, match="at least one"):
        normalize_origins([])


@pytest.mark.parametrize(
    ("url", "allowed"),
    [
        ("https://shop.example.com/checkout", True),
        ("https://SHOP.example.com:443/", True),
        ("http://shop.example.com/checkout", False),  # scheme differs
        ("https://shop.example.com:8443/", False),  # port differs
        ("https://www.shop.example.com/", False),  # subdomain is another origin
        ("https://shop.example.com.evil.test/", False),
        ("https://evil.test/?u=https://shop.example.com", False),
        ("https://user:pw@shop.example.com/", False),
        ("not a url", False),
    ],
)
def test_is_allowed(url: str, allowed: bool) -> None:
    assert is_allowed(url, ["https://shop.example.com", "not-an-origin"]) is allowed
