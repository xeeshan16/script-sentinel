from __future__ import annotations

import asyncio
import codecs
import hashlib
from collections.abc import AsyncIterator, Callable, Coroutine

import httpx
import pytest

from script_sentinel.db.models import ScriptFetchOutcome, SnapshotOutcome
from script_sentinel.fetch import FetchLimits, PageFetcher, decode_html
from script_sentinel.robots import MAX_ROBOTS_BYTES
from tests.conftest import FixtureSite

SHOP = "https://shop.test"
ALLOWED = [SHOP]
Handler = Callable[[httpx.Request], Coroutine[None, None, httpx.Response]]


def mock_fetcher(handler: Handler, **limits: object) -> PageFetcher:
    return PageFetcher(
        FetchLimits(**limits),  # type: ignore[arg-type]
        transport=httpx.MockTransport(handler),
    )


def html(body: str = "<script src='/a.js'></script>", status: int = 200) -> httpx.Response:
    return httpx.Response(status, headers={"content-type": "text/html"}, text=body)


def routes(table: dict[str, httpx.Response | Exception]) -> Handler:
    async def handler(request: httpx.Request) -> httpx.Response:
        key = str(request.url)
        item = table.get(key, httpx.Response(404))
        if isinstance(item, Exception):
            raise item
        return item

    return handler


# Decoding and limits


def test_decode_html_priorities() -> None:
    assert decode_html(codecs.BOM_UTF8 + "é".encode(), "text/html; charset=latin-1") == "é"
    assert decode_html(codecs.BOM_UTF16_LE + "é".encode("utf-16-le"), None) == "é"
    assert decode_html(codecs.BOM_UTF16_BE + "é".encode("utf-16-be"), None) == "é"
    assert decode_html("é".encode("latin-1"), 'text/html; charset="ISO-8859-1"') == "é"
    meta = b'<meta charset="windows-1252"><p>\x80</p>'
    assert decode_html(meta, "text/html") == '<meta charset="windows-1252"><p>€</p>'
    assert decode_html("é".encode(), "text/html; charset=bogus") == "é"
    assert decode_html(b"\xff", "text/html; foo=bar") == "�"


def test_product_token() -> None:
    assert FetchLimits(user_agent="script-sentinel/0.1 (+https://x)").product_token == (
        "script-sentinel"
    )
    assert FetchLimits(user_agent="MyBot extra").product_token == "MyBot"
    assert FetchLimits(user_agent="   ").product_token == "script-sentinel"


# Against a real local HTTP server


async def test_fetches_a_page_from_the_fixture_site(fixture_site: FixtureSite) -> None:
    fixture_site.page("/checkout", "<script src='/js/app.js'></script>")
    async with PageFetcher(FetchLimits(user_agent="script-sentinel/9 (test)")) as fetcher:
        result = await fetcher.fetch_page(fixture_site.url("/checkout"), [fixture_site.origin])
    assert result.outcome is SnapshotOutcome.OK
    assert result.status_code == 200
    assert result.final_url == fixture_site.url("/checkout")
    assert result.text == "<script src='/js/app.js'></script>"
    assert result.size_bytes == len(result.text)
    assert result.body_sha384 == hashlib.sha384(result.text.encode()).hexdigest()
    assert result.content_type == "text/html; charset=utf-8"
    # robots.txt is asked first (a 404 here, so no rules), with our user agent.
    assert fixture_site.requests == [
        ("/robots.txt", "script-sentinel/9 (test)"),
        ("/checkout", "script-sentinel/9 (test)"),
    ]


async def test_robots_txt_is_read_once_per_origin_and_obeyed(fixture_site: FixtureSite) -> None:
    fixture_site.set(
        "/robots.txt", "User-agent: *\nDisallow: /checkout\n", content_type="text/plain"
    )
    fixture_site.page("/", "<p>home</p>")
    fixture_site.page("/checkout", "<p>pay</p>")
    origins = [fixture_site.origin]
    async with PageFetcher() as fetcher:
        home, checkout = await asyncio.gather(
            fetcher.fetch_page(fixture_site.url("/"), origins),
            fetcher.fetch_page(fixture_site.url("/checkout"), origins),
        )
        ignored = await fetcher.fetch_page(
            fixture_site.url("/checkout"), origins, respect_robots=False
        )
    assert home.outcome is SnapshotOutcome.OK
    assert checkout.outcome is SnapshotOutcome.ROBOTS_DISALLOWED
    assert checkout.error == "disallowed by robots.txt (parsed)"
    assert not checkout.outcome.failed
    assert ignored.outcome is SnapshotOutcome.OK
    assert fixture_site.paths().count("/robots.txt") == 1
    assert fixture_site.paths().count("/checkout") == 1


async def test_redirects_are_followed_only_within_the_allowlist(
    fixture_site: FixtureSite,
) -> None:
    fixture_site.set("/old", "", 301, location="/new")
    fixture_site.page("/new", "<script>x()</script>")
    fixture_site.set("/away", "", 302, location="https://evil.test/phish")
    origins = [fixture_site.origin]
    async with PageFetcher() as fetcher:
        moved = await fetcher.fetch_page(fixture_site.url("/old"), origins)
        away = await fetcher.fetch_page(fixture_site.url("/away"), origins)
    assert moved.outcome is SnapshotOutcome.OK
    assert moved.final_url == fixture_site.url("/new")
    assert moved.redirects == [fixture_site.url("/new")]
    assert away.outcome is SnapshotOutcome.REDIRECT_BLOCKED
    assert away.error == "redirected to https://evil.test/phish, which is not an allowed origin"
    assert away.outcome.failed
    assert "/phish" not in fixture_site.paths()


# Edge cases through a mock transport


async def test_redirect_targets_are_checked_against_robots_txt() -> None:
    handler = routes(
        {
            f"{SHOP}/robots.txt": httpx.Response(200, text="User-agent: *\nDisallow: /private"),
            f"{SHOP}/go": httpx.Response(307, headers={"location": "/private/page"}),
        }
    )
    async with mock_fetcher(handler) as fetcher:
        result = await fetcher.fetch_page(f"{SHOP}/go", ALLOWED)
    assert result.outcome is SnapshotOutcome.ROBOTS_DISALLOWED
    assert result.final_url == f"{SHOP}/private/page"


async def test_too_many_redirects() -> None:
    async def loop(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(404)
        return httpx.Response(302, headers={"location": f"/r{len(request.url.path)}"})

    async with mock_fetcher(loop, max_redirects=2) as fetcher:
        result = await fetcher.fetch_page(f"{SHOP}/start", ALLOWED)
    assert result.outcome is SnapshotOutcome.FETCH_ERROR
    assert result.error == "more than 2 redirects"
    assert len(result.redirects) == 3


@pytest.mark.parametrize("status", [404, 500, 101])
async def test_http_errors(status: int) -> None:
    handler = routes({f"{SHOP}/": html("gone", status)})
    async with mock_fetcher(handler) as fetcher:
        result = await fetcher.fetch_page(f"{SHOP}/", ALLOWED)
    assert result.outcome is SnapshotOutcome.HTTP_ERROR
    assert result.status_code == status
    assert result.error == f"HTTP {status}"


async def test_a_redirect_without_location_is_an_http_answer() -> None:
    handler = routes({f"{SHOP}/": httpx.Response(302)})
    async with mock_fetcher(handler) as fetcher:
        result = await fetcher.fetch_page(f"{SHOP}/", ALLOWED)
    assert result.outcome is SnapshotOutcome.OK  # 3xx without Location: nothing to follow
    assert result.text == ""


async def test_non_html_is_reported_and_missing_content_type_is_parsed() -> None:
    handler = routes(
        {
            f"{SHOP}/data.json": httpx.Response(
                200, headers={"content-type": "application/json"}, text="{}"
            ),
            f"{SHOP}/bare": httpx.Response(200, content=b"<script>x</script>"),
            f"{SHOP}/xhtml": httpx.Response(
                200, headers={"content-type": "application/xhtml+xml"}, text="<p/>"
            ),
        }
    )
    async with mock_fetcher(handler) as fetcher:
        data = await fetcher.fetch_page(f"{SHOP}/data.json", ALLOWED)
        bare = await fetcher.fetch_page(f"{SHOP}/bare", ALLOWED)
        xhtml = await fetcher.fetch_page(f"{SHOP}/xhtml", ALLOWED)
    assert data.outcome is SnapshotOutcome.NOT_HTML
    assert data.error == "expected HTML, got application/json"
    assert bare.outcome is SnapshotOutcome.OK
    assert bare.content_type is None
    assert xhtml.outcome is SnapshotOutcome.OK


async def test_pages_over_the_size_cap_are_not_parsed() -> None:
    async def chunks() -> AsyncIterator[bytes]:
        for _ in range(10):
            yield b"x" * 512

    handler = routes(
        {
            f"{SHOP}/declared": html("y" * 5000),
            f"{SHOP}/streamed": httpx.Response(
                200, headers={"content-type": "text/html"}, content=chunks()
            ),
            f"{SHOP}/fits": html("z" * 1024),
        }
    )
    async with mock_fetcher(handler, max_page_bytes=1024) as fetcher:
        declared = await fetcher.fetch_page(f"{SHOP}/declared", ALLOWED)
        streamed = await fetcher.fetch_page(f"{SHOP}/streamed", ALLOWED)
        fits = await fetcher.fetch_page(f"{SHOP}/fits", ALLOWED)
    for result in (declared, streamed):
        assert result.outcome is SnapshotOutcome.TOO_LARGE
        assert result.text is None
        assert result.error is not None
        assert "SENTINEL_MAX_PAGE_BYTES" in result.error
    assert fits.outcome is SnapshotOutcome.OK
    assert fits.size_bytes == 1024


async def test_transport_errors_and_timeouts() -> None:
    handler = routes(
        {
            f"{SHOP}/robots.txt": httpx.Response(404),
            f"{SHOP}/slow": httpx.ReadTimeout("read timed out"),
            f"{SHOP}/down": httpx.ConnectError("connection refused"),
        }
    )
    async with mock_fetcher(handler) as fetcher:
        slow = await fetcher.fetch_page(f"{SHOP}/slow", ALLOWED)
        down = await fetcher.fetch_page(f"{SHOP}/down", ALLOWED)
    assert slow.outcome is SnapshotOutcome.FETCH_ERROR
    assert slow.error == "timed out (ReadTimeout)"
    assert down.error == "ConnectError: connection refused"


async def test_overall_deadline() -> None:
    async def stall(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(404)
        await asyncio.sleep(5)
        return html()  # pragma: no cover - cancelled by the deadline

    async with mock_fetcher(stall, timeout_seconds=0.05) as fetcher:
        result = await fetcher.fetch_page(f"{SHOP}/", ALLOWED)
    assert result.outcome is SnapshotOutcome.FETCH_ERROR
    assert result.error == "timed out after 0.05s"


async def test_elapsed_time_uses_the_injected_clock() -> None:
    ticks = iter([10.0, 10.25])
    fetcher = PageFetcher(
        transport=httpx.MockTransport(routes({f"{SHOP}/": html()})), clock=lambda: next(ticks)
    )
    async with fetcher:
        result = await fetcher.fetch_page(f"{SHOP}/", ALLOWED)
    assert result.elapsed_ms == 250


# robots.txt HTTP semantics (RFC 9309 section 2.3.1)


@pytest.mark.parametrize(
    ("robots", "allowed", "source"),
    [
        (httpx.Response(404), True, "unavailable (404)"),
        (httpx.Response(403), True, "unavailable (403)"),
        (httpx.Response(503), False, "unreachable (503)"),
        (httpx.ConnectError("refused"), False, "unreachable (ConnectError)"),
        (httpx.Response(200, text="User-agent: *\nDisallow: /"), False, "parsed"),
    ],
)
async def test_robots_status_semantics(
    robots: httpx.Response | Exception, allowed: bool, source: str
) -> None:
    handler = routes({f"{SHOP}/robots.txt": robots, f"{SHOP}/": html()})
    async with mock_fetcher(handler) as fetcher:
        policy = await fetcher.robots_policy(f"{SHOP}/", ALLOWED)
        result = await fetcher.fetch_page(f"{SHOP}/", ALLOWED)
    assert policy.source == source
    assert policy.can_fetch(f"{SHOP}/") is allowed
    assert (result.outcome is SnapshotOutcome.OK) is allowed


async def test_robots_redirects() -> None:
    other = "https://www.shop.test"
    handler = routes(
        {
            f"{SHOP}/robots.txt": httpx.Response(301, headers={"location": f"{other}/robots.txt"}),
            f"{other}/robots.txt": httpx.Response(200, text="User-agent: *\nDisallow: /x"),
        }
    )
    async with mock_fetcher(handler) as fetcher:
        followed = await fetcher.robots_policy(f"{SHOP}/", [SHOP, other])
    async with mock_fetcher(handler) as fetcher:
        off_list = await fetcher.robots_policy(f"{SHOP}/", [SHOP])
    assert not followed.can_fetch("/x")
    assert off_list.source == "redirected off allowlist"
    assert off_list.can_fetch("/x")


async def test_robots_redirect_loop_means_no_rules() -> None:
    handler = routes(
        {f"{SHOP}/robots.txt": httpx.Response(302, headers={"location": "/robots.txt"})}
    )
    async with mock_fetcher(handler, max_redirects=1) as fetcher:
        policy = await fetcher.robots_policy(f"{SHOP}/", ALLOWED)
    assert policy.source == "too many redirects"
    assert policy.can_fetch("/")


async def test_robots_body_is_capped() -> None:
    async def big() -> AsyncIterator[bytes]:
        yield b"User-agent: *\n"
        for _ in range(MAX_ROBOTS_BYTES // 1024 + 2):
            yield b"#" * 1023 + b"\n"
        yield b"Disallow: /late\n"  # pragma: no cover - never read

    handler = routes({f"{SHOP}/robots.txt": httpx.Response(200, content=big())})
    async with mock_fetcher(handler) as fetcher:
        policy = await fetcher.robots_policy(f"{SHOP}/", ALLOWED)
    assert policy.can_fetch("/late")


async def test_a_redirect_httpx_cannot_parse_is_a_failed_page_not_a_crash() -> None:
    handler = routes(
        {
            f"{SHOP}/robots.txt": httpx.Response(302, headers={"location": "data:x,1"}),
            f"{SHOP}/": httpx.Response(302, headers={"location": "data:text/html,hi"}),
        }
    )
    async with mock_fetcher(handler) as fetcher:
        result = await fetcher.fetch_page(f"{SHOP}/", ALLOWED, respect_robots=False)
        robots = await fetcher.robots_policy(f"{SHOP}/", ALLOWED)
    assert result.outcome is SnapshotOutcome.FETCH_ERROR
    assert result.error is not None
    assert result.error.startswith("InvalidURL: ")
    assert not robots.can_fetch(f"{SHOP}/")
    assert robots.source == "unreachable (InvalidURL)"


# Security headers


async def test_page_security_headers_are_captured() -> None:
    page = httpx.Response(
        200,
        headers=[
            ("content-type", "text/html"),
            ("content-security-policy", "script-src 'self'"),
            ("content-security-policy", "object-src 'none'"),
            ("x-frame-options", "DENY"),
            ("set-cookie", "session=secret"),
        ],
        text="<p>hi</p>",
    )
    handler = routes({f"{SHOP}/robots.txt": httpx.Response(404), f"{SHOP}/": page})
    async with mock_fetcher(handler) as fetcher:
        result = await fetcher.fetch_page(f"{SHOP}/", ALLOWED)
    assert result.security_headers == {
        "content-security-policy": ["script-src 'self'", "object-src 'none'"],
        "x-frame-options": ["DENY"],
    }


# External scripts

CDN = "https://cdn.vendor.test"


def js(
    body: bytes = b"run();", status: int = 200, headers: dict[str, str] | None = None
) -> httpx.Response:
    return httpx.Response(
        status, headers={"content-type": "text/javascript", **(headers or {})}, content=body
    )


async def test_fetch_script_from_the_fixture_site(fixture_site: FixtureSite) -> None:
    fixture_site.set("/w.js", b"widget();", content_type="text/javascript")
    async with PageFetcher() as fetcher:
        result = await fetcher.fetch_script(fixture_site.url("/w.js"))
    assert result.outcome is ScriptFetchOutcome.OK
    assert (result.status_code, result.body, result.content_type) == (
        200,
        b"widget();",
        "text/javascript",
    )
    assert result.final_url == fixture_site.url("/w.js")
    # robots.txt is never consulted for a subresource.
    assert fixture_site.paths() == ["/w.js"]


async def test_fetch_script_follows_redirects_to_any_http_origin() -> None:
    handler = routes(
        {
            f"{CDN}/latest/w.js": httpx.Response(302, headers={"location": "/v2/w.js"}),
            f"{CDN}/v2/w.js": httpx.Response(
                301, headers={"location": "https://mirror.test/v2/w.js"}
            ),
            "https://mirror.test/v2/w.js": js(b"v2();"),
            f"{CDN}/ftp": httpx.Response(302, headers={"location": "ftp://cdn.vendor.test/w.js"}),
            f"{CDN}/bad": httpx.Response(302, headers={"location": "data:text/javascript,1"}),
            f"{CDN}/loop": httpx.Response(302, headers={"location": "/loop"}),
        }
    )
    async with mock_fetcher(handler, max_redirects=3) as fetcher:
        moved = await fetcher.fetch_script(f"{CDN}/latest/w.js")
        ftp = await fetcher.fetch_script(f"{CDN}/ftp")
        bad = await fetcher.fetch_script(f"{CDN}/bad")
        loop = await fetcher.fetch_script(f"{CDN}/loop")
    assert moved.outcome is ScriptFetchOutcome.OK
    assert moved.body == b"v2();"
    assert moved.final_url == "https://mirror.test/v2/w.js"
    assert moved.redirects == [f"{CDN}/v2/w.js", "https://mirror.test/v2/w.js"]
    assert ftp.outcome is ScriptFetchOutcome.BAD_REDIRECT
    assert ftp.error == "redirected to a non-http(s) URL: ftp://cdn.vendor.test/w.js"
    # httpx refuses some Location values outright; that is a failed fetch, not a crash.
    assert bad.outcome is ScriptFetchOutcome.FETCH_ERROR
    assert bad.error is not None
    assert bad.error.startswith("InvalidURL: ")
    assert loop.outcome is ScriptFetchOutcome.FETCH_ERROR
    assert loop.error == "more than 3 redirects"


async def test_fetch_script_failures() -> None:
    async def stall(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(5)
        return js()  # pragma: no cover - cancelled by the deadline

    handler = routes(
        {
            f"{CDN}/gone.js": js(b"", 404),
            f"{CDN}/odd.js": js(b"", 199),
            f"{CDN}/big.js": js(b"x" * 2048),
            f"{CDN}/declared.js": js(b"", headers={"content-length": "999999"}),
            f"{CDN}/slow.js": httpx.ReadTimeout("read timed out"),
            f"{CDN}/down.js": httpx.ConnectError("connection refused"),
        }
    )
    async with mock_fetcher(handler, max_script_bytes=1024) as fetcher:
        gone = await fetcher.fetch_script(f"{CDN}/gone.js")
        odd = await fetcher.fetch_script(f"{CDN}/odd.js")
        big = await fetcher.fetch_script(f"{CDN}/big.js")
        declared = await fetcher.fetch_script(f"{CDN}/declared.js")
        slow = await fetcher.fetch_script(f"{CDN}/slow.js")
        down = await fetcher.fetch_script(f"{CDN}/down.js")
    assert (gone.outcome, gone.error, gone.status_code) == (
        ScriptFetchOutcome.HTTP_ERROR,
        "HTTP 404",
        404,
    )
    assert odd.outcome is ScriptFetchOutcome.HTTP_ERROR
    assert big.outcome is declared.outcome is ScriptFetchOutcome.TOO_LARGE
    assert big.error is not None
    assert "SENTINEL_MAX_SCRIPT_BYTES" in big.error
    assert big.body is None
    assert slow.error == "timed out (ReadTimeout)"
    assert down.error == "ConnectError: connection refused"
    async with mock_fetcher(stall, timeout_seconds=0.05) as fetcher:
        stalled = await fetcher.fetch_script(f"{CDN}/w.js")
    assert stalled.outcome is ScriptFetchOutcome.FETCH_ERROR
    assert stalled.error == "timed out after 0.05s"


async def test_fetch_script_elapsed_time() -> None:
    ticks = iter([1.0, 1.5])
    fetcher = PageFetcher(
        transport=httpx.MockTransport(routes({f"{CDN}/w.js": js()})), clock=lambda: next(ticks)
    )
    async with fetcher:
        result = await fetcher.fetch_script(f"{CDN}/w.js")
    assert result.elapsed_ms == 500
