"""Fetching pages for a scan: timeouts, size caps, redirects and ``robots.txt``.

Rules the fetcher enforces:

* **Only allowlisted origins.** Redirects are followed by hand, and every hop has to stay
  on one of the site's allowed origins. A page that redirects elsewhere is reported as
  ``redirect_blocked`` instead of being followed.
* **Bounded work.** Each request has connect/read timeouts plus an overall deadline, at
  most ``max_redirects`` hops, and the body is streamed and abandoned past
  ``max_page_bytes``. A page that is too large is reported, never parsed half-way,
  because a truncated page would hide the scripts after the cut.
* **robots.txt per RFC 9309.** Fetched once per origin per scan. 2xx is parsed, 4xx means
  there are no rules, and 5xx or an unreachable server means everything is disallowed.

External scripts are fetched with :meth:`PageFetcher.fetch_script`, only because an
allowlisted page references them. A browser follows a script's redirects to any http(s)
URL, so the fetcher does too (up to ``max_redirects``), but it never treats the body as a
page. robots.txt doesn't apply: loading a subresource a page asks for isn't crawling. Bodies
are capped at ``max_script_bytes``, measured after content decoding, which is also what
Subresource Integrity hashes.
"""

from __future__ import annotations

import asyncio
import codecs
import hashlib
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx

from script_sentinel.db.models import ScriptFetchOutcome
from script_sentinel.db.models import SnapshotOutcome as Outcome
from script_sentinel.headers import capture_security_headers
from script_sentinel.origins import is_allowed, origin_of
from script_sentinel.robots import MAX_ROBOTS_BYTES, RobotsPolicy

HTML_CONTENT_TYPES = frozenset({"text/html", "application/xhtml+xml"})
_REDIRECTS = frozenset({301, 302, 303, 307, 308})
_META_CHARSET = re.compile(rb"""<meta[^>]+charset\s*=\s*["']?\s*([A-Za-z0-9_:.-]+)""", re.I)


@dataclass(frozen=True, slots=True)
class FetchLimits:
    timeout_seconds: float = 10.0
    max_page_bytes: int = 2 * 1024 * 1024
    max_redirects: int = 5
    user_agent: str = "script-sentinel"
    max_script_bytes: int = 5 * 1024 * 1024

    @property
    def product_token(self) -> str:
        """The robots.txt product token: the user agent up to the first ``/`` or space."""
        return re.split(r"[/\s]", self.user_agent.strip(), maxsplit=1)[0] or "script-sentinel"


@dataclass(slots=True)
class FetchResult:
    requested_url: str
    outcome: Outcome
    final_url: str | None = None
    status_code: int | None = None
    content_type: str | None = None
    text: str | None = None
    size_bytes: int | None = None
    body_sha384: str | None = None
    elapsed_ms: int = 0
    error: str | None = None
    redirects: list[str] = field(default_factory=list)
    security_headers: dict[str, list[str]] = field(default_factory=dict)


@dataclass(slots=True)
class ScriptFetchResult:
    url: str
    outcome: ScriptFetchOutcome
    final_url: str | None = None
    status_code: int | None = None
    content_type: str | None = None
    body: bytes | None = None
    elapsed_ms: int = 0
    error: str | None = None
    redirects: list[str] = field(default_factory=list)


class _TooLargeError(Exception):
    pass


def _media_type(content_type: str | None) -> str | None:
    if not content_type:
        return None
    return content_type.split(";", 1)[0].strip().lower() or None


def _charset(content_type: str | None) -> str | None:
    for part in (content_type or "").split(";")[1:]:
        key, _, value = part.partition("=")
        if key.strip().lower() == "charset":
            return value.strip().strip("\"'") or None
    return None


def decode_html(body: bytes, content_type: str | None) -> str:
    """Decode a page the way browsers prioritize: BOM, then header, then ``<meta>``."""
    for bom, encoding in (
        (codecs.BOM_UTF8, "utf-8"),
        (codecs.BOM_UTF16_LE, "utf-16-le"),
        (codecs.BOM_UTF16_BE, "utf-16-be"),
    ):
        if body.startswith(bom):
            return body[len(bom) :].decode(encoding, errors="replace")
    candidates = [_charset(content_type)]
    match = _META_CHARSET.search(body[:1024])
    if match:
        candidates.append(match.group(1).decode("ascii"))
    for candidate in candidates:
        if not candidate:
            continue
        try:
            return body.decode(candidate, errors="replace")
        except LookupError:
            continue
    return body.decode("utf-8", errors="replace")


async def _read_capped(response: httpx.Response, limit: int) -> bytes:
    declared = response.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise _TooLargeError
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if total > limit:
            raise _TooLargeError
        chunks.append(chunk)
    return b"".join(chunks)


class PageFetcher:
    """Fetches pages and robots.txt files for one scan.

    The robots.txt cache lives as long as the fetcher, so create one per scan. Pass a
    ``transport`` to run against an in-process app or a mock in tests.
    """

    def __init__(
        self,
        limits: FetchLimits | None = None,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.limits = limits or FetchLimits()
        self._clock = clock
        self._client = httpx.AsyncClient(
            transport=transport,
            follow_redirects=False,
            timeout=httpx.Timeout(self.limits.timeout_seconds),
            headers={
                "user-agent": self.limits.user_agent,
                "accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
            },
            trust_env=False,
        )
        self._robots: dict[str, RobotsPolicy] = {}
        self._robots_locks: dict[str, asyncio.Lock] = {}

    async def __aenter__(self) -> PageFetcher:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    # robots.txt

    async def robots_policy(self, url: str, allowed_origins: list[str]) -> RobotsPolicy:
        """The robots.txt policy of ``url``'s origin, fetched once per fetcher."""
        origin = str(origin_of(url))
        lock = self._robots_locks.setdefault(origin, asyncio.Lock())
        async with lock:
            policy = self._robots.get(origin)
            if policy is None:
                policy = await self._fetch_robots(origin, allowed_origins)
                self._robots[origin] = policy
        return policy

    async def _fetch_robots(self, origin: str, allowed_origins: list[str]) -> RobotsPolicy:
        url = origin + "/robots.txt"
        try:
            async with asyncio.timeout(self.limits.timeout_seconds):
                for _ in range(self.limits.max_redirects + 1):
                    async with self._client.stream("GET", url) as response:
                        status = response.status_code
                        if status in _REDIRECTS and "location" in response.headers:
                            url = urljoin(url, response.headers["location"])
                            if not is_allowed(url, allowed_origins):
                                return RobotsPolicy.allow_everything("redirected off allowlist")
                            continue
                        if 200 <= status < 300:
                            body = await _read_capped_robots(response)
                            return RobotsPolicy.parse(body, self.limits.product_token)
                        if 400 <= status < 500:
                            return RobotsPolicy.allow_everything(f"unavailable ({status})")
                        return RobotsPolicy.disallow_everything(f"unreachable ({status})")
                return RobotsPolicy.allow_everything("too many redirects")
        except (TimeoutError, httpx.HTTPError, httpx.InvalidURL) as exc:
            return RobotsPolicy.disallow_everything(f"unreachable ({type(exc).__name__})")

    # Pages

    async def fetch_page(
        self, url: str, allowed_origins: list[str], *, respect_robots: bool = True
    ) -> FetchResult:
        started = self._clock()
        result = await self._fetch_page(url, allowed_origins, respect_robots)
        result.elapsed_ms = max(0, round((self._clock() - started) * 1000))
        return result

    async def _fetch_page(
        self, url: str, allowed_origins: list[str], respect_robots: bool
    ) -> FetchResult:
        result = FetchResult(requested_url=url, outcome=Outcome.FETCH_ERROR)
        current = url
        try:
            async with asyncio.timeout(self.limits.timeout_seconds):
                for _ in range(self.limits.max_redirects + 1):
                    if not is_allowed(current, allowed_origins):
                        result.outcome = Outcome.REDIRECT_BLOCKED
                        result.error = f"redirected to {current}, which is not an allowed origin"
                        return result
                    if respect_robots:
                        policy = await self.robots_policy(current, allowed_origins)
                        if not policy.can_fetch(current):
                            result.outcome = Outcome.ROBOTS_DISALLOWED
                            result.final_url = current
                            result.error = f"disallowed by robots.txt ({policy.source})"
                            return result
                    async with self._client.stream("GET", current) as response:
                        result.status_code = response.status_code
                        result.final_url = current
                        location = response.headers.get("location")
                        if response.status_code in _REDIRECTS and location:
                            current = urljoin(current, location)
                            result.redirects.append(current)
                            continue
                        return await self._finish(result, response)
                result.error = f"more than {self.limits.max_redirects} redirects"
                return result
        except TimeoutError:
            result.error = f"timed out after {self.limits.timeout_seconds:g}s"
        except httpx.TimeoutException as exc:
            result.error = f"timed out ({type(exc).__name__})"
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            # InvalidURL: httpx parses a redirect's Location eagerly and rejects some.
            result.error = f"{type(exc).__name__}: {exc}"[:500]
        return result

    async def _finish(self, result: FetchResult, response: httpx.Response) -> FetchResult:
        content_type = response.headers.get("content-type")
        result.content_type = content_type
        result.security_headers = capture_security_headers(response.headers)
        if response.status_code >= 400 or response.status_code < 200:
            result.outcome = Outcome.HTTP_ERROR
            result.error = f"HTTP {response.status_code}"
            return result
        media_type = _media_type(content_type)
        if media_type is not None and media_type not in HTML_CONTENT_TYPES:
            result.outcome = Outcome.NOT_HTML
            result.error = f"expected HTML, got {media_type}"
            return result
        try:
            body = await _read_capped(response, self.limits.max_page_bytes)
        except _TooLargeError:
            result.outcome = Outcome.TOO_LARGE
            result.error = (
                f"page is larger than {self.limits.max_page_bytes} bytes "
                "(raise SENTINEL_MAX_PAGE_BYTES to scan it)"
            )
            return result
        result.outcome = Outcome.OK
        result.size_bytes = len(body)
        result.body_sha384 = hashlib.sha384(body).hexdigest()
        result.text = decode_html(body, content_type)
        return result

    # Scripts

    async def fetch_script(self, url: str) -> ScriptFetchResult:
        """Download one external script. Never raises; failures are in the result."""
        started = self._clock()
        result = await self._fetch_script(url)
        result.elapsed_ms = max(0, round((self._clock() - started) * 1000))
        return result

    async def _fetch_script(self, url: str) -> ScriptFetchResult:
        result = ScriptFetchResult(url=url, outcome=ScriptFetchOutcome.FETCH_ERROR)
        current = url
        headers = {"accept": "*/*"}
        try:
            async with asyncio.timeout(self.limits.timeout_seconds):
                for _ in range(self.limits.max_redirects + 1):
                    if urlsplit(current).scheme not in ("http", "https"):
                        result.outcome = ScriptFetchOutcome.BAD_REDIRECT
                        result.error = f"redirected to a non-http(s) URL: {current[:200]}"
                        return result
                    async with self._client.stream("GET", current, headers=headers) as response:
                        result.status_code = response.status_code
                        result.final_url = current
                        location = response.headers.get("location")
                        if response.status_code in _REDIRECTS and location:
                            current = urljoin(current, location)
                            result.redirects.append(current)
                            continue
                        return await self._finish_script(result, response)
                result.error = f"more than {self.limits.max_redirects} redirects"
                return result
        except TimeoutError:
            result.error = f"timed out after {self.limits.timeout_seconds:g}s"
        except httpx.TimeoutException as exc:
            result.error = f"timed out ({type(exc).__name__})"
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            # InvalidURL: httpx parses a redirect's Location eagerly and rejects some.
            result.error = f"{type(exc).__name__}: {exc}"[:500]
        return result

    async def _finish_script(
        self, result: ScriptFetchResult, response: httpx.Response
    ) -> ScriptFetchResult:
        result.content_type = response.headers.get("content-type")
        if not 200 <= response.status_code < 300:
            result.outcome = ScriptFetchOutcome.HTTP_ERROR
            result.error = f"HTTP {response.status_code}"
            return result
        try:
            body = await _read_capped(response, self.limits.max_script_bytes)
        except _TooLargeError:
            result.outcome = ScriptFetchOutcome.TOO_LARGE
            result.error = (
                f"script is larger than {self.limits.max_script_bytes} bytes "
                "(raise SENTINEL_MAX_SCRIPT_BYTES to hash it)"
            )
            return result
        result.outcome = ScriptFetchOutcome.OK
        result.body = body
        return result


async def _read_capped_robots(response: httpx.Response) -> bytes:
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_bytes():
        chunks.append(chunk)
        total += len(chunk)
        if total >= MAX_ROBOTS_BYTES:
            break  # the rest is ignored, not an error (RFC 9309 section 2.5)
    return b"".join(chunks)[:MAX_ROBOTS_BYTES]
