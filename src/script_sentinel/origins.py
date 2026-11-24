"""Origins and page URLs: parsing, normalization and the scan allowlist.

script-sentinel only fetches pages whose origin a site lists explicitly. Everything here is
pure so the rules can be tested without a network or a database.

An origin is ``scheme://host[:port]`` as browsers compare it: the scheme and host are
lowercased, internationalized hosts are IDNA-encoded and the default port for the scheme
is dropped. Matching is exact. There are no wildcards: a subdomain is a different origin
and has to be listed on its own.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit, urlunsplit

_DEFAULT_PORTS = {"http": 80, "https": 443}
MAX_URL_LENGTH = 2048


class InvalidUrlError(ValueError):
    """A URL or origin that script-sentinel refuses to store or scan."""


@dataclass(frozen=True, slots=True, order=True)
class Origin:
    scheme: str
    host: str
    port: int | None = None

    def __str__(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        port = f":{self.port}" if self.port is not None else ""
        return f"{self.scheme}://{host}{port}"


def _normalize_host(raw: str | None, original: str) -> str:
    if not raw:
        raise InvalidUrlError(f"{original!r} has no host")
    host = raw.rstrip(".").lower()
    if not host:
        raise InvalidUrlError(f"{original!r} has no host")
    try:
        # IPv6 literals arrive without brackets from urlsplit.
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidUrlError(f"{original!r} has an invalid host") from exc
    return host


def _split(url: str) -> tuple[SplitResult, Origin]:
    if not isinstance(url, str) or not url.strip():
        raise InvalidUrlError("URL is empty")
    url = url.strip()
    if len(url) > MAX_URL_LENGTH:
        raise InvalidUrlError(f"URL is longer than {MAX_URL_LENGTH} characters")
    if any(ch.isspace() or ord(ch) < 0x20 for ch in url):
        raise InvalidUrlError(f"{url!r} contains whitespace or control characters")
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise InvalidUrlError(f"{url!r} is not an http or https URL")
    if parts.username is not None or parts.password is not None:
        # Never store credentials, even ones embedded in a URL.
        raise InvalidUrlError(f"{scheme}://… URLs with credentials are not accepted")
    host = _normalize_host(parts.hostname, url)
    try:
        port = parts.port
    except ValueError as exc:
        raise InvalidUrlError(f"{url!r} has an invalid port") from exc
    if port == _DEFAULT_PORTS[scheme]:
        port = None
    return parts, Origin(scheme, host, port)


def parse_origin(value: str) -> Origin:
    """Parse an allowlist entry such as ``https://shop.example.com``.

    A trailing ``/`` is accepted; any other path, a query or a fragment is rejected so an
    entry cannot look narrower than it is.
    """
    parts, origin = _split(value)
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise InvalidUrlError(f"{value!r} is not a bare origin (drop the path, query and fragment)")
    return origin


def origin_of(url: str) -> Origin:
    """The origin of any http(s) URL."""
    return _split(url)[1]


def normalize_page_url(url: str) -> str:
    """The canonical form a page URL is stored under.

    Lowercases the scheme and host, drops the default port and the fragment (it never
    reaches the server) and uses ``/`` for an empty path. The path and query are kept as
    given, because servers may treat them case-sensitively.
    """
    parts, origin = _split(url)
    netloc = str(origin).split("://", 1)[1]
    return urlunsplit((origin.scheme, netloc, parts.path or "/", parts.query, ""))


def normalize_url_prefix(value: str) -> str:
    """The canonical form of a URL prefix such as ``https://cdn.vendor.com/sdk/``.

    The scheme, host and port are normalized like an origin and the path is kept as given.
    The path always starts with ``/``, so a prefix can never match another host that
    merely starts with the same name (``https://cdn.vendor.com.evil.test/``). A query or
    fragment is rejected: prefixes match paths.
    """
    parts, origin = _split(value)
    if parts.query or parts.fragment or value.strip().endswith(("?", "#")):
        raise InvalidUrlError(f"{value!r} has a query or fragment; a prefix matches paths only")
    return f"{origin}{parts.path or '/'}"


def normalize_origins(values: list[str]) -> list[str]:
    """Parse, deduplicate and sort allowlist entries. At least one is required."""
    origins = sorted({parse_origin(v) for v in values})
    if not origins:
        raise InvalidUrlError("at least one allowed origin is required")
    return [str(o) for o in origins]


def is_allowed(url: str, allowed_origins: list[str]) -> bool:
    """Whether ``url`` is on one of the allowed origins (exact origin match)."""
    try:
        origin = origin_of(url)
    except InvalidUrlError:
        return False
    allowed = set()
    for entry in allowed_origins:
        try:
            allowed.add(parse_origin(entry))
        except InvalidUrlError:
            continue
    return origin in allowed
