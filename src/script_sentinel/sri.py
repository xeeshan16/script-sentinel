"""Subresource Integrity: generating ``integrity`` values and checking them like a browser.

Follows the W3C SRI specification
(https://w3c.github.io/webappsec-subresource-integrity/):

* ``integrity`` holds whitespace-separated ``<algorithm>-<base64 digest>[?options]``
  tokens. Tokens with an unknown algorithm or a malformed shape are ignored.
* Only the tokens using the *strongest* algorithm present count; the body matches if any of
  them matches. ``sha256-<good> sha384-<bad>`` therefore fails, because sha384 is stronger.
* If no token is usable, the browser loads the script without checking it. That is reported
  as :attr:`SriStatus.NO_SUPPORTED_HASH`, because the attribute gives a false sense of
  safety.

Digests are compared as exact base64 strings, as the specification says. Some browsers are
more lenient (base64url, missing padding); being strict here can only produce a false
alarm, never a false "match".

The same ``sha384-<base64>`` string is also a CSP hash source for inline scripts
(``script-src 'sha384-…'``), which the CSP builder uses on day 9.
"""

from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass

from script_sentinel.db.models import SriStatus

# Strength order from weakest to strongest.
SUPPORTED_ALGORITHMS = ("sha256", "sha384", "sha512")
_TOKEN = re.compile(r"(?P<alg>[A-Za-z0-9]+)-(?P<digest>[A-Za-z0-9+/_-]+={0,2})(?:\?(?P<opts>.*))?")
_ASCII_WHITESPACE = re.compile(r"[\t\n\f\r ]+")


@dataclass(frozen=True, slots=True)
class IntegrityHash:
    algorithm: str  # lowercase, one of SUPPORTED_ALGORITHMS
    digest: str  # base64, as written


def parse_integrity(value: str) -> list[IntegrityHash]:
    """The usable hashes in an ``integrity`` attribute, in the order written."""
    hashes = []
    for token in _ASCII_WHITESPACE.split(value.strip()):
        match = _TOKEN.fullmatch(token)
        if not match:
            continue
        algorithm = match.group("alg").lower()
        if algorithm in SUPPORTED_ALGORITHMS:
            hashes.append(IntegrityHash(algorithm, match.group("digest")))
    return hashes


def strongest(hashes: list[IntegrityHash]) -> list[IntegrityHash]:
    """Only the hashes that use the strongest algorithm present."""
    if not hashes:
        return []
    best = max(SUPPORTED_ALGORITHMS.index(h.algorithm) for h in hashes)
    return [h for h in hashes if SUPPORTED_ALGORITHMS.index(h.algorithm) == best]


def integrity_value(body: bytes, algorithm: str = "sha384") -> str:
    """The SRI value for ``body``: ``<algorithm>-<base64 digest>``."""
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"unsupported SRI algorithm {algorithm!r}")
    digest = hashlib.new(algorithm, body).digest()
    return f"{algorithm}-{base64.b64encode(digest).decode('ascii')}"


def body_digests(body: bytes) -> dict[str, str]:
    """The base64 digest of ``body`` for every supported algorithm."""
    return {
        algorithm: base64.b64encode(hashlib.new(algorithm, body).digest()).decode("ascii")
        for algorithm in SUPPORTED_ALGORITHMS
    }


def check_integrity_digests(value: str, digests: Mapping[str, str]) -> SriStatus:
    """Like :func:`check_integrity`, from precomputed :func:`body_digests`."""
    candidates = strongest(parse_integrity(value))
    if not candidates:
        return SriStatus.NO_SUPPORTED_HASH
    actual = digests[candidates[0].algorithm]
    if any(h.digest == actual for h in candidates):
        return SriStatus.MATCH
    return SriStatus.MISMATCH


def check_integrity(value: str, body: bytes) -> SriStatus:
    """Whether a browser would accept ``body`` for this ``integrity`` attribute."""
    return check_integrity_digests(value, body_digests(body))
