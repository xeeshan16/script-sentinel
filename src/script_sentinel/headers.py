"""The security-relevant response headers of a page, captured on every scan.

PCI DSS 11.6.1 asks for a mechanism that detects unauthorized changes both to the scripts a
payment page runs *and* to its security-impacting HTTP headers. Each page snapshot keeps
the headers below exactly as served (every value, in order, since a header such as
``Content-Security-Policy`` may legitimately appear more than once and each copy is
enforced). Comparing them between scans is part of change detection (day 5).
"""

from __future__ import annotations

from collections.abc import Mapping

import httpx

SECURITY_HEADERS = (
    "content-security-policy",
    "content-security-policy-report-only",
    "integrity-policy",
    "integrity-policy-report-only",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
    "reporting-endpoints",
    "report-to",
)

# A misbehaving server shouldn't be able to bloat every snapshot.
MAX_VALUES_PER_HEADER = 8
MAX_VALUE_LENGTH = 8192


def capture_security_headers(headers: httpx.Headers) -> dict[str, list[str]]:
    """The security headers present in ``headers``, lowercase names to their values."""
    captured: dict[str, list[str]] = {}
    for name in SECURITY_HEADERS:
        values = [v.strip()[:MAX_VALUE_LENGTH] for v in headers.get_list(name)]
        if values:
            captured[name] = values[:MAX_VALUES_PER_HEADER]
    return captured


def describe(headers: Mapping[str, list[str]], meta_csp: list[str]) -> str:
    """A one-line summary for the CLI, e.g. ``CSP report-only, nosniff, HSTS``."""
    parts = []
    if "content-security-policy" in headers:
        parts.append("CSP")
    if meta_csp:
        parts.append("CSP (meta)")
    if "content-security-policy-report-only" in headers:
        parts.append("CSP report-only")
    if "integrity-policy" in headers:
        parts.append("Integrity-Policy")
    if "integrity-policy-report-only" in headers:
        parts.append("Integrity-Policy report-only")
    if "strict-transport-security" in headers:
        parts.append("HSTS")
    if any(v.lower() == "nosniff" for v in headers.get("x-content-type-options", [])):
        parts.append("nosniff")
    if "x-frame-options" in headers:
        parts.append("X-Frame-Options")
    if "referrer-policy" in headers:
        parts.append("Referrer-Policy")
    if "permissions-policy" in headers:
        parts.append("Permissions-Policy")
    return ", ".join(parts) if parts else "no security headers"
