"""CSP violation reports: parsing, validation, normalization and fingerprinting.

Browsers send violation reports in two formats:

* **``report-uri``** (``Content-Type: application/csp-report``): one JSON object per
  request, ``{"csp-report": {"document-uri": …, "effective-directive": …, …}}``.
* **The Reporting API** (``report-to`` with a ``Reporting-Endpoints`` header,
  ``Content-Type: application/reports+json``): a JSON array of reports, batched, of which
  only ``"type": "csp-violation"`` entries are CSP violations. Other types (deprecation,
  intervention, crash, …) can share the endpoint and are counted, not stored.

Everything here is pure: the payload is validated against a schema, each report becomes a
:class:`Violation` or a :class:`DropReason`, and a violation's fingerprint decides which
group it counts towards. Persistence lives in ``violations.py``.

Reports come from browsers, so every field is untrusted, and they carry data nobody asked
for. Normalization keeps what is needed to act on a violation and drops the rest:

* the query and fragment of the document, blocked and source URLs (they can carry session
  tokens, e-mail addresses or order numbers), and URL credentials;
* the ``referrer`` and the reporting browser's user agent;
* the body of ``data:`` and ``blob:`` URLs (only the scheme is kept);
* the script sample beyond 40 characters (the length browsers send).

A report about a document that isn't on one of the site's allowed origins is dropped, so a
third party can't fill a site's inventory of violations with someone else's pages, and
reports caused by browser extensions are dropped as noise.
"""

from __future__ import annotations

import enum
import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field
from pydantic import ValidationError as PydanticValidationError

from script_sentinel.db.models import CspBlockedKind, CspDisposition, CspReportFormat
from script_sentinel.origins import MAX_URL_LENGTH, InvalidUrlError, origin_of

CSP_REPORT_TYPE = "application/csp-report"
REPORTS_JSON_TYPE = "application/reports+json"
JSON_TYPE = "application/json"
ACCEPTED_CONTENT_TYPES = frozenset({CSP_REPORT_TYPE, REPORTS_JSON_TYPE, JSON_TYPE})

# Browsers send at most 40 characters of the offending code.
MAX_SAMPLE_CHARS = 40
# Kept for display; the fingerprint covers the policy's hash, which is computed in full.
MAX_POLICY_CHARS = 4096
MAX_OTHER_BLOCKED_CHARS = 256

# Values browsers put in blocked-uri / blockedURL instead of a URL.
BLOCKED_KEYWORDS = frozenset(
    {"inline", "eval", "wasm-eval", "self", "trusted-types-policy", "trusted-types-sink"}
)
# Schemes whose URLs say nothing useful beyond the scheme (and may embed whole documents).
OPAQUE_SCHEMES = frozenset({"data", "blob", "filesystem", "mediastream", "about"})
URL_SCHEMES = frozenset({"http", "https", "ws", "wss"})
# Reports triggered by browser extensions injecting code into the page.
EXTENSION_SCHEMES = frozenset(
    {
        "chrome-extension",
        "moz-extension",
        "safari-extension",
        "safari-web-extension",
        "ms-browser-extension",
        "edge-extension",
        "resource",
    }
)
_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}
_DIRECTIVE = re.compile(r"[a-z][a-z-]{0,63}")
_SCHEME = re.compile(r"([a-z][a-z0-9+.-]*):", re.IGNORECASE)
_BARE_SCHEME = re.compile(r"[a-z][a-z0-9+.-]*", re.IGNORECASE)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class PayloadError(ValueError):
    """A request body that isn't a CSP report payload at all (HTTP 400)."""


class UnsupportedContentTypeError(ValueError):
    """A content type that isn't one of the report formats (HTTP 415)."""


class DropReason(enum.StrEnum):
    INVALID = "invalid"  # failed the schema or has no usable directive or document
    NOT_CSP = "not_csp"  # a Reporting API report of another type
    FOREIGN_DOCUMENT = "foreign_document"  # the page isn't on the site's allowed origins
    EXTENSION = "extension"  # caused by a browser extension
    BATCH_LIMIT = "batch_limit"  # beyond the reports accepted per request
    GROUP_LIMIT = "group_limit"  # a new group when the site has as many as it may keep


# --- Schemas --------------------------------------------------------------------------------

# Long enough for any real value; longer strings are reports nobody sent by accident.
_Text = Annotated[str, Field(max_length=16_384)]
_Url = Annotated[str, Field(max_length=8_192)]
_Count = Annotated[int, Field(ge=0, le=2**31 - 1)]
_Status = Annotated[int, Field(ge=0, le=999)]


class _LegacyReport(BaseModel):
    """The object inside ``{"csp-report": …}`` (CSP Level 2 names)."""

    model_config = ConfigDict(extra="ignore")

    document_uri: _Url = Field(alias="document-uri")
    violated_directive: _Text | None = Field(default=None, alias="violated-directive")
    effective_directive: _Text | None = Field(default=None, alias="effective-directive")
    original_policy: _Text | None = Field(default=None, alias="original-policy")
    disposition: Literal["enforce", "report"] | None = None
    blocked_uri: _Url | None = Field(default=None, alias="blocked-uri")
    source_file: _Url | None = Field(default=None, alias="source-file")
    line_number: _Count | None = Field(default=None, alias="line-number")
    column_number: _Count | None = Field(default=None, alias="column-number")
    status_code: _Status | None = Field(default=None, alias="status-code")
    script_sample: _Text | None = Field(default=None, alias="script-sample")


class _LegacyEnvelope(BaseModel):
    model_config = ConfigDict(extra="ignore")

    csp_report: dict[str, Any] = Field(alias="csp-report")


class _ReportEnvelope(BaseModel):
    """One entry of a Reporting API batch."""

    model_config = ConfigDict(extra="ignore")

    type: Annotated[str, Field(max_length=64)]
    body: dict[str, Any] | None = None


class _CspViolationBody(BaseModel):
    """The ``body`` of a ``csp-violation`` report (CSP Level 3 names)."""

    model_config = ConfigDict(extra="ignore")

    document_url: _Url = Field(alias="documentURL")
    effective_directive: _Text | None = Field(default=None, alias="effectiveDirective")
    original_policy: _Text | None = Field(default=None, alias="originalPolicy")
    disposition: Literal["enforce", "report"] | None = None
    blocked_url: _Url | None = Field(default=None, alias="blockedURL")
    source_file: _Url | None = Field(default=None, alias="sourceFile")
    line_number: _Count | None = Field(default=None, alias="lineNumber")
    column_number: _Count | None = Field(default=None, alias="columnNumber")
    status_code: _Status | None = Field(default=None, alias="statusCode")
    sample: _Text | None = None


# --- The normalized violation ----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Blocked:
    value: str
    kind: CspBlockedKind
    host: str | None = None


@dataclass(frozen=True, slots=True)
class Violation:
    """One report, reduced to what is needed to act on it."""

    format: CspReportFormat
    document_url: str  # origin and path, no query or fragment
    effective_directive: str
    blocked: Blocked
    disposition: CspDisposition
    source_file: str | None = None  # origin and path, no query or fragment
    line: int | None = None
    column: int | None = None
    status_code: int | None = None
    sample: str | None = None
    original_policy: str | None = None  # truncated to MAX_POLICY_CHARS
    policy_sha256: str | None = None  # of the whole policy as sent

    def fingerprint(self) -> str:
        """The identity of the group this violation counts towards.

        The same page, directive, blocked resource, source location and disposition is the
        same problem, whichever browser reported it and however often. The column, the
        sample and the policy text are left out: minified code puts everything on line 1
        with columns that move on every build, and a sample is attacker-controlled text.
        """
        parts = (
            self.document_url,
            self.effective_directive,
            self.blocked.kind.value,
            self.blocked.value,
            self.source_file or "",
            "" if self.line is None else str(self.line),
            self.disposition.value,
        )
        return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


@dataclass(slots=True)
class ParsedPayload:
    """A request body split into violations and the reasons the rest were dropped."""

    format: CspReportFormat
    received: int  # reports in the payload, including dropped ones
    violations: list[Violation] = field(default_factory=list)
    dropped: Counter[DropReason] = field(default_factory=Counter)


# --- Helpers ----------------------------------------------------------------------------------


def media_type(content_type: str | None) -> str:
    """``application/csp-report`` from ``application/csp-report; charset=utf-8``."""
    return (content_type or "").split(";", 1)[0].strip().lower()


def _clean(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    cleaned = _CONTROL.sub("", value).strip()
    return cleaned[:limit] or None


def _scheme(value: str) -> str | None:
    match = _SCHEME.match(value.strip())
    return match.group(1).lower() if match else None


def is_extension(value: str | None) -> bool:
    """Whether a blocked or source URL (or a bare scheme) points into a browser extension."""
    if not value:
        return False
    value = value.strip().lower()
    return (_scheme(value) or value) in EXTENSION_SCHEMES


def strip_url(value: str) -> tuple[str, str] | None:
    """``(scheme://host[:port]/path, host)`` for an http(s)/ws(s) URL, or ``None``.

    Drops credentials, the query and the fragment, lowercases the scheme and host and drops
    the default port, so the same resource requested with different query strings is one
    resource.
    """
    value = value.strip()
    if len(value) > MAX_URL_LENGTH or _CONTROL.search(value) or " " in value:
        return None
    try:
        parts = urlsplit(value)
        scheme = parts.scheme.lower()
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if scheme not in URL_SCHEMES or not host:
        return None
    host = host.rstrip(".")
    if not host:
        return None
    if ":" in host:  # an IPv6 literal
        netloc = f"[{host}]"
    else:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return None
        netloc = host
    if port is not None and port != _DEFAULT_PORTS[scheme]:
        netloc += f":{port}"
    return f"{scheme}://{netloc}{parts.path or '/'}", host


def normalize_blocked(value: str | None) -> Blocked:
    """What was blocked, as one of :class:`CspBlockedKind`."""
    raw = (value or "").strip()
    if not raw:
        return Blocked("", CspBlockedKind.NONE)
    lowered = raw.lower()
    if lowered in BLOCKED_KEYWORDS:
        return Blocked(lowered, CspBlockedKind.KEYWORD)
    scheme = _scheme(raw)
    if scheme in URL_SCHEMES:
        stripped = strip_url(raw)
        if stripped is not None:
            return Blocked(stripped[0], CspBlockedKind.URL, stripped[1])
    elif scheme is not None and (scheme in OPAQUE_SCHEMES or "//" not in raw):
        # data:…, blob:https://…, and other schemes without an authority: scheme only.
        return Blocked(f"{scheme}:", CspBlockedKind.SCHEME)
    elif scheme is None and _BARE_SCHEME.fullmatch(raw):
        # Older browsers send just the scheme ("data", "blob") for opaque resources.
        return Blocked(f"{lowered}:", CspBlockedKind.SCHEME)
    return Blocked(_clean(raw, MAX_OTHER_BLOCKED_CHARS) or "", CspBlockedKind.OTHER)


def normalize_directive(effective: str | None, violated: str | None = None) -> str | None:
    """The directive that was violated, e.g. ``script-src-elem``.

    ``effective-directive`` is preferred; old browsers only send ``violated-directive``,
    which is the whole directive with its sources (``script-src 'self' cdn.test``).
    """
    for candidate in (effective, violated):
        if not candidate or not candidate.strip():
            continue
        name = candidate.strip().split(None, 1)[0].lower()
        return name if _DIRECTIVE.fullmatch(name) else None
    return None


def _document(value: str, allowed_origins: list[str]) -> str | DropReason:
    try:
        origin = origin_of(value)
    except InvalidUrlError:
        return DropReason.INVALID
    if str(origin) not in allowed_origins:
        return DropReason.FOREIGN_DOCUMENT
    stripped = strip_url(value)
    return stripped[0] if stripped is not None else DropReason.INVALID


def _policy(value: str | None) -> tuple[str | None, str | None]:
    if value is None or not value.strip():
        return None, None
    text = value.strip()
    return text[:MAX_POLICY_CHARS], hashlib.sha256(text.encode("utf-8")).hexdigest()


def _violation(
    fmt: CspReportFormat,
    *,
    document: str,
    directive: str | None,
    blocked: str | None,
    disposition: str | None,
    source_file: str | None,
    line: int | None,
    column: int | None,
    status_code: int | None,
    sample: str | None,
    policy: str | None,
    allowed_origins: list[str],
) -> Violation | DropReason:
    if is_extension(blocked) or is_extension(source_file):
        return DropReason.EXTENSION
    document_url = _document(document, allowed_origins)
    if isinstance(document_url, DropReason):
        return document_url
    if directive is None:
        return DropReason.INVALID
    stripped_source = strip_url(source_file) if source_file else None
    policy_text, policy_hash = _policy(policy)
    return Violation(
        format=fmt,
        document_url=document_url,
        effective_directive=directive,
        blocked=normalize_blocked(blocked),
        disposition=CspDisposition(disposition) if disposition else CspDisposition.UNKNOWN,
        source_file=stripped_source[0] if stripped_source else None,
        line=line,
        column=column,
        status_code=status_code,
        sample=_clean(sample, MAX_SAMPLE_CHARS),
        original_policy=policy_text,
        policy_sha256=policy_hash,
    )


def normalize_legacy(report: dict[str, Any], allowed_origins: list[str]) -> Violation | DropReason:
    """One ``report-uri`` report (the object inside ``"csp-report"``)."""
    try:
        parsed = _LegacyReport.model_validate(report)
    except PydanticValidationError:
        return DropReason.INVALID
    return _violation(
        CspReportFormat.CSP_REPORT,
        document=parsed.document_uri,
        directive=normalize_directive(parsed.effective_directive, parsed.violated_directive),
        blocked=parsed.blocked_uri,
        disposition=parsed.disposition,
        source_file=parsed.source_file,
        line=parsed.line_number,
        column=parsed.column_number,
        status_code=parsed.status_code,
        sample=parsed.script_sample,
        policy=parsed.original_policy,
        allowed_origins=allowed_origins,
    )


def normalize_reporting(report: Any, allowed_origins: list[str]) -> Violation | DropReason:
    """One entry of a Reporting API batch."""
    try:
        envelope = _ReportEnvelope.model_validate(report)
    except PydanticValidationError:
        return DropReason.INVALID
    if envelope.type != "csp-violation":
        return DropReason.NOT_CSP
    try:
        body = _CspViolationBody.model_validate(envelope.body or {})
    except PydanticValidationError:
        return DropReason.INVALID
    return _violation(
        CspReportFormat.REPORTING_API,
        document=body.document_url,
        directive=normalize_directive(body.effective_directive),
        blocked=body.blocked_url,
        disposition=body.disposition,
        source_file=body.source_file,
        line=body.line_number,
        column=body.column_number,
        status_code=body.status_code,
        sample=body.sample,
        policy=body.original_policy,
        allowed_origins=allowed_origins,
    )


def _load(body: bytes) -> Any:
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise PayloadError("the body is not valid UTF-8 JSON") from exc


def check_content_type(content_type: str | None) -> str:
    """The media type, if it is one of the report formats."""
    kind = media_type(content_type)
    if kind not in ACCEPTED_CONTENT_TYPES:
        raise UnsupportedContentTypeError(
            f"unsupported content type {kind or '(none)'!r}; send {CSP_REPORT_TYPE} "
            f"(report-uri) or {REPORTS_JSON_TYPE} (Reporting API)"
        )
    return kind


def detect_format(payload: Any, content_type: str | None) -> CspReportFormat:
    """Which format a decoded payload is in, from its content type and shape.

    ``application/json`` (sent by some proxies and test tools) is accepted for both, and a
    payload whose shape contradicts its content type is rejected rather than guessed at.
    """
    kind = check_content_type(content_type)
    if isinstance(payload, list) and kind in (REPORTS_JSON_TYPE, JSON_TYPE):
        return CspReportFormat.REPORTING_API
    if isinstance(payload, dict) and kind in (CSP_REPORT_TYPE, JSON_TYPE):
        return CspReportFormat.CSP_REPORT
    expected = "an array of reports" if kind == REPORTS_JSON_TYPE else '{"csp-report": {…}}'
    raise PayloadError(f"{kind} payloads are {expected}")


def parse_payload(
    body: bytes, content_type: str | None, allowed_origins: list[str], *, max_reports: int
) -> ParsedPayload:
    """Split a request body into violations and dropped reports.

    Raises :class:`UnsupportedContentTypeError` for a content type that isn't a report
    format and :class:`PayloadError` for a body that isn't JSON of the right shape. A
    batch with some bad reports is not an error: the bad ones are counted as dropped.
    Reports beyond ``max_reports`` are dropped unread (``batch_limit``).
    """
    check_content_type(content_type)  # before reading anything
    payload = _load(body)
    fmt = detect_format(payload, content_type)
    if fmt is CspReportFormat.CSP_REPORT:
        try:
            envelope = _LegacyEnvelope.model_validate(payload)
        except PydanticValidationError as exc:
            raise PayloadError('report-uri payloads are {"csp-report": {…}}') from exc
        parsed = ParsedPayload(fmt, received=1)
        _add(parsed, normalize_legacy(envelope.csp_report, allowed_origins))
        return parsed
    parsed = ParsedPayload(fmt, received=len(payload))
    for report in payload[:max_reports]:
        _add(parsed, normalize_reporting(report, allowed_origins))
    if len(payload) > max_reports:
        parsed.dropped[DropReason.BATCH_LIMIT] += len(payload) - max_reports
    return parsed


def _add(parsed: ParsedPayload, result: Violation | DropReason) -> None:
    if isinstance(result, DropReason):
        parsed.dropped[result] += 1
    else:
        parsed.violations.append(result)
