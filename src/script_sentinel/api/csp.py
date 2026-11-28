"""The CSP report collector and the violation groups it builds.

Browsers ``POST`` violation reports to ``/v1/reports/csp/{site}``: point a policy's
``report-uri`` there, or name it in ``Reporting-Endpoints`` and use ``report-to``. The
endpoint needs no credentials (browsers have none to send), so everything it accepts is
bounded instead: the body size is checked before reading and while streaming, each site
has a token-bucket rate limit charged per report, batches are capped, and only reports
about the site's own allowed origins are kept.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse

from script_sentinel import sites, violations
from script_sentinel.api.schemas import (
    CspIngestOut,
    CspRollupOut,
    CspViolationDetail,
    CspViolationList,
    CspViolationOut,
    ErrorOut,
)
from script_sentinel.api.sites import AppSettings, Session
from script_sentinel.csp_reports import (
    ParsedPayload,
    PayloadError,
    UnsupportedContentTypeError,
    parse_payload,
)
from script_sentinel.db.models import CspDisposition, Site, utcnow
from script_sentinel.ingest import IngestUnavailableError, ReportSink
from script_sentinel.origins import InvalidUrlError, parse_origin
from script_sentinel.ratelimit import RateLimiter, retry_after

router = APIRouter(tags=["csp"])

REPORT_PATH = "/v1/reports/csp/{name}"

_COLLECT_ERRORS: dict[int | str, dict[str, object]] = {
    code: {"model": ErrorOut} for code in (400, 404, 413, 415, 429, 503)
}
_ERRORS: dict[int | str, dict[str, object]] = {404: {"model": ErrorOut}, 422: {"model": ErrorOut}}


def _cors(request: Request, site: Site) -> dict[str, str]:
    """CORS headers for a request from one of the site's own origins.

    Reporting API deliveries are CORS requests (their content type isn't a "simple" one),
    so the browser asks first with a preflight. Only the site's allowed origins are let
    through; anyone else gets no ``Access-Control-Allow-Origin`` and the browser stops.
    """
    headers = {"Vary": "Origin"}
    origin = request.headers.get("origin")
    if origin:
        try:
            allowed = str(parse_origin(origin)) in site.allowed_origins
        except InvalidUrlError:
            allowed = False
        if allowed:
            headers["Access-Control-Allow-Origin"] = origin
    return headers


async def _read_body(request: Request, limit: int) -> bytes:
    too_large = HTTPException(
        status.HTTP_413_CONTENT_TOO_LARGE, f"report payloads are limited to {limit} bytes"
    )
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            length = int(declared)
        except ValueError:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid Content-Length") from None
        if length > limit:
            raise too_large
    encoding = request.headers.get("content-encoding", "identity").strip().lower()
    if encoding not in ("", "identity"):
        raise HTTPException(
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "compressed report payloads are not accepted"
        )
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:  # a missing or understated Content-Length
            raise too_large
        chunks.append(chunk)
    return b"".join(chunks)


@router.options(REPORT_PATH, include_in_schema=False)
async def preflight(name: str, request: Request, session: Session) -> Response:
    site = await sites.get_site(session, name)
    headers = _cors(request, site)
    if "Access-Control-Allow-Origin" in headers:
        headers |= {
            "Access-Control-Allow-Methods": "POST",
            "Access-Control-Allow-Headers": "content-type",
            "Access-Control-Max-Age": "86400",
        }
    return Response(status_code=status.HTTP_204_NO_CONTENT, headers=headers)


@router.post(
    REPORT_PATH,
    status_code=status.HTTP_202_ACCEPTED,
    response_model=CspIngestOut,
    responses=_COLLECT_ERRORS,
)
async def collect(
    name: str, request: Request, session: Session, settings: AppSettings
) -> JSONResponse:
    """Collect CSP violation reports (``application/csp-report`` or
    ``application/reports+json``).

    Answers ``202`` with what was counted and why the rest was dropped. ``429`` with
    ``Retry-After`` when the site is over its rate limit (nothing is recorded), ``413``
    for a body over the size limit, ``415`` for another content type, ``400`` for a body
    that isn't a report payload. ``503`` with ``Retry-After`` when the buffer or the queue
    can't take the reports (buffered and kafka modes).
    """
    site = await sites.get_site(session, name)
    cors = _cors(request, site)
    limits = settings.ingest_limits()
    limiter: RateLimiter = request.app.state.csp_limiter
    parsed: ParsedPayload | None = None
    error: HTTPException | None = None
    try:
        body = await _read_body(request, settings.csp_max_body_bytes)
        parsed = parse_payload(
            body,
            request.headers.get("content-type"),
            site.allowed_origins,
            max_reports=limits.max_reports,
        )
    except HTTPException as exc:
        error = exc
    except UnsupportedContentTypeError as exc:
        error = HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, str(exc))
    except PayloadError as exc:
        error = HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
    # Charge what was read (a rejected request still costs one), before any write.
    cost = min(parsed.received, limits.max_reports) if parsed else 1
    wait = limiter.acquire(site.name, cost)
    if wait:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too many CSP reports for this site; try again later",
            headers={**cors, "Retry-After": retry_after(wait)},
        )
    if error is not None:
        error.headers = {**cors, **(error.headers or {})}
        raise error
    assert parsed is not None
    sink: ReportSink | None = request.app.state.csp_sink
    if sink is None:
        result = await violations.ingest(session, site, parsed, limits=limits)
    else:
        try:
            await sink.submit(violations.Pending(site.id, utcnow(), parsed.violations))
        except IngestUnavailableError as exc:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                str(exc),
                headers={**cors, "Retry-After": retry_after(exc.retry_after)},
            ) from exc
        result = violations.queued(site, parsed, mode=sink.mode.value)
    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content=CspIngestOut.model_validate(result.to_dict()).model_dump(mode="json"),
        headers=cors,
    )


@router.get("/v1/sites/{name}/csp/violations", responses=_ERRORS)
async def list_violations(
    name: str,
    session: Session,
    directive: Annotated[str | None, Query(max_length=64)] = None,
    disposition: CspDisposition | None = None,
    blocked_host: Annotated[str | None, Query(max_length=255)] = None,
    since: datetime | None = None,
    order: violations.ViolationOrder = violations.ViolationOrder.LAST_SEEN,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
) -> CspViolationList:
    """The site's violation groups, most recently seen (or most reported) first."""
    page = await violations.list_violations(
        session,
        name,
        directive=directive,
        disposition=disposition,
        blocked_host=blocked_host,
        since=since,
        order=order,
        limit=limit,
    )
    return CspViolationList(
        site=name,
        total_groups=page.total_groups,
        total_reports=page.total_reports,
        violations=[CspViolationOut.of(g) for g in page.groups],
    )


@router.get("/v1/sites/{name}/csp/violations/{violation_id}", responses=_ERRORS)
async def get_violation(name: str, violation_id: uuid.UUID, session: Session) -> CspViolationDetail:
    """One violation group, with the policy that was violated."""
    group = await violations.get_violation(session, name, violation_id)
    return CspViolationDetail(
        **CspViolationOut.of(group).model_dump(), original_policy=group.original_policy
    )


@router.get("/v1/sites/{name}/csp/rollups", responses=_ERRORS)
async def get_rollups(
    name: str,
    session: Session,
    by: violations.RollupDimension = violations.RollupDimension.BOTH,
    hours: Annotated[int, Query(ge=1, le=violations.MAX_WINDOW_HOURS)] = 24,
    directive: Annotated[str | None, Query(max_length=64)] = None,
    disposition: CspDisposition | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 20,
) -> CspRollupOut:
    """Accepted reports over the last ``hours`` UTC hours by directive, blocked host (or
    keyword) or both, each with its count in the window before, plus an hourly series."""
    report = await violations.rollup(
        session,
        name,
        by=by,
        hours=hours,
        directive=directive,
        disposition=disposition,
        limit=limit,
    )
    return CspRollupOut.model_validate(report.to_dict())


@router.get("/v1/csp/ingest", tags=["csp"])
async def ingest_status(request: Request) -> dict[str, object]:
    """How this process hands reports to the database: the mode, and for buffered and
    kafka modes what is waiting, what was written or published, and the last error."""
    sink: ReportSink | None = request.app.state.csp_sink
    return {"mode": "direct"} if sink is None else sink.status()
