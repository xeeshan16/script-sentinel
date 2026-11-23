"""``/v1/sites/{name}/scans``, ``/v1/scans/{id}`` and ``/v1/sites/{name}/scripts``."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Query, Request, Response, status

from script_sentinel import scanner, versions
from script_sentinel.api.schemas import (
    ErrorOut,
    ObservationOut,
    ScanDetail,
    ScanList,
    ScanOut,
    ScriptDetail,
    ScriptFetchOut,
    ScriptList,
    ScriptOut,
    SnapshotOut,
    VersionOut,
)
from script_sentinel.api.sites import AppSettings, Session
from script_sentinel.db.models import Scan, ScanTrigger, Script, ScriptVersion

router = APIRouter(tags=["scans"])

_ERRORS: dict[int | str, dict[str, object]] = {404: {"model": ErrorOut}, 422: {"model": ErrorOut}}


def _detail(scan: Scan, site_name: str) -> ScanDetail:
    return ScanDetail(
        **ScanOut.model_validate(scan).model_dump(),
        site=site_name,
        pages=[
            SnapshotOut(
                url=snap.url,
                payment_page=snap.payment_page,
                outcome=snap.outcome,
                final_url=snap.final_url,
                http_status=snap.http_status,
                content_type=snap.content_type,
                size_bytes=snap.size_bytes,
                body_sha384=snap.body_sha384,
                elapsed_ms=snap.elapsed_ms,
                error=snap.error,
                warnings=snap.warnings,
                data_block_count=snap.data_block_count,
                security_headers=snap.security_headers,
                meta_csp=snap.meta_csp,
                fetched_at=snap.fetched_at,
                scripts=[
                    ObservationOut(
                        position=obs.position,
                        script_id=obs.script_id,
                        kind=obs.script.kind,
                        locator=obs.script.locator,
                        script_type=obs.script_type,
                        type_attribute=obs.type_attribute,
                        integrity=obs.integrity,
                        crossorigin=obs.crossorigin,
                        referrerpolicy=obs.referrerpolicy,
                        has_nonce=obs.nonce_digest is not None,
                        is_async=obs.is_async,
                        is_defer=obs.is_defer,
                        nomodule=obs.nomodule,
                        inline_sha384=obs.inline_sha384,
                        inline_size_bytes=obs.inline_size_bytes,
                        version_id=obs.version_id,
                        sha384=obs.version.sha384 if obs.version else None,
                        sri=obs.version.sri if obs.version else None,
                        sri_status=obs.sri_status,
                    )
                    for obs in snap.observations
                ],
            )
            for snap in scan.snapshots
        ],
        script_fetches=[
            ScriptFetchOut(
                script_id=f.script_id,
                url=f.url,
                outcome=f.outcome,
                final_url=f.final_url,
                http_status=f.http_status,
                content_type=f.content_type,
                size_bytes=f.size_bytes,
                elapsed_ms=f.elapsed_ms,
                error=f.error,
                version_id=f.version_id,
                sha384=f.version.sha384 if f.version else None,
                sri=f.version.sri if f.version else None,
                new_version=f.new_version,
                fetched_at=f.fetched_at,
            )
            for f in scan.script_fetches
        ],
    )


def _script_out(script: Script, script_versions: list[ScriptVersion]) -> dict[str, object]:
    return {
        "id": script.id,
        "kind": script.kind,
        "locator": script.locator,
        "status": script.status,
        "justification": script.justification,
        "first_seen_at": script.first_seen_at,
        "last_seen_at": script.last_seen_at,
        "version_count": len(script_versions),
        "current_version": VersionOut.of(script_versions[0]) if script_versions else None,
    }


@router.post("/v1/sites/{name}/scans", status_code=status.HTTP_201_CREATED, responses=_ERRORS)
async def run_scan(
    name: str, request: Request, session: Session, settings: AppSettings
) -> ScanDetail:
    """Scan every page of the site now and return what was found.

    Runs inside the request; scheduled scans in the background arrive with the worker.
    """
    async with request.app.state.fetcher_factory() as fetcher:
        scan = await scanner.scan_site(
            session,
            name,
            fetcher,
            trigger=ScanTrigger.API,
            concurrency=settings.scan_concurrency,
        )
    detailed, site_name = await scanner.get_scan(session, scan.id)
    return _detail(detailed, site_name)


@router.get("/v1/sites/{name}/scans", responses=_ERRORS)
async def list_scans(
    name: str, session: Session, limit: Annotated[int, Query(ge=1, le=200)] = 20
) -> ScanList:
    scans = await scanner.list_scans(session, name, limit=limit)
    return ScanList(site=name, scans=[ScanOut.model_validate(s) for s in scans])


@router.get("/v1/scans/{scan_id}", responses=_ERRORS)
async def get_scan(scan_id: uuid.UUID, session: Session) -> ScanDetail:
    scan, site_name = await scanner.get_scan(session, scan_id)
    return _detail(scan, site_name)


@router.get("/v1/sites/{name}/scripts", responses=_ERRORS)
async def list_scripts(name: str, session: Session) -> ScriptList:
    """The site's script inventory, each with its current version and SRI value."""
    scripts = await scanner.list_scripts(session, name)
    by_script = await versions.versions_by_script(session, [s.id for s in scripts])
    return ScriptList(
        site=name,
        scripts=[ScriptOut.model_validate(_script_out(s, by_script[s.id])) for s in scripts],
    )


@router.get("/v1/sites/{name}/scripts/{script_id}", responses=_ERRORS)
async def get_script(name: str, script_id: uuid.UUID, session: Session) -> ScriptDetail:
    """One script with every body it has served (its version history)."""
    script = await versions.get_script(session, name, script_id)
    history = (await versions.versions_by_script(session, [script.id]))[script.id]
    return ScriptDetail.model_validate(
        {**_script_out(script, history), "versions": [VersionOut.of(v) for v in history]}
    )


# A stored third-party body must never run on this origin: plain text, no sniffing, and a
# sandboxing policy in case a browser opens it anyway.
_CONTENT_HEADERS = {
    "x-content-type-options": "nosniff",
    "content-security-policy": "default-src 'none'; sandbox",
    "cache-control": "no-store",
}


@router.get(
    "/v1/sites/{name}/scripts/{script_id}/versions/{version_id}/content",
    responses={**_ERRORS, 200: {"content": {"text/plain": {}}}},
    response_class=Response,
)
async def get_version_content(
    name: str, script_id: uuid.UUID, version_id: uuid.UUID, session: Session
) -> Response:
    """The body of one version as text (served as ``text/plain``, never as JavaScript)."""
    version = await versions.get_version(session, name, script_id, version_id)
    return Response(
        content=version.content or "",
        media_type="text/plain; charset=utf-8",
        headers={**_CONTENT_HEADERS, "x-script-sha384": version.sha384},
    )
