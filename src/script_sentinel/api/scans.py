"""``/v1/sites/{name}/scans``, ``/v1/scans/{id}`` and ``/v1/sites/{name}/scripts``."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Query, Request, status

from script_sentinel import scanner
from script_sentinel.api.schemas import (
    ErrorOut,
    ObservationOut,
    ScanDetail,
    ScanList,
    ScanOut,
    ScriptList,
    ScriptOut,
    SnapshotOut,
)
from script_sentinel.api.sites import AppSettings, Session
from script_sentinel.db.models import Scan, ScanTrigger

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
                    )
                    for obs in snap.observations
                ],
            )
            for snap in scan.snapshots
        ],
    )


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
    scripts = await scanner.list_scripts(session, name)
    return ScriptList(site=name, scripts=[ScriptOut.model_validate(s) for s in scripts])
