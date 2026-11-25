"""Findings raised by scans, and diffs between script versions."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Query

from script_sentinel import findings, versions
from script_sentinel.api.schemas import (
    DiffOut,
    ErrorOut,
    FindingDetail,
    FindingList,
    FindingOut,
    FindingStatusIn,
    VersionOut,
)
from script_sentinel.api.sites import Session
from script_sentinel.db.models import Finding, FindingStatus, Severity

router = APIRouter(tags=["findings"])

_ERRORS: dict[int | str, dict[str, object]] = {404: {"model": ErrorOut}, 422: {"model": ErrorOut}}


def _detail(finding: Finding, site_name: str) -> FindingDetail:
    return FindingDetail(
        **FindingOut.of(finding).model_dump(), site=site_name, detail=finding.detail
    )


@router.get("/v1/sites/{name}/findings", responses=_ERRORS)
async def list_findings(
    name: str,
    session: Session,
    status: FindingStatus | None = None,
    min_severity: Severity | None = None,
    scan_id: uuid.UUID | None = None,
    script_id: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
) -> FindingList:
    """The site's findings, newest first. Filter by status, minimum severity, scan or script."""
    rows = await findings.list_findings(
        session,
        name,
        status=status,
        min_severity=min_severity,
        scan_id=scan_id,
        script_id=script_id,
        limit=limit,
    )
    return FindingList(site=name, findings=[FindingOut.of(f) for f in rows])


@router.get("/v1/findings/{finding_id}", responses=_ERRORS)
async def get_finding(finding_id: uuid.UUID, session: Session) -> FindingDetail:
    """One finding with its evidence (for a change: the diff and what it references)."""
    finding, site_name = await findings.get_finding(session, finding_id)
    return _detail(finding, site_name)


async def _set(
    session: Session, finding_id: uuid.UUID, status: FindingStatus, body: FindingStatusIn
) -> FindingDetail:
    finding, site_name = await findings.set_status(
        session, finding_id, status, actor=body.actor, note=body.note
    )
    return _detail(finding, site_name)


@router.post("/v1/findings/{finding_id}/acknowledge", responses=_ERRORS)
async def acknowledge_finding(
    finding_id: uuid.UUID, body: FindingStatusIn, session: Session
) -> FindingDetail:
    """Someone is looking at it. Recorded in the audit trail."""
    return await _set(session, finding_id, FindingStatus.ACKNOWLEDGED, body)


@router.post("/v1/findings/{finding_id}/resolve", responses=_ERRORS)
async def resolve_finding(
    finding_id: uuid.UUID, body: FindingStatusIn, session: Session
) -> FindingDetail:
    """Close it with a note saying what was done. Recorded in the audit trail."""
    return await _set(session, finding_id, FindingStatus.RESOLVED, body)


@router.post("/v1/findings/{finding_id}/reopen", responses=_ERRORS)
async def reopen_finding(
    finding_id: uuid.UUID, body: FindingStatusIn, session: Session
) -> FindingDetail:
    return await _set(session, finding_id, FindingStatus.OPEN, body)


@router.get("/v1/sites/{name}/scripts/{script_id}/diff", responses=_ERRORS)
async def diff_script(
    name: str,
    script_id: uuid.UUID,
    session: Session,
    from_ref: Annotated[str | None, Query(alias="from", max_length=96)] = None,
    to_ref: Annotated[str | None, Query(alias="to", max_length=96)] = None,
    max_hunks: Annotated[int, Query(ge=1, le=1000)] = 200,
) -> DiffOut:
    """The token diff between two versions (by id, or a SHA-384 or SRI prefix).

    Defaults to the body seen most recently against the one seen before it.
    """
    result = await versions.diff_versions(
        session, name, script_id, from_ref=from_ref, to_ref=to_ref
    )
    return DiffOut.model_validate(
        {
            "script_id": result.script.id,
            "locator": result.script.locator,
            "from_version": VersionOut.of(result.old),
            "to_version": VersionOut.of(result.new),
            **result.analysis.to_dict(max_hunks=max_hunks),
        }
    )
