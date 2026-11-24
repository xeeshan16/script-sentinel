"""Authorization (PCI DSS 6.4.3): decisions about scripts, policies and the audit trail."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Query

from script_sentinel import audit, authorization, versions
from script_sentinel.api.scans import script_out
from script_sentinel.api.schemas import (
    ApproveIn,
    AuditEventOut,
    AuditList,
    ChainOut,
    ErrorOut,
    PolicyChangeOut,
    PolicyCreate,
    PolicyList,
    PolicyOut,
    RejectIn,
    ScriptDetail,
    StatusChangeOut,
    VersionOut,
)
from script_sentinel.api.sites import Session
from script_sentinel.db.models import Script
from script_sentinel.sites import get_site

router = APIRouter(tags=["authorization"])

_ERRORS: dict[int | str, dict[str, object]] = {
    404: {"model": ErrorOut},
    409: {"model": ErrorOut},
    422: {"model": ErrorOut},
}


async def _detail(session: Session, script: Script) -> ScriptDetail:
    history = (await versions.versions_by_script(session, [script.id]))[script.id]
    return ScriptDetail.model_validate(
        {**script_out(script, history), "versions": [VersionOut.of(v) for v in history]}
    )


def _changes(changes: list[authorization.Change]) -> list[StatusChangeOut]:
    return [
        StatusChangeOut(
            script_id=c.script.id,
            locator=c.script.locator,
            from_status=c.from_status,
            to_status=c.to_status,
        )
        for c in changes
    ]


@router.post("/v1/sites/{name}/scripts/{script_id}/approve", responses=_ERRORS)
async def approve_script(
    name: str, script_id: uuid.UUID, body: ApproveIn, session: Session
) -> ScriptDetail:
    """Approve a script with a written justification.

    A pinned approval covers the bodies the script serves now; when the vendor serves a
    new body the script is pending again until it is approved again.
    """
    script = await authorization.approve_script(
        session,
        name,
        script_id,
        actor=body.actor,
        justification=body.justification,
        scope=body.scope,
    )
    return await _detail(session, script)


@router.post("/v1/sites/{name}/scripts/{script_id}/reject", responses=_ERRORS)
async def reject_script(
    name: str, script_id: uuid.UUID, body: RejectIn, session: Session
) -> ScriptDetail:
    """Reject a script. A rejection overrides every policy."""
    script = await authorization.reject_script(
        session, name, script_id, actor=body.actor, reason=body.reason
    )
    return await _detail(session, script)


@router.post("/v1/sites/{name}/scripts/{script_id}/reset", responses=_ERRORS)
async def reset_script(
    name: str, script_id: uuid.UUID, body: RejectIn, session: Session
) -> ScriptDetail:
    """Withdraw the decision about a script, so policies alone decide its status."""
    script = await authorization.reset_script(
        session, name, script_id, actor=body.actor, reason=body.reason
    )
    return await _detail(session, script)


@router.get("/v1/sites/{name}/policies", responses=_ERRORS)
async def list_policies(name: str, session: Session) -> PolicyList:
    policies = await authorization.list_policies(session, name)
    return PolicyList(site=name, policies=[PolicyOut.of(p) for p in policies])


@router.post("/v1/sites/{name}/policies", status_code=201, responses=_ERRORS)
async def create_policy(name: str, body: PolicyCreate, session: Session) -> PolicyChangeOut:
    """Add a policy; the response lists the scripts whose status it changed."""
    policy, changes = await authorization.create_policy(
        session,
        name,
        kind=body.kind,
        match=body.match,
        change=body.change,
        ignore_query=body.ignore_query,
        justification=body.justification,
        actor=body.actor,
    )
    return PolicyChangeOut(policy=PolicyOut.of(policy), scripts_changed=_changes(changes))


@router.delete("/v1/sites/{name}/policies/{policy_id}", responses=_ERRORS)
async def remove_policy(
    name: str,
    policy_id: uuid.UUID,
    session: Session,
    actor: Annotated[str, Query(min_length=1, max_length=128)],
    reason: Annotated[str, Query(min_length=1, max_length=2000)],
) -> PolicyChangeOut:
    """Remove a policy; the response lists the scripts whose status it changed."""
    changes = await authorization.remove_policy(
        session, name, policy_id, actor=actor, reason=reason
    )
    return PolicyChangeOut(policy=None, scripts_changed=_changes(changes))


@router.get("/v1/sites/{name}/audit", responses=_ERRORS)
async def list_audit(
    name: str,
    session: Session,
    script_id: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
) -> AuditList:
    """The site's authorization audit trail, newest first."""
    site = await get_site(session, name)
    events = await audit.list_events(session, site.id, script_id=script_id, limit=limit)
    return AuditList(site=name, events=[AuditEventOut.of(e) for e in events])


@router.get("/v1/sites/{name}/audit/verify", responses=_ERRORS)
async def verify_audit(name: str, session: Session) -> ChainOut:
    """Recompute the trail's hash chain and report the first break, if any."""
    site = await get_site(session, name)
    report = await audit.verify_chain(session, site.id)
    return ChainOut(
        site=name,
        ok=report.ok,
        events=report.events,
        head_hash=report.head_hash,
        first_bad_seq=report.first_bad_seq,
        problem=report.problem,
    )
