"""Findings: raising them after a scan, and the workflow for handling them.

After a scan has recorded what each script served, :func:`detect` compares every script
with what it served at the end of the previous successful fetch
(``scripts.current_version_ids`` before the scan updated it):

* a script that serves a body it didn't serve last time raises ``script.changed`` (or
  ``script.reformatted`` when only comments or whitespace differ), with the token diff,
  size and entropy deltas and the hosts and URLs the new body references that the old one
  didn't. Going back to an earlier body counts too: it is a change from last time even
  though the body isn't new;
* a script that appears on a page that an earlier scan already inventoried raises
  ``script.added``. A page's first successful scan is its baseline: the scripts found
  there are recorded, not reported, so adding a page to monitoring doesn't flood the
  findings;
* except that a script on a page's first scan whose code the skimmer heuristics flag
  (a ``high`` verdict or worse) raises ``script.suspicious``, so a skimmer that was
  already running when monitoring started doesn't quietly become the baseline.

Every finding on a body carries the heuristics' evidence: for a change, the signals the new
body added and the verdicts on them; for a new or suspicious script, all of its signals
and verdicts. "Its own" destinations are the script's host and the site's origins.

The severity rules are in :mod:`script_sentinel.changes`. Handling a finding (acknowledge,
resolve, reopen) records who did it and why, and goes to the site's audit trail, so the
response to a change is evidence alongside the change itself (PCI DSS 11.6.1 asks for both).
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from script_sentinel import audit
from script_sentinel.authorization import validate_actor
from script_sentinel.changes import (
    Assessment,
    added_severity,
    analyze_change,
    change_severity,
    entropy,
    references,
    severity_at_least,
    suspicious_severity,
)
from script_sentinel.db.models import (
    Finding,
    FindingKind,
    FindingStatus,
    PageSnapshot,
    Scan,
    Script,
    ScriptKind,
    ScriptVersion,
    Severity,
    Site,
    SnapshotOutcome,
    utcnow,
)
from script_sentinel.diff import similarity
from script_sentinel.heuristics import Context, Report, Verdict, assess, inspect
from script_sentinel.sites import NotFoundError, ValidationError, get_site

MAX_NOTE = 2_000
MAX_STORED_SIGNALS = 50


@dataclass(slots=True)
class ScriptActivity:
    """What one script did in a scan, as far as change detection cares."""

    script: Script
    previous_ids: list[str]  # current_version_ids before the scan
    served_ids: set[uuid.UUID]  # bodies served this scan (empty if every fetch failed)
    is_new: bool  # first seen in this scan
    pages: set[str] = field(default_factory=set)
    payment_page: bool = False


@dataclass(frozen=True, slots=True)
class _Body:
    id: uuid.UUID
    sha384: str
    normalized_sha384: str | None
    size_bytes: int
    text: str
    approved: bool
    first_seen_at: datetime


async def _bodies(session: AsyncSession, ids: Iterable[uuid.UUID]) -> dict[uuid.UUID, _Body]:
    wanted = sorted(set(ids))
    out: dict[uuid.UUID, _Body] = {}
    for start in range(0, len(wanted), 500):
        rows = await session.execute(
            select(
                ScriptVersion.id,
                ScriptVersion.sha384,
                ScriptVersion.normalized_sha384,
                ScriptVersion.size_bytes,
                ScriptVersion.content,
                ScriptVersion.approved_at,
                ScriptVersion.first_seen_at,
            ).where(ScriptVersion.id.in_(wanted[start : start + 500]))
        )
        for row in rows:
            out[row[0]] = _Body(
                row[0], row[1], row[2], row[3], row[4] or "", row[5] is not None, row[6]
            )
    return out


def _closest(new: _Body, candidates: Sequence[_Body]) -> _Body:
    """The previous body to diff against: same normalized form first, then most similar."""
    for candidate in candidates:
        if new.normalized_sha384 and candidate.normalized_sha384 == new.normalized_sha384:
            return candidate
    if len(candidates) == 1:
        return candidates[0]
    return max(candidates, key=lambda c: (similarity(c.text, new.text), c.id))


def _pages_detail(activity: ScriptActivity) -> dict[str, Any]:
    return {"pages": sorted(activity.pages), "payment_page": activity.payment_page}


def _host(locator: str) -> str | None:
    try:
        return urlsplit(locator).hostname
    except ValueError:  # pragma: no cover - locators are URLs the scanner already parsed
        return None


def site_hosts(site: Site) -> frozenset[str]:
    """The hosts of the site's own origins."""
    return frozenset(h for h in (_host(origin) for origin in site.allowed_origins) if h)


def context_for(script: Script, site_hosts: frozenset[str]) -> Context:
    """What counts as the script's own destination: its host and the site's."""
    host = _host(script.locator) if script.kind is ScriptKind.EXTERNAL else None
    return Context(script_host=host, site_hosts=site_hosts)


def inspect_body(text: str, context: Context) -> tuple[Report, list[Verdict]]:
    report = inspect(text)
    return report, assess(report, context)


async def known_hosts(session: AsyncSession, site: Site) -> set[str]:
    """Hosts of the site's own origins and of every external script it has served."""
    locators = await session.scalars(
        select(Script.locator).where(Script.site_id == site.id, Script.kind == ScriptKind.EXTERNAL)
    )
    candidates = [*site.allowed_origins, *locators]
    return {h for h in (_host(value) for value in candidates) if h}


async def baseline_pages(session: AsyncSession, site_id: uuid.UUID) -> set[str]:
    """The page URLs of the site that some scan has already inventoried."""
    return set(
        await session.scalars(
            select(PageSnapshot.url)
            .join(Scan, Scan.id == PageSnapshot.scan_id)
            .where(Scan.site_id == site_id, PageSnapshot.outcome == SnapshotOutcome.OK)
            .distinct()
        )
    )


def _finding(
    scan: Scan,
    script: Script,
    kind: FindingKind,
    assessment: Assessment,
    title: str,
    detail: dict[str, Any],
    *,
    version_id: uuid.UUID | None,
    previous_version_id: uuid.UUID | None = None,
    created_at: datetime,
) -> Finding:
    return Finding(
        id=uuid.uuid4(),
        site_id=scan.site_id,
        script_id=script.id,
        version_id=version_id,
        previous_version_id=previous_version_id,
        scan_id=scan.id,
        locator=script.locator,
        kind=kind.value,
        severity=assessment.severity,
        status=FindingStatus.OPEN,
        title=title[:256],
        detail={"reasons": list(assessment.reasons), **detail},
        created_at=created_at,
    )


async def detect(
    session: AsyncSession,
    scan: Scan,
    activities: Sequence[ScriptActivity],
    *,
    baseline: set[str],
    hosts: set[str],
    own_hosts: frozenset[str] = frozenset(),
    clock: Callable[[], datetime] = utcnow,
) -> list[Finding]:
    """Raise the findings for one scan (see the module docs). Adds them to the session.

    ``baseline`` holds the pages inventoried before this scan (see
    :func:`baseline_pages`), ``hosts`` the hosts known before it (:func:`known_hosts`) and
    ``own_hosts`` the hosts of the site's origins (:func:`site_hosts`).
    """
    wanted: set[uuid.UUID] = set()
    for activity in activities:
        previous = {uuid.UUID(v) for v in activity.previous_ids}
        if previous and activity.served_ids - previous:
            wanted |= previous | activity.served_ids
        elif activity.is_new and activity.served_ids:
            wanted |= activity.served_ids
    bodies = await _bodies(session, wanted)
    now = clock()
    raised: list[Finding] = []
    for activity in sorted(activities, key=lambda a: a.script.locator):
        before = [bodies[uuid.UUID(v)] for v in activity.previous_ids if uuid.UUID(v) in bodies]
        context = context_for(activity.script, own_hosts)
        if activity.is_new:
            if activity.pages & baseline:
                raised.append(await _added(scan, activity, bodies, hosts, context, now))
            else:
                suspicious = await _suspicious(scan, activity, bodies, context, now)
                if suspicious is not None:
                    raised.append(suspicious)
            continue
        if not before:
            continue
        for new_id in sorted(activity.served_ids - {b.id for b in before}):
            new = bodies[new_id]
            old = _closest(new, before)
            raised.append(await _changed(scan, activity, old, new, context, now))
    for finding in raised:
        session.add(finding)
    return raised


def _served(activity: ScriptActivity, bodies: dict[uuid.UUID, _Body]) -> list[_Body]:
    return sorted((bodies[i] for i in activity.served_ids if i in bodies), key=lambda b: b.id)


def _heuristics_detail(report: Report, verdicts: Sequence[Verdict]) -> dict[str, Any]:
    return {
        "signals": [s.to_dict() for s in report.signals[:MAX_STORED_SIGNALS]],
        "signals_truncated": report.truncated or len(report.signals) > MAX_STORED_SIGNALS,
        "hidden_hosts": sorted(report.hidden_hosts),
        "verdicts": [v.to_dict() for v in verdicts],
    }


async def _added(
    scan: Scan,
    activity: ScriptActivity,
    bodies: dict[uuid.UUID, _Body],
    hosts: set[str],
    context: Context,
    now: datetime,
) -> Finding:
    script = activity.script
    inline = script.kind is ScriptKind.INLINE
    host = None if inline else _host(script.locator)
    detail: dict[str, Any] = {**_pages_detail(activity), "host": host}
    served = _served(activity, bodies)
    verdicts: list[Verdict] = []
    if served:
        body = served[0]
        refs = references(body.text)
        report, verdicts = await asyncio.to_thread(inspect_body, body.text, context)
        detail.update(
            sha384=body.sha384,
            size=body.size_bytes,
            entropy=entropy(body.text),
            hosts_referenced=sorted(refs.hosts | report.hidden_hosts),
            **_heuristics_detail(report, verdicts),
        )
    assessment = added_severity(
        inline=inline,
        new_host=host is not None and host not in hosts,
        payment_page=activity.payment_page,
        verdicts=verdicts,
    )
    where = "a payment page" if activity.payment_page else f"{len(activity.pages)} page(s)"
    what = "inline script" if inline else "external script"
    return _finding(
        scan,
        script,
        FindingKind.SCRIPT_ADDED,
        assessment,
        f"New {what} on {where}: {script.locator}",
        detail,
        version_id=served[0].id if served else None,
        created_at=now,
    )


async def _suspicious(
    scan: Scan,
    activity: ScriptActivity,
    bodies: dict[uuid.UUID, _Body],
    context: Context,
    now: datetime,
) -> Finding | None:
    """A script on a page's first scan that the heuristics flag, or ``None``."""
    served = _served(activity, bodies)
    if not served:
        return None
    body = served[0]
    report, verdicts = await asyncio.to_thread(inspect_body, body.text, context)
    assessment = suspicious_severity(verdicts, payment_page=activity.payment_page)
    if assessment is None:
        return None
    script = activity.script
    where = "a payment page" if activity.payment_page else f"{len(activity.pages)} page(s)"
    return _finding(
        scan,
        script,
        FindingKind.SCRIPT_SUSPICIOUS,
        assessment,
        f"Suspicious script on {where}: {script.locator}",
        {
            **_pages_detail(activity),
            "host": _host(script.locator) if script.kind is ScriptKind.EXTERNAL else None,
            "sha384": body.sha384,
            "size": body.size_bytes,
            **_heuristics_detail(report, verdicts),
        },
        version_id=body.id,
        created_at=now,
    )


async def _changed(
    scan: Scan,
    activity: ScriptActivity,
    old: _Body,
    new: _Body,
    context: Context,
    now: datetime,
) -> Finding:
    script = activity.script
    cosmetic = old.normalized_sha384 is not None and old.normalized_sha384 == new.normalized_sha384
    # The body existed before this scan: the script went back to something it served.
    reverted = new.first_seen_at < scan.started_at
    analysis = await asyncio.to_thread(
        analyze_change,
        old.text,
        new.text,
        old_size=old.size_bytes,
        new_size=new.size_bytes,
        context=context,
    )
    assessment = change_severity(
        analysis, cosmetic=cosmetic, reverted=reverted, payment_page=activity.payment_page
    )
    if cosmetic:
        kind, verb = FindingKind.SCRIPT_REFORMATTED, "reformatted (same code)"
    else:
        kind = FindingKind.SCRIPT_CHANGED
        verb = "went back to an earlier body" if reverted else "changed"
    detail = {
        **_pages_detail(activity),
        "from_sha384": old.sha384,
        "to_sha384": new.sha384,
        "reverted": reverted,
        "to_previously_approved": new.approved,
        **analysis.to_dict(),
    }
    return _finding(
        scan,
        script,
        kind,
        assessment,
        f"Script {verb}: {script.locator}",
        detail,
        version_id=new.id,
        previous_version_id=old.id,
        created_at=now,
    )


# --- Reading and handling findings -------------------------------------------------------


_ORDER = list(Severity)


async def list_findings(
    session: AsyncSession,
    site_name: str,
    *,
    status: FindingStatus | None = None,
    min_severity: Severity | None = None,
    scan_id: uuid.UUID | None = None,
    script_id: uuid.UUID | None = None,
    limit: int = 50,
) -> list[Finding]:
    """A site's findings, newest first, most severe first within a scan."""
    site = await get_site(session, site_name)
    query = select(Finding).where(Finding.site_id == site.id)
    if status is not None:
        query = query.where(Finding.status == status)
    if min_severity is not None:
        query = query.where(Finding.severity.in_(_ORDER[_ORDER.index(min_severity) :]))
    if scan_id is not None:
        query = query.where(Finding.scan_id == scan_id)
    if script_id is not None:
        query = query.where(Finding.script_id == script_id)
    rows = list(await session.scalars(query.order_by(Finding.created_at.desc(), Finding.id)))
    # Severity order isn't alphabetical, so the tie-break within a timestamp is done here.
    rows.sort(key=lambda f: (f.created_at, _ORDER.index(f.severity)), reverse=True)
    return rows[: max(1, limit)]


async def scan_findings(session: AsyncSession, scan_id: uuid.UUID) -> list[Finding]:
    rows = list(await session.scalars(select(Finding).where(Finding.scan_id == scan_id)))
    rows.sort(key=lambda f: (-_ORDER.index(f.severity), f.locator or "", str(f.id)))
    return rows


async def get_finding(session: AsyncSession, finding_id: uuid.UUID) -> tuple[Finding, str]:
    """A finding and the name of its site."""
    row = (
        await session.execute(
            select(Finding, Site.name)
            .join(Site, Site.id == Finding.site_id)
            .where(Finding.id == finding_id)
        )
    ).one_or_none()
    if row is None:
        raise NotFoundError(f"finding {finding_id} not found")
    return row[0], row[1]


# The statuses each status may move to.
_TRANSITIONS = {
    FindingStatus.OPEN: {FindingStatus.ACKNOWLEDGED, FindingStatus.RESOLVED},
    FindingStatus.ACKNOWLEDGED: {FindingStatus.RESOLVED, FindingStatus.OPEN},
    FindingStatus.RESOLVED: {FindingStatus.OPEN},
}
_ACTIONS = {
    FindingStatus.ACKNOWLEDGED: "finding.acknowledged",
    FindingStatus.RESOLVED: "finding.resolved",
    FindingStatus.OPEN: "finding.reopened",
}


async def set_status(
    session: AsyncSession,
    finding_id: uuid.UUID,
    status: FindingStatus,
    *,
    actor: str,
    note: str | None = None,
    clock: Callable[[], datetime] = utcnow,
) -> tuple[Finding, str]:
    """Acknowledge, resolve or reopen a finding, and record it in the audit trail.

    Resolving needs a note: it is the record of what was done about the change.
    """
    actor = validate_actor(actor)
    note = (note or "").strip() or None
    if note is not None and len(note) > MAX_NOTE:
        raise ValidationError(f"a note can be at most {MAX_NOTE} characters")
    if status is FindingStatus.RESOLVED and note is None:
        raise ValidationError("resolving a finding needs a note saying what was done")
    finding, site_name = await get_finding(session, finding_id)
    if status not in _TRANSITIONS[finding.status]:
        raise ValidationError(f"a finding that is {finding.status.value} can't be {status.value}")
    now = clock()
    previous = finding.status
    finding.status = status
    finding.status_changed_at = now
    finding.status_changed_by = actor
    finding.status_note = note
    finding.resolved_at = now if status is FindingStatus.RESOLVED else None
    await audit.AuditLog(session, finding.site_id, clock=clock).append(
        _ACTIONS[status],
        actor=actor,
        script_id=finding.script_id,
        locator=finding.locator,
        from_status=previous.value,
        to_status=status.value,
        reason=note,
        detail={
            "finding_id": str(finding.id),
            "kind": finding.kind,
            "severity": finding.severity.value,
        },
    )
    await session.flush()
    return finding, site_name


def worst(findings: Iterable[Finding]) -> Severity | None:
    severities = [f.severity for f in findings]
    if not severities:
        return None
    return max(severities, key=_ORDER.index)


def any_at_least(findings: Iterable[Finding], threshold: Severity) -> bool:
    return any(severity_at_least(f.severity, threshold) for f in findings)
