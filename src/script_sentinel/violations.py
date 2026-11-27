"""Storing and reading CSP violation groups.

A report is never stored on its own. Each one is folded into the group its fingerprint
names (see ``csp_reports.Violation.fingerprint``) with a single upsert per group, so a
page that triggers the same violation for every visitor costs one row and a counter, and
the table grows with the number of distinct problems, not with traffic.

A site keeps at most ``max_groups`` groups. Once it has that many, reports for groups it
already has still count, and reports that would open a new group are dropped
(``group_limit``). The check is made per request, so concurrent requests can overshoot
the limit by a few groups; it bounds growth, it isn't an exact quota.
"""

from __future__ import annotations

import enum
import uuid
from collections import Counter
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.ext.asyncio import AsyncSession

from script_sentinel.csp_reports import DropReason, ParsedPayload, Violation, parse_payload
from script_sentinel.db.models import (
    CspDisposition,
    CspReportFormat,
    CspViolation,
    Site,
    utcnow,
)
from script_sentinel.sites import NotFoundError, get_site


class ViolationOrder(enum.StrEnum):
    LAST_SEEN = "last_seen"
    COUNT = "count"


@dataclass(frozen=True, slots=True)
class IngestLimits:
    max_reports: int = 100  # per request
    max_groups: int = 10_000  # per site


@dataclass(frozen=True, slots=True)
class IngestResult:
    site: str
    format: CspReportFormat
    received: int  # reports in the payload
    accepted: int  # reports counted towards a group
    groups_new: int
    groups_updated: int
    dropped: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "site": self.site,
            "format": self.format.value,
            "received": self.received,
            "accepted": self.accepted,
            "groups_new": self.groups_new,
            "groups_updated": self.groups_updated,
            "dropped": self.dropped,
        }


@dataclass(frozen=True, slots=True)
class ViolationPage:
    groups: list[CspViolation]
    total_groups: int  # matching the filters, before the limit
    total_reports: int  # the sum of their counts


@dataclass(frozen=True, slots=True)
class _Recorded:
    groups_new: int
    groups_updated: int
    over_limit: int  # reports dropped because their group would exceed max_groups


def _insert(dialect: str) -> Any:
    # Both dialects spell the upsert the same way; only the import differs.
    return postgresql.insert if dialect == "postgresql" else sqlite.insert


async def record(
    session: AsyncSession,
    site: Site,
    violations: list[Violation],
    *,
    max_groups: int,
    now: datetime | None = None,
) -> _Recorded:
    """Fold violations into the site's groups: one upsert per distinct fingerprint."""
    if not violations:
        return _Recorded(0, 0, 0)
    now = now or utcnow()
    batch: dict[str, tuple[Violation, int]] = {}
    for violation in violations:
        key = violation.fingerprint()
        seen = batch.get(key)
        if seen is None:
            batch[key] = (violation, 1)
        else:
            # The newest report decides the format shown; everything else is first-seen.
            batch[key] = (replace(seen[0], format=violation.format), seen[1] + 1)

    existing = set(
        await session.scalars(
            select(CspViolation.fingerprint).where(
                CspViolation.site_id == site.id, CspViolation.fingerprint.in_(batch)
            )
        )
    )
    total = (
        await session.scalar(
            select(func.count()).select_from(CspViolation).where(CspViolation.site_id == site.id)
        )
        or 0
    )
    room = max(0, max_groups - total)
    rows: list[dict[str, Any]] = []
    over_limit = 0
    new = 0
    for key, (violation, count) in batch.items():
        if key not in existing:
            if room == 0:
                over_limit += count
                continue
            room -= 1
            new += 1
        rows.append(_row(site.id, key, violation, count, now))
    if rows:
        insert = _insert(session.get_bind().dialect.name)
        stmt = insert(CspViolation).values(rows)
        stmt = stmt.on_conflict_do_update(
            index_elements=[CspViolation.site_id, CspViolation.fingerprint],
            set_={
                "count": CspViolation.count + stmt.excluded.count,
                "last_seen_at": stmt.excluded.last_seen_at,
                "report_format": stmt.excluded.report_format,
            },
        )
        await session.execute(stmt)
    return _Recorded(new, len(rows) - new, over_limit)


def _row(
    site_id: uuid.UUID, fingerprint: str, v: Violation, count: int, now: datetime
) -> dict[str, Any]:
    return {
        "id": uuid.uuid4(),
        "site_id": site_id,
        "fingerprint": fingerprint,
        "document_url": v.document_url,
        "effective_directive": v.effective_directive,
        "blocked": v.blocked.value,
        "blocked_kind": v.blocked.kind,
        "blocked_host": v.blocked.host,
        "disposition": v.disposition,
        "source_file": v.source_file,
        "line": v.line,
        "column": v.column,
        "status_code": v.status_code,
        "sample": v.sample,
        "original_policy": v.original_policy,
        "policy_sha256": v.policy_sha256,
        "report_format": v.format,
        "count": count,
        "first_seen_at": now,
        "last_seen_at": now,
    }


def _dropped(counter: Counter[DropReason]) -> dict[str, int]:
    return {reason.value: counter[reason] for reason in DropReason if counter[reason]}


async def ingest(
    session: AsyncSession,
    site: Site,
    parsed: ParsedPayload,
    *,
    limits: IngestLimits,
    now: datetime | None = None,
) -> IngestResult:
    """Record an already parsed payload for ``site``."""
    recorded = await record(session, site, parsed.violations, max_groups=limits.max_groups, now=now)
    dropped = Counter(parsed.dropped)
    if recorded.over_limit:
        dropped[DropReason.GROUP_LIMIT] += recorded.over_limit
    return IngestResult(
        site=site.name,
        format=parsed.format,
        received=parsed.received,
        accepted=len(parsed.violations) - recorded.over_limit,
        groups_new=recorded.groups_new,
        groups_updated=recorded.groups_updated,
        dropped=_dropped(dropped),
    )


async def ingest_payload(
    session: AsyncSession,
    site_name: str,
    body: bytes,
    content_type: str | None,
    *,
    limits: IngestLimits,
    now: datetime | None = None,
) -> IngestResult:
    """Parse a report payload and record it (the CLI's path; the API parses first so it
    can rate-limit by the number of reports before touching the database)."""
    site = await get_site(session, site_name)
    parsed = parse_payload(body, content_type, site.allowed_origins, max_reports=limits.max_reports)
    return await ingest(session, site, parsed, limits=limits, now=now)


async def list_violations(
    session: AsyncSession,
    site_name: str,
    *,
    directive: str | None = None,
    disposition: CspDisposition | None = None,
    blocked_host: str | None = None,
    since: datetime | None = None,
    order: ViolationOrder = ViolationOrder.LAST_SEEN,
    limit: int = 50,
) -> ViolationPage:
    """A site's violation groups, most recent (or most reported) first."""
    site = await get_site(session, site_name)
    conditions = [CspViolation.site_id == site.id]
    if directive is not None:
        conditions.append(CspViolation.effective_directive == directive.strip().lower())
    if disposition is not None:
        conditions.append(CspViolation.disposition == disposition)
    if blocked_host is not None:
        conditions.append(CspViolation.blocked_host == blocked_host.strip().lower())
    if since is not None:
        conditions.append(CspViolation.last_seen_at >= since)
    totals = (
        await session.execute(
            select(func.count(), func.coalesce(func.sum(CspViolation.count), 0)).where(*conditions)
        )
    ).one()
    ordering = (
        (CspViolation.count.desc(), CspViolation.last_seen_at.desc())
        if order is ViolationOrder.COUNT
        else (CspViolation.last_seen_at.desc(), CspViolation.count.desc())
    )
    groups = list(
        await session.scalars(
            select(CspViolation)
            .where(*conditions)
            .order_by(*ordering, CspViolation.id)
            .limit(max(1, limit))
        )
    )
    return ViolationPage(groups, total_groups=int(totals[0]), total_reports=int(totals[1]))


async def get_violation(
    session: AsyncSession, site_name: str, violation_id: uuid.UUID
) -> CspViolation:
    site = await get_site(session, site_name)
    group = await session.scalar(
        select(CspViolation).where(CspViolation.site_id == site.id, CspViolation.id == violation_id)
    )
    if group is None:
        raise NotFoundError(f"CSP violation {violation_id} not found for site {site_name!r}")
    return group
