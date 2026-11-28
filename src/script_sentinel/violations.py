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
from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import case, delete, func, select
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.ext.asyncio import AsyncSession

from script_sentinel.csp_reports import DropReason, ParsedPayload, Violation, parse_payload
from script_sentinel.db.models import (
    CspBlockedKind,
    CspDisposition,
    CspReportFormat,
    CspRollup,
    CspViolation,
    Site,
    utcnow,
)
from script_sentinel.sites import NotFoundError, get_site


class RollupDimension(enum.StrEnum):
    DIRECTIVE = "directive"
    BLOCKED = "blocked"
    BOTH = "both"


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
    accepted: int  # reports counted towards a group (or queued to be)
    groups_new: int | None  # None when queued: known once written
    groups_updated: int | None
    dropped: dict[str, int]
    mode: str = "direct"

    def to_dict(self) -> dict[str, Any]:
        return {
            "site": self.site,
            "format": self.format.value,
            "mode": self.mode,
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


@dataclass(frozen=True, slots=True)
class Pending:
    """Violations accepted for one site at one moment, waiting to be written.

    ``received_at`` is when the collector accepted them, not when they are written, so a
    buffered or queued report still lands in the hour it arrived.
    """

    site_id: uuid.UUID
    received_at: datetime
    violations: Sequence[Violation]


@dataclass(frozen=True, slots=True)
class SiteWrite:
    groups_new: int
    groups_updated: int
    accepted: int  # reports counted towards a group
    over_limit: int  # reports dropped because their group would exceed max_groups


@dataclass(frozen=True, slots=True)
class BatchResult:
    sites: dict[uuid.UUID, SiteWrite]
    site_gone: int  # reports for sites deleted before they were written

    @property
    def accepted(self) -> int:
        return sum(w.accepted for w in self.sites.values())

    @property
    def over_limit(self) -> int:
        return sum(w.over_limit for w in self.sites.values())


@dataclass(slots=True)
class _Merged:
    violation: Violation  # the first report, with the format of the newest
    count: int
    first: datetime
    last: datetime
    buckets: Counter[datetime]


# Rows per INSERT statement: well under SQLite's and asyncpg's bound-parameter limits.
_CHUNK = 500


def _insert(dialect: str) -> Any:
    # Both dialects spell the upsert the same way; only the import differs.
    return postgresql.insert if dialect == "postgresql" else sqlite.insert


def _greatest(dialect: str, a: Any, b: Any) -> Any:
    # SQLite's two-argument max() and min() are scalar functions.
    return func.greatest(a, b) if dialect == "postgresql" else func.max(a, b)


def _least(dialect: str, a: Any, b: Any) -> Any:
    return func.least(a, b) if dialect == "postgresql" else func.min(a, b)


def hour_bucket(moment: datetime) -> datetime:
    """The start of the UTC hour ``moment`` falls in."""
    return moment.astimezone(UTC).replace(minute=0, second=0, microsecond=0)


def blocked_key(violation: Violation) -> str:
    """What a rollup groups a blocked resource by: its host, or the keyword or scheme."""
    blocked = violation.blocked
    if blocked.host:
        return blocked.host
    if blocked.kind is CspBlockedKind.NONE:
        return "(none)"
    if blocked.kind is CspBlockedKind.OTHER:
        return "(other)"
    return blocked.value[:255]


def _merge(batch: Sequence[Pending]) -> dict[uuid.UUID, dict[str, _Merged]]:
    merged: dict[uuid.UUID, dict[str, _Merged]] = {}
    for pending in batch:
        groups = merged.setdefault(pending.site_id, {})
        bucket = hour_bucket(pending.received_at)
        for violation in pending.violations:
            key = violation.fingerprint()
            seen = groups.get(key)
            if seen is None:
                groups[key] = _Merged(
                    violation, 1, pending.received_at, pending.received_at, Counter({bucket: 1})
                )
                continue
            seen.count += 1
            seen.buckets[bucket] += 1
            seen.first = min(seen.first, pending.received_at)
            if pending.received_at >= seen.last:
                # The newest report decides the format shown; everything else is first-seen.
                seen.last = pending.received_at
                seen.violation = replace(seen.violation, format=violation.format)
    return merged


async def write_batch(
    session: AsyncSession, batch: Sequence[Pending], *, max_groups: int
) -> BatchResult:
    """Fold pending violations into groups and hourly rollups.

    Reports are merged in memory first, so however many requests a batch holds, each
    distinct group costs one row in one upsert, and so does each rollup key. Reports for a
    site that no longer exists are counted as ``site_gone`` and dropped.
    """
    merged = _merge(batch)
    if not merged:
        return BatchResult({}, 0)
    present = set(await session.scalars(select(Site.id).where(Site.id.in_(merged))))
    site_gone = sum(
        m.count
        for site_id, groups in merged.items()
        if site_id not in present
        for m in groups.values()
    )
    totals: dict[uuid.UUID, int] = {
        site_id: int(count)
        for site_id, count in (
            await session.execute(
                select(CspViolation.site_id, func.count())
                .where(CspViolation.site_id.in_(present))
                .group_by(CspViolation.site_id)
            )
        )
    }
    dialect = session.get_bind().dialect.name
    group_rows: list[dict[str, Any]] = []
    rollups: Counter[tuple[uuid.UUID, datetime, str, str, CspDisposition]] = Counter()
    written: dict[uuid.UUID, SiteWrite] = {}
    for site_id, groups in merged.items():
        if site_id not in present:
            continue
        existing = await _existing(session, site_id, list(groups))
        room = max(0, max_groups - totals.get(site_id, 0))
        new = updated = accepted = over_limit = 0
        for key, m in groups.items():
            if key not in existing:
                if room == 0:
                    over_limit += m.count
                    continue
                room -= 1
                new += 1
            else:
                updated += 1
            accepted += m.count
            group_rows.append(_row(site_id, key, m))
            v = m.violation
            for bucket, count in m.buckets.items():
                rollups[
                    (site_id, bucket, v.effective_directive, blocked_key(v), v.disposition)
                ] += count
        written[site_id] = SiteWrite(new, updated, accepted, over_limit)
    # Rows go in key order: concurrent writers then take their row locks in the same
    # order and wait for each other instead of deadlocking.
    group_rows.sort(key=lambda row: (str(row["site_id"]), row["fingerprint"]))
    await _upsert_groups(session, dialect, group_rows)
    await _upsert_rollups(session, dialect, rollups)
    return BatchResult(written, site_gone)


async def _existing(session: AsyncSession, site_id: uuid.UUID, keys: list[str]) -> set[str]:
    found: set[str] = set()
    for i in range(0, len(keys), _CHUNK):
        found.update(
            await session.scalars(
                select(CspViolation.fingerprint).where(
                    CspViolation.site_id == site_id,
                    CspViolation.fingerprint.in_(keys[i : i + _CHUNK]),
                )
            )
        )
    return found


async def _upsert_groups(session: AsyncSession, dialect: str, rows: list[dict[str, Any]]) -> None:
    table = CspViolation.__table__
    for i in range(0, len(rows), _CHUNK):
        stmt = _insert(dialect)(table).values(rows[i : i + _CHUNK])
        excluded = stmt.excluded
        stmt = stmt.on_conflict_do_update(
            index_elements=[table.c.site_id, table.c.fingerprint],
            set_={
                "count": table.c.count + excluded.count,
                "first_seen_at": _least(dialect, table.c.first_seen_at, excluded.first_seen_at),
                "last_seen_at": _greatest(dialect, table.c.last_seen_at, excluded.last_seen_at),
                # Out-of-order delivery (a queue, a retried flush) mustn't let an older
                # report decide the format shown.
                "report_format": case(
                    (excluded.last_seen_at >= table.c.last_seen_at, excluded.report_format),
                    else_=table.c.report_format,
                ),
            },
        )
        await session.execute(stmt)


async def _upsert_rollups(
    session: AsyncSession,
    dialect: str,
    rollups: Counter[tuple[uuid.UUID, datetime, str, str, CspDisposition]],
) -> None:
    rows = [
        {
            "id": uuid.uuid4(),
            "site_id": site_id,
            "bucket_start": bucket,
            "effective_directive": directive,
            "blocked": blocked,
            "disposition": disposition,
            "count": count,
        }
        for (site_id, bucket, directive, blocked, disposition), count in sorted(
            rollups.items(), key=lambda item: (str(item[0][0]), *item[0][1:])
        )
    ]
    table = CspRollup.__table__
    for i in range(0, len(rows), _CHUNK):
        stmt = _insert(dialect)(table).values(rows[i : i + _CHUNK])
        stmt = stmt.on_conflict_do_update(
            index_elements=[
                table.c.site_id,
                table.c.bucket_start,
                table.c.effective_directive,
                table.c.blocked,
                table.c.disposition,
            ],
            set_={"count": table.c.count + stmt.excluded.count},
        )
        await session.execute(stmt)


async def record(
    session: AsyncSession,
    site: Site,
    violations: list[Violation],
    *,
    max_groups: int,
    now: datetime | None = None,
) -> _Recorded:
    """Fold violations reported together into the site's groups and rollups."""
    if not violations:
        return _Recorded(0, 0, 0)
    result = await write_batch(
        session, [Pending(site.id, now or utcnow(), violations)], max_groups=max_groups
    )
    w = result.sites[site.id]
    return _Recorded(w.groups_new, w.groups_updated, w.over_limit)


def _row(site_id: uuid.UUID, fingerprint: str, m: _Merged) -> dict[str, Any]:
    v = m.violation
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
        "count": m.count,
        "first_seen_at": m.first,
        "last_seen_at": m.last,
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
    """Record an already parsed payload for ``site`` in this transaction."""
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


def queued(site: Site, parsed: ParsedPayload, *, mode: str) -> IngestResult:
    """What the collector answers when the reports were handed to a buffer or a queue:
    group counts and group-limit drops are only known once they are written."""
    return IngestResult(
        site=site.name,
        format=parsed.format,
        received=parsed.received,
        accepted=len(parsed.violations),
        groups_new=None,
        groups_updated=None,
        dropped=_dropped(Counter(parsed.dropped)),
        mode=mode,
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


# --- Rolling aggregates -----------------------------------------------------------------------

MAX_WINDOW_HOURS = 24 * 31


@dataclass(frozen=True, slots=True)
class RollupRow:
    directive: str | None
    blocked: str | None
    count: int  # in the window
    previous: int  # in the window of the same length before it

    @property
    def new(self) -> bool:
        """Nothing like it in the previous window."""
        return self.previous == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "directive": self.directive,
            "blocked": self.blocked,
            "count": self.count,
            "previous": self.previous,
            "new": self.new,
        }


@dataclass(frozen=True, slots=True)
class RollupReport:
    site: str
    by: RollupDimension
    hours: int
    window_start: datetime  # the first hour bucket in the window
    window_end: datetime  # the end of the current hour
    total: int
    previous_total: int
    rows: list[RollupRow]
    buckets: list[tuple[datetime, int]]  # every hour of the window, oldest first

    def to_dict(self) -> dict[str, Any]:
        return {
            "site": self.site,
            "by": self.by.value,
            "hours": self.hours,
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "total": self.total,
            "previous_total": self.previous_total,
            "rows": [r.to_dict() for r in self.rows],
            "buckets": [{"hour": h.isoformat(), "count": c} for h, c in self.buckets],
        }


async def rollup(
    session: AsyncSession,
    site_name: str,
    *,
    by: RollupDimension = RollupDimension.BOTH,
    hours: int = 24,
    directive: str | None = None,
    disposition: CspDisposition | None = None,
    limit: int = 20,
    now: datetime | None = None,
) -> RollupReport:
    """The site's accepted reports over the last ``hours`` hour buckets, by directive,
    blocked host (or keyword) or both, each with its count in the window before.

    The window is whole UTC hours and includes the current one, so ``hours=24`` covers
    between 23 and 24 hours of traffic.
    """
    if not 1 <= hours <= MAX_WINDOW_HOURS:
        raise ValueError(f"hours must be between 1 and {MAX_WINDOW_HOURS}")
    site = await get_site(session, site_name)
    current = hour_bucket(now or utcnow())
    start = current - timedelta(hours=hours - 1)
    previous_start = start - timedelta(hours=hours)
    conditions = [
        CspRollup.site_id == site.id,
        CspRollup.bucket_start >= previous_start,
        CspRollup.bucket_start <= current,
    ]
    if directive is not None:
        conditions.append(CspRollup.effective_directive == directive.strip().lower())
    if disposition is not None:
        conditions.append(CspRollup.disposition == disposition)
    in_window = func.coalesce(
        func.sum(case((CspRollup.bucket_start >= start, CspRollup.count), else_=0)), 0
    )
    before = func.coalesce(
        func.sum(case((CspRollup.bucket_start < start, CspRollup.count), else_=0)), 0
    )
    dims = {
        RollupDimension.DIRECTIVE: [CspRollup.effective_directive],
        RollupDimension.BLOCKED: [CspRollup.blocked],
        RollupDimension.BOTH: [CspRollup.effective_directive, CspRollup.blocked],
    }[by]
    totals = (await session.execute(select(in_window, before).where(*conditions))).one()
    grouped = await session.execute(
        select(*dims, in_window, before)
        .where(*conditions)
        .group_by(*dims)
        .having(in_window > 0)
        .order_by(in_window.desc(), *dims)
        .limit(max(1, limit))
    )
    rows: list[RollupRow] = []
    for row in grouped:
        values = dict(zip([d.key for d in dims], row[: len(dims)], strict=True))
        rows.append(
            RollupRow(
                directive=values.get("effective_directive"),
                blocked=values.get("blocked"),
                count=int(row[-2]),
                previous=int(row[-1]),
            )
        )
    per_hour = {
        hour_bucket(bucket): int(count)
        for bucket, count in (
            await session.execute(
                select(CspRollup.bucket_start, func.sum(CspRollup.count))
                .where(*conditions, CspRollup.bucket_start >= start)
                .group_by(CspRollup.bucket_start)
            )
        )
    }
    buckets = [
        (start + timedelta(hours=i), per_hour.get(start + timedelta(hours=i), 0))
        for i in range(hours)
    ]
    return RollupReport(
        site=site.name,
        by=by,
        hours=hours,
        window_start=start,
        window_end=current + timedelta(hours=1),
        total=int(totals[0]),
        previous_total=int(totals[1]),
        rows=rows,
        buckets=buckets,
    )


async def prune_rollups(session: AsyncSession, *, before: datetime) -> int:
    """Delete rollup buckets that start before ``before``; returns how many."""
    result = await session.execute(delete(CspRollup).where(CspRollup.bucket_start < before))
    return int(getattr(result, "rowcount", 0) or 0)
