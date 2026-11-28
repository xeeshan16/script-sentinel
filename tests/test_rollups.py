from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from script_sentinel import sites, violations
from script_sentinel.csp_reports import Blocked, Violation
from script_sentinel.db import make_engine, make_sessionmaker
from script_sentinel.db.models import (
    CspBlockedKind,
    CspDisposition,
    CspReportFormat,
    CspRollup,
    CspViolation,
    Site,
)
from script_sentinel.violations import Pending, RollupDimension, blocked_key, hour_bucket

ORIGIN = "https://shop.example.com"
T0 = datetime(2026, 11, 28, 10, 15, tzinfo=UTC)


def _v(
    blocked: str = "https://collect.skim.test/c",
    *,
    host: str | None = "collect.skim.test",
    kind: CspBlockedKind = CspBlockedKind.URL,
    directive: str = "connect-src",
    disposition: CspDisposition = CspDisposition.ENFORCE,
    fmt: CspReportFormat = CspReportFormat.REPORTING_API,
    page: str = "/checkout",
) -> Violation:
    return Violation(
        format=fmt,
        document_url=f"{ORIGIN}{page}",
        effective_directive=directive,
        blocked=Blocked(blocked, kind, host),
        disposition=disposition,
    )


INLINE = _v("inline", host=None, kind=CspBlockedKind.KEYWORD, directive="script-src-elem")


async def _site(session: AsyncSession, name: str = "shop") -> Site:
    await sites.create_site(session, name=name, allowed_origins=[ORIGIN], scan_interval_hours=24)
    return await sites.get_site(session, name)


async def _rollups(session: AsyncSession) -> list[tuple[datetime, str, str, str, int]]:
    rows = await session.scalars(
        select(CspRollup).order_by(
            CspRollup.bucket_start, CspRollup.effective_directive, CspRollup.blocked
        )
    )
    return [
        (r.bucket_start, r.effective_directive, r.blocked, r.disposition.value, r.count)
        for r in rows
    ]


def test_blocked_key_and_hour_bucket() -> None:
    assert blocked_key(_v()) == "collect.skim.test"
    assert blocked_key(INLINE) == "inline"
    assert blocked_key(_v("data:", host=None, kind=CspBlockedKind.SCHEME)) == "data:"
    assert blocked_key(_v("", host=None, kind=CspBlockedKind.NONE)) == "(none)"
    assert blocked_key(_v("weird thing", host=None, kind=CspBlockedKind.OTHER)) == "(other)"
    dubai = datetime(2026, 11, 28, 14, 59, 59, 999, tzinfo=UTC).astimezone(ZoneInfo("Asia/Dubai"))
    assert hour_bucket(dubai) == datetime(2026, 11, 28, 14, tzinfo=UTC)


async def test_a_batch_merges_requests_into_one_row_per_group(session: AsyncSession) -> None:
    site = await _site(session)
    batch = [
        Pending(site.id, T0, [_v(), _v(), INLINE]),
        Pending(site.id, T0 + timedelta(minutes=5), [_v(fmt=CspReportFormat.CSP_REPORT)]),
        Pending(site.id, T0 + timedelta(hours=1), [_v()]),
    ]
    result = await violations.write_batch(session, batch, max_groups=100)
    assert (result.accepted, result.over_limit, result.site_gone) == (5, 0, 0)
    w = result.sites[site.id]
    assert (w.groups_new, w.groups_updated, w.accepted) == (2, 0, 5)
    beacon = await session.scalar(
        select(CspViolation).where(CspViolation.effective_directive == "connect-src")
    )
    assert beacon is not None
    assert beacon.count == 4
    assert beacon.first_seen_at == T0
    assert beacon.last_seen_at == T0 + timedelta(hours=1)
    # The newest report decides the format (the CSP_REPORT one was in between).
    assert beacon.report_format is CspReportFormat.REPORTING_API
    ten, eleven = datetime(2026, 11, 28, 10, tzinfo=UTC), datetime(2026, 11, 28, 11, tzinfo=UTC)
    assert await _rollups(session) == [
        (ten, "connect-src", "collect.skim.test", "enforce", 3),
        (ten, "script-src-elem", "inline", "enforce", 1),
        (eleven, "connect-src", "collect.skim.test", "enforce", 1),
    ]


async def test_late_batches_keep_first_and_last_seen_in_order(session: AsyncSession) -> None:
    site = await _site(session)
    await violations.write_batch(session, [Pending(site.id, T0, [_v()])], max_groups=100)
    # A batch that arrives late (a retried flush, a lagging consumer) carries older and
    # newer reports: first_seen moves back, last_seen forward, and the format follows the
    # newest report only.
    older = Pending(site.id, T0 - timedelta(hours=2), [_v(fmt=CspReportFormat.CSP_REPORT)])
    result = await violations.write_batch(session, [older], max_groups=100)
    assert result.sites[site.id].groups_updated == 1
    group = await session.scalar(select(CspViolation))
    assert group is not None
    await session.refresh(group)
    assert (group.count, group.first_seen_at, group.last_seen_at) == (
        2,
        T0 - timedelta(hours=2),
        T0,
    )
    assert group.report_format is CspReportFormat.REPORTING_API
    newer = Pending(site.id, T0 + timedelta(hours=1), [_v(fmt=CspReportFormat.CSP_REPORT)])
    await violations.write_batch(session, [newer], max_groups=100)
    await session.refresh(group)
    assert (group.count, group.last_seen_at) == (3, T0 + timedelta(hours=1))
    assert group.report_format.value == "csp-report"
    assert [r[0].hour for r in await _rollups(session)] == [8, 10, 11]


async def test_the_group_cap_applies_per_site_and_skips_rollups(session: AsyncSession) -> None:
    shop = await _site(session)
    blog = await _site(session, "blog")
    batch = [
        Pending(shop.id, T0, [_v(), INLINE, _v(page="/other"), _v(page="/other")]),
        Pending(blog.id, T0, [_v(), INLINE]),
    ]
    result = await violations.write_batch(session, batch, max_groups=2)
    assert result.sites[shop.id].over_limit == 2  # /other would have been a third group
    assert result.sites[blog.id].over_limit == 0
    assert (result.accepted, result.over_limit) == (4, 2)
    rolled = await session.scalar(select(func.sum(CspRollup.count)))
    assert rolled == 4  # dropped reports aren't rolled up either


async def test_reports_for_a_deleted_site_are_dropped(session: AsyncSession) -> None:
    site = await _site(session)
    gone = uuid.uuid4()
    result = await violations.write_batch(
        session, [Pending(gone, T0, [_v(), _v()]), Pending(site.id, T0, [_v()])], max_groups=10
    )
    assert (result.site_gone, result.accepted) == (2, 1)
    assert gone not in result.sites
    assert await violations.write_batch(session, [], max_groups=10) == violations.BatchResult({}, 0)
    empty = await violations.write_batch(session, [Pending(site.id, T0, [])], max_groups=10)
    assert empty.accepted == 0


async def test_large_batches_are_written_in_chunks(session: AsyncSession) -> None:
    site = await _site(session)
    many = [_v(page=f"/p{i}") for i in range(1_234)]
    result = await violations.write_batch(session, [Pending(site.id, T0, many)], max_groups=5_000)
    assert result.sites[site.id].groups_new == 1_234
    again = await violations.write_batch(session, [Pending(site.id, T0, many)], max_groups=5_000)
    assert again.sites[site.id].groups_updated == 1_234
    total = await session.scalar(select(func.sum(CspViolation.count)))
    assert total == 2_468
    assert await _rollups(session) == [
        (hour_bucket(T0), "connect-src", "collect.skim.test", "enforce", 2_468)
    ]


async def _seed(session: AsyncSession) -> Site:
    site = await _site(session)
    report_only = _v(disposition=CspDisposition.REPORT)
    pixel = _v("https://px.ads.test/p.gif", host="px.ads.test", directive="img-src")
    batch = [
        # The previous 24h window: the beacon, and the pixel.
        Pending(site.id, T0 - timedelta(hours=30), [_v(), _v(), pixel]),
        # The current window.
        Pending(site.id, T0 - timedelta(hours=3), [_v(), _v(), _v(), report_only]),
        Pending(site.id, T0, [INLINE, INLINE, pixel]),
        # Older than both windows: ignored.
        Pending(site.id, T0 - timedelta(hours=60), [_v()] * 9),
    ]
    await violations.write_batch(session, batch, max_groups=100)
    return site


async def test_rollup_by_both_compares_with_the_window_before(session: AsyncSession) -> None:
    await _seed(session)
    report = await violations.rollup(session, "shop", hours=24, now=T0)
    assert report.window_start == datetime(2026, 11, 27, 11, tzinfo=UTC)
    assert report.window_end == datetime(2026, 11, 28, 11, tzinfo=UTC)
    assert (report.total, report.previous_total) == (7, 3)
    assert [r.to_dict() for r in report.rows] == [
        {
            "directive": "connect-src",
            "blocked": "collect.skim.test",
            "count": 4,
            "previous": 2,
            "new": False,
        },
        {
            "directive": "script-src-elem",
            "blocked": "inline",
            "count": 2,
            "previous": 0,
            "new": True,
        },
        {"directive": "img-src", "blocked": "px.ads.test", "count": 1, "previous": 1, "new": False},
    ]
    assert len(report.buckets) == 24
    assert sum(c for _, c in report.buckets) == 7
    assert report.buckets[-1] == (datetime(2026, 11, 28, 10, tzinfo=UTC), 3)
    assert report.buckets[-4] == (datetime(2026, 11, 28, 7, tzinfo=UTC), 4)
    data = report.to_dict()
    assert data["by"] == "both"
    assert data["buckets"][-1] == {"hour": "2026-11-28T10:00:00+00:00", "count": 3}


async def test_rollup_by_one_dimension_and_filters(session: AsyncSession) -> None:
    await _seed(session)
    by_directive = await violations.rollup(
        session, "shop", by=RollupDimension.DIRECTIVE, hours=24, now=T0
    )
    assert [(r.directive, r.blocked, r.count) for r in by_directive.rows] == [
        ("connect-src", None, 4),
        ("script-src-elem", None, 2),
        ("img-src", None, 1),
    ]
    by_blocked = await violations.rollup(
        session, "shop", by=RollupDimension.BLOCKED, hours=24, limit=1, now=T0
    )
    assert [(r.directive, r.blocked, r.count) for r in by_blocked.rows] == [
        (None, "collect.skim.test", 4)
    ]
    enforced = await violations.rollup(
        session, "shop", disposition=CspDisposition.ENFORCE, directive=" Connect-Src ", now=T0
    )
    assert (enforced.total, enforced.previous_total) == (3, 2)
    # A short window: only this hour, compared with the hour before.
    hour = await violations.rollup(session, "shop", hours=1, now=T0)
    assert (hour.total, hour.previous_total, len(hour.buckets)) == (3, 0, 1)
    # A window with nothing in it still has its buckets.
    later = await violations.rollup(session, "shop", hours=2, now=T0 + timedelta(days=30))
    assert (later.total, later.rows, [c for _, c in later.buckets]) == (0, [], [0, 0])


async def test_rollup_errors(session: AsyncSession) -> None:
    await _site(session)
    with pytest.raises(ValueError, match="hours must be between"):
        await violations.rollup(session, "shop", hours=0)
    with pytest.raises(ValueError, match="hours must be between"):
        await violations.rollup(session, "shop", hours=violations.MAX_WINDOW_HOURS + 1)
    with pytest.raises(sites.NotFoundError):
        await violations.rollup(session, "nope")


async def test_prune_deletes_old_buckets_and_site_delete_cascades(session: AsyncSession) -> None:
    await _seed(session)
    assert await violations.prune_rollups(session, before=T0 - timedelta(hours=48)) == 1
    assert await violations.prune_rollups(session, before=T0 - timedelta(hours=48)) == 0
    assert len(await _rollups(session)) == 6
    await session.commit()
    await sites.delete_site(session, "shop")
    await session.commit()
    assert await _rollups(session) == []


async def test_concurrent_writers_do_not_deadlock(database_url: str) -> None:
    """Writers whose batches overlap in opposite orders wait for each other instead of
    deadlocking (rows are upserted in key order)."""
    if not database_url.startswith("postgresql"):
        pytest.skip("SQLite has a single writer; row-lock order only matters on PostgreSQL")
    engine = make_engine(database_url, pool_size=12)
    maker = make_sessionmaker(engine)
    try:
        async with maker() as session, session.begin():
            site = await _site(session)
        pages = [_v(page=f"/p{i}") for i in range(40)]

        async def writer(n: int) -> None:
            ordered = pages if n % 2 else list(reversed(pages))
            mixed = [*ordered, INLINE, _v(directive=f"d{n % 3}-src")]
            for _ in range(5):
                async with maker() as session, session.begin():
                    await violations.write_batch(
                        session, [Pending(site.id, T0, mixed)], max_groups=1_000
                    )

        await asyncio.gather(*(writer(n) for n in range(10)))
        async with maker() as session:
            total = await session.scalar(select(func.sum(CspViolation.count)))
            rolled = await session.scalar(select(func.sum(CspRollup.count)))
        assert total == rolled == 10 * 5 * 42
    finally:
        await engine.dispose()
