from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from script_sentinel import sites, violations
from script_sentinel.csp_reports import PayloadError, parse_payload
from script_sentinel.db.models import CspDisposition, CspReportFormat, CspViolation
from script_sentinel.violations import IngestLimits, ViolationOrder

ORIGIN = "https://shop.example.com"
LIMITS = IngestLimits(max_reports=50, max_groups=100)


def _report(**body: Any) -> dict[str, Any]:
    base = {
        "documentURL": f"{ORIGIN}/checkout",
        "effectiveDirective": "connect-src",
        "blockedURL": "https://collect.evil.test/c",
        "disposition": "enforce",
    }
    return {"type": "csp-violation", "body": {**base, **body}}


def _batch(*reports: dict[str, Any]) -> bytes:
    return json.dumps(list(reports)).encode()


async def _site(session: AsyncSession, name: str = "shop") -> None:
    await sites.create_site(session, name=name, allowed_origins=[ORIGIN], scan_interval_hours=24)


async def _ingest(
    session: AsyncSession, body: bytes, *, limits: IngestLimits = LIMITS, **kwargs: Any
) -> violations.IngestResult:
    return await violations.ingest_payload(
        session, "shop", body, "application/reports+json", limits=limits, **kwargs
    )


async def test_identical_reports_become_one_counted_group(session: AsyncSession) -> None:
    await _site(session)
    first = await _ingest(
        session,
        _batch(
            _report(),
            _report(documentURL=f"{ORIGIN}/checkout?step=2"),
            _report(blockedURL="inline", effectiveDirective="script-src-elem", lineNumber=3),
        ),
    )
    assert (first.received, first.accepted, first.groups_new, first.groups_updated) == (3, 3, 2, 0)
    assert first.format is CspReportFormat.REPORTING_API
    second = await _ingest(session, _batch(_report(), _report()))
    assert (second.groups_new, second.groups_updated) == (0, 1)
    page = await violations.list_violations(session, "shop", order=ViolationOrder.COUNT)
    assert (page.total_groups, page.total_reports) == (2, 5)
    top = page.groups[0]
    assert (top.count, top.blocked_host, top.document_url) == (
        4,
        "collect.evil.test",
        f"{ORIGIN}/checkout",
    )
    assert top.last_seen_at >= top.first_seen_at


async def test_counts_and_timestamps_move_on_conflict(session: AsyncSession) -> None:
    await _site(session)
    t0 = datetime(2026, 11, 27, 9, 0, tzinfo=UTC)
    await _ingest(session, _batch(_report()), now=t0)
    await _ingest(session, _batch(_report(), _report()), now=t0 + timedelta(hours=2))
    await session.commit()
    session.expire_all()
    (group,) = (await violations.list_violations(session, "shop")).groups
    assert group.count == 3
    assert group.first_seen_at == t0
    assert group.last_seen_at == t0 + timedelta(hours=2)


async def test_the_newest_report_decides_the_format(session: AsyncSession) -> None:
    await _site(session)
    legacy = {
        "csp-report": {
            "document-uri": f"{ORIGIN}/checkout",
            "effective-directive": "connect-src",
            "blocked-uri": "https://collect.evil.test/c",
            "disposition": "enforce",
        }
    }
    await violations.ingest_payload(
        session, "shop", json.dumps(legacy).encode(), "application/csp-report", limits=LIMITS
    )
    await _ingest(session, _batch(_report()))
    session.expire_all()
    (group,) = (await violations.list_violations(session, "shop")).groups
    assert (group.count, group.report_format) == (2, CspReportFormat.REPORTING_API)


async def test_a_batch_mixing_formats_keeps_the_last(session: AsyncSession) -> None:
    await _site(session)
    site = await sites.get_site(session, "shop")
    legacy = parse_payload(
        json.dumps(
            {
                "csp-report": {
                    "document-uri": f"{ORIGIN}/checkout",
                    "effective-directive": "connect-src",
                    "blocked-uri": "https://collect.evil.test/c",
                    "disposition": "enforce",
                }
            }
        ).encode(),
        "application/csp-report",
        [ORIGIN],
        max_reports=5,
    ).violations
    modern = parse_payload(_batch(_report()), "application/json", [ORIGIN], max_reports=5)
    recorded = await violations.record(session, site, legacy + modern.violations, max_groups=10)
    assert (recorded.groups_new, recorded.groups_updated, recorded.over_limit) == (1, 0, 0)
    (group,) = (await violations.list_violations(session, "shop")).groups
    assert (group.count, group.report_format) == (2, CspReportFormat.REPORTING_API)


async def test_dropped_reports_are_counted_by_reason(session: AsyncSession) -> None:
    await _site(session)
    result = await _ingest(
        session,
        _batch(
            _report(),
            {"type": "deprecation", "body": {}},
            _report(documentURL="https://evil.test/"),
            _report(blockedURL="chrome-extension://x/y.js"),
            _report(effectiveDirective="!!"),
        ),
    )
    assert result.accepted == 1
    assert result.dropped == {
        "invalid": 1,
        "not_csp": 1,
        "foreign_document": 1,
        "extension": 1,
    }
    assert result.to_dict()["dropped"] == result.dropped


async def test_a_payload_with_nothing_to_record(session: AsyncSession) -> None:
    await _site(session)
    result = await _ingest(session, _batch({"type": "intervention", "body": {}}))
    assert (result.accepted, result.groups_new, result.dropped) == (0, 0, {"not_csp": 1})
    assert (await violations.list_violations(session, "shop")).total_groups == 0


async def test_the_group_limit_keeps_counting_known_groups(session: AsyncSession) -> None:
    await _site(session)
    limits = IngestLimits(max_reports=50, max_groups=2)
    await _ingest(session, _batch(_report(lineNumber=1), _report(lineNumber=2)), limits=limits)
    result = await _ingest(
        session,
        _batch(_report(lineNumber=1), _report(lineNumber=3), _report(lineNumber=3)),
        limits=limits,
    )
    assert (result.accepted, result.groups_new, result.groups_updated) == (1, 0, 1)
    assert result.dropped == {"group_limit": 2}
    count = await session.scalar(select(func.count()).select_from(CspViolation))
    assert count == 2


async def test_a_full_site_with_only_new_groups_writes_nothing(session: AsyncSession) -> None:
    await _site(session)
    limits = IngestLimits(max_reports=50, max_groups=1)
    await _ingest(session, _batch(_report(lineNumber=1)), limits=limits)
    result = await _ingest(session, _batch(_report(lineNumber=2)), limits=limits)
    assert (result.accepted, result.groups_new, result.groups_updated) == (0, 0, 0)
    assert result.dropped == {"group_limit": 1}


async def test_the_group_limit_admits_new_groups_up_to_the_room_left(
    session: AsyncSession,
) -> None:
    await _site(session)
    limits = IngestLimits(max_reports=50, max_groups=2)
    result = await _ingest(
        session, _batch(*(_report(lineNumber=n) for n in range(5))), limits=limits
    )
    assert (result.groups_new, result.accepted, result.dropped) == (2, 2, {"group_limit": 3})


async def test_groups_belong_to_their_site(session: AsyncSession) -> None:
    await _site(session)
    await _site(session, "blog")
    await _ingest(session, _batch(_report()))
    await violations.ingest_payload(
        session, "blog", _batch(_report()), "application/json", limits=LIMITS
    )
    for name in ("shop", "blog"):
        page = await violations.list_violations(session, name)
        assert (page.total_groups, page.total_reports) == (1, 1)


async def test_listing_filters_and_orders(session: AsyncSession) -> None:
    await _site(session)
    t0 = datetime(2026, 11, 27, 9, 0, tzinfo=UTC)
    await _ingest(session, _batch(_report(), _report(), _report()), now=t0)
    await _ingest(
        session,
        _batch(
            _report(
                effectiveDirective="script-src-elem",
                blockedURL="https://cdn.vendor.test/x.js",
                disposition="report",
            )
        ),
        now=t0 + timedelta(minutes=5),
    )

    async def blocked(**kwargs: Any) -> list[str]:
        page = await violations.list_violations(session, "shop", **kwargs)
        return [g.blocked for g in page.groups]

    evil, vendor = "https://collect.evil.test/c", "https://cdn.vendor.test/x.js"
    assert await blocked() == [vendor, evil]
    assert await blocked(order=ViolationOrder.COUNT) == [evil, vendor]
    assert await blocked(directive=" Script-Src-Elem ") == [vendor]
    assert await blocked(disposition=CspDisposition.ENFORCE) == [evil]
    assert await blocked(blocked_host="COLLECT.evil.test") == [evil]
    assert await blocked(since=t0 + timedelta(minutes=1)) == [vendor]
    assert await blocked(limit=1) == [vendor]
    page = await violations.list_violations(session, "shop", limit=1)
    assert (page.total_groups, page.total_reports) == (2, 4)


async def test_getting_one_group(session: AsyncSession) -> None:
    await _site(session)
    await _site(session, "blog")
    await _ingest(session, _batch(_report(originalPolicy="connect-src 'self'")))
    (group,) = (await violations.list_violations(session, "shop")).groups
    found = await violations.get_violation(session, "shop", group.id)
    assert found.original_policy == "connect-src 'self'"
    with pytest.raises(sites.NotFoundError, match="not found"):
        await violations.get_violation(session, "blog", group.id)
    with pytest.raises(sites.NotFoundError, match="not found"):
        await violations.get_violation(session, "shop", uuid.uuid4())


async def test_unknown_sites_and_bad_payloads(session: AsyncSession) -> None:
    with pytest.raises(sites.NotFoundError):
        await _ingest(session, _batch(_report()))
    with pytest.raises(sites.NotFoundError):
        await violations.list_violations(session, "shop")
    await _site(session)
    with pytest.raises(PayloadError):
        await _ingest(session, b"{")


async def test_deleting_a_site_deletes_its_groups(session: AsyncSession) -> None:
    await _site(session)
    await _ingest(session, _batch(_report()))
    await session.commit()
    await sites.delete_site(session, "shop")
    await session.commit()
    assert await session.scalar(select(func.count()).select_from(CspViolation)) == 0
