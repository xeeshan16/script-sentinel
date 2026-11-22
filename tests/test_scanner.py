from __future__ import annotations

import hashlib
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from script_sentinel import scanner, sites
from script_sentinel.db.models import (
    AuthorizationStatus,
    PageSnapshot,
    Scan,
    ScanStatus,
    ScanTrigger,
    ScriptKind,
    ScriptObservation,
    ScriptType,
    SnapshotOutcome,
)
from script_sentinel.fetch import PageFetcher
from tests.conftest import FixtureSite

VENDOR = "https://cdn.vendor.test/widget.js"

CHECKOUT = f"""<!doctype html><html><head>
<script nonce="n1">window.checkoutConfig = {{currency: "EUR"}};</script>
<script src="/js/app.js" defer></script>
<script src="{VENDOR}" integrity="sha384-AAAA" crossorigin="anonymous" async></script>
<script type="module" src="/js/checkout.mjs"></script>
<script type="application/ld+json">{{"@type": "WebPage"}}</script>
</head><body><form id="pay"></form></body></html>"""

HOME = f"""<html><head><script src="/js/app.js"></script>
<script src="{VENDOR}"></script></head><body><script>track("home")</script></body></html>"""


def clock_from(start: datetime) -> Callable[[], datetime]:
    ticks: Iterator[int] = iter(range(10_000))
    return lambda: start + timedelta(seconds=next(ticks))


async def _shop(session: AsyncSession, site: FixtureSite, *, respect_robots: bool = True) -> None:
    await sites.create_site(
        session,
        name="shop",
        allowed_origins=[site.origin],
        scan_interval_hours=24,
        respect_robots=respect_robots,
    )
    await sites.add_page(session, "shop", url=site.url("/checkout"), payment_page=True)
    await sites.add_page(session, "shop", url=site.url("/"), label="home")


async def _scan(session: AsyncSession, **kwargs: object) -> Scan:
    async with PageFetcher() as fetcher:
        return await scanner.scan_site(
            session,
            "shop",
            fetcher,
            trigger=ScanTrigger.CLI,
            **kwargs,  # type: ignore[arg-type]
        )


async def test_scan_records_snapshots_and_builds_the_inventory(
    session: AsyncSession, fixture_site: FixtureSite
) -> None:
    fixture_site.page("/checkout", CHECKOUT)
    fixture_site.page("/", HOME)
    await _shop(session, fixture_site)
    start = datetime(2026, 11, 22, 9, 0, tzinfo=UTC)

    scan = await _scan(session, clock=clock_from(start))

    assert scan.status is ScanStatus.COMPLETED
    assert scan.trigger is ScanTrigger.CLI
    assert (scan.pages_total, scan.pages_ok, scan.pages_skipped, scan.pages_failed) == (2, 2, 0, 0)
    # checkout: inline, app.js, vendor, module; home adds its own inline block (app.js and
    # the vendor script are shared).
    assert (scan.scripts_seen, scan.scripts_new) == (5, 5)
    assert scan.started_at == start
    assert scan.finished_at is not None
    assert scan.finished_at > scan.started_at

    detailed, site_name = await scanner.get_scan(session, scan.id)
    assert site_name == "shop"
    home, checkout = detailed.snapshots  # ordered by URL: "/" sorts before "/checkout"
    assert checkout.url == fixture_site.url("/checkout")
    assert checkout.payment_page
    assert checkout.outcome is SnapshotOutcome.OK
    assert checkout.http_status == 200
    assert checkout.body_sha384 == hashlib.sha384(CHECKOUT.encode()).hexdigest()
    assert checkout.script_count == 4
    assert checkout.data_block_count == 1
    assert checkout.warnings == []
    assert [(o.position, o.script.locator) for o in checkout.observations] == [
        (1, fixture_site.url("/checkout#inline-1")),
        (2, fixture_site.url("/js/app.js")),
        (3, VENDOR),
        (4, fixture_site.url("/js/checkout.mjs")),
    ]
    inline, app, vendor, module = checkout.observations
    assert (
        inline.inline_sha384
        == hashlib.sha384(b'window.checkoutConfig = {currency: "EUR"};').hexdigest()
    )
    assert inline.nonce_digest == hashlib.sha256(b"n1").hexdigest()[:16]
    assert app.is_defer
    assert app.inline_sha384 is None
    assert (vendor.integrity, vendor.crossorigin, vendor.is_async) == (
        "sha384-AAAA",
        "anonymous",
        True,
    )
    assert module.script_type is ScriptType.MODULE
    assert home.payment_page is False
    assert home.script_count == 3

    inventory = await scanner.list_scripts(session, "shop")
    # External scripts first (ordering within a kind follows the database collation).
    assert [s.kind for s in inventory] == [ScriptKind.EXTERNAL] * 3 + [ScriptKind.INLINE] * 2
    assert {s.locator for s in inventory} == {
        VENDOR,
        fixture_site.url("/js/app.js"),
        fixture_site.url("/js/checkout.mjs"),
        fixture_site.url("/#inline-1"),
        fixture_site.url("/checkout#inline-1"),
    }
    assert len(inventory) == 5
    assert {s.status for s in inventory} == {AuthorizationStatus.PENDING}
    shared = next(s for s in inventory if s.locator == VENDOR)
    observed_on = await session.scalar(
        select(func.count())
        .select_from(ScriptObservation)
        .where(ScriptObservation.script_id == shared.id)
    )
    assert observed_on == 2  # one script, observed on both pages


async def test_rescanning_updates_the_inventory_instead_of_duplicating_it(
    session: AsyncSession, fixture_site: FixtureSite
) -> None:
    fixture_site.page("/checkout", CHECKOUT)
    fixture_site.page("/", HOME)
    await _shop(session, fixture_site)
    first = await _scan(session, clock=clock_from(datetime(2026, 11, 22, 9, tzinfo=UTC)))
    ids = {s.locator: s.id for s in await scanner.list_scripts(session, "shop")}

    # The inline config changes and the vendor script disappears from the home page.
    fixture_site.page("/checkout", CHECKOUT.replace('"EUR"', '"USD"'))
    fixture_site.page("/", '<script src="/js/app.js"></script>')
    later = datetime(2026, 11, 23, 9, tzinfo=UTC)
    second = await _scan(session, clock=clock_from(later))

    assert (second.scripts_seen, second.scripts_new) == (4, 0)
    inventory = {s.locator: s for s in await scanner.list_scripts(session, "shop")}
    assert {loc: s.id for loc, s in inventory.items()} == ids  # same rows, no duplicates
    assert inventory[fixture_site.url("/#inline-1")].last_seen_at < later  # not seen again
    assert inventory[VENDOR].last_seen_at >= later  # still on checkout
    detailed, _ = await scanner.get_scan(session, second.id)
    checkout = detailed.snapshots[1]
    assert (
        checkout.observations[0].inline_sha384
        == hashlib.sha384(b'window.checkoutConfig = {currency: "USD"};').hexdigest()
    )
    scans = await scanner.list_scans(session, "shop")
    assert [s.id for s in scans] == [second.id, first.id]
    assert [s.id for s in await scanner.list_scans(session, "shop", limit=1)] == [second.id]


async def test_robots_txt_skips_pages_unless_the_site_ignores_it(
    session: AsyncSession, fixture_site: FixtureSite
) -> None:
    fixture_site.set(
        "/robots.txt", "User-agent: *\nDisallow: /checkout\n", content_type="text/plain"
    )
    fixture_site.page("/checkout", CHECKOUT)
    fixture_site.page("/", HOME)
    await _shop(session, fixture_site)

    scan = await _scan(session)
    assert scan.status is ScanStatus.COMPLETED  # a robots refusal is not a failure
    assert (scan.pages_ok, scan.pages_skipped, scan.pages_failed) == (1, 1, 0)
    detailed, _ = await scanner.get_scan(session, scan.id)
    skipped = detailed.snapshots[1]
    assert skipped.outcome is SnapshotOutcome.ROBOTS_DISALLOWED
    assert skipped.error == "disallowed by robots.txt (parsed)"
    assert skipped.observations == []
    assert "/checkout" not in fixture_site.paths()

    await sites.update_site(session, "shop", respect_robots=False)
    scan = await _scan(session)
    assert (scan.pages_ok, scan.pages_skipped) == (2, 0)
    assert "/checkout" in fixture_site.paths()


async def test_partial_and_failed_scans(session: AsyncSession, fixture_site: FixtureSite) -> None:
    fixture_site.page("/", HOME)
    fixture_site.set("/checkout", "boom", 500)
    await _shop(session, fixture_site)

    partial = await _scan(session)
    assert partial.status is ScanStatus.PARTIAL
    assert (partial.pages_ok, partial.pages_failed) == (1, 1)
    detailed, _ = await scanner.get_scan(session, partial.id)
    assert detailed.snapshots[1].outcome is SnapshotOutcome.HTTP_ERROR
    assert detailed.snapshots[1].error == "HTTP 500"

    fixture_site.set("/", "gone", 404)
    failed = await _scan(session)
    assert failed.status is ScanStatus.FAILED
    assert (failed.pages_ok, failed.pages_failed, failed.scripts_seen) == (0, 2, 0)


async def test_scripts_resolve_against_the_final_url_after_redirects(
    session: AsyncSession, fixture_site: FixtureSite
) -> None:
    await sites.create_site(
        session, name="shop", allowed_origins=[fixture_site.origin], scan_interval_hours=24
    )
    await sites.add_page(session, "shop", url=fixture_site.url("/pay"))
    fixture_site.set("/pay", "", 302, location="/v2/pay/")
    fixture_site.page("/v2/pay/", "<script src='bundle.js'></script><script>inline()</script>")

    scan = await _scan(session)
    detailed, _ = await scanner.get_scan(session, scan.id)
    (snapshot,) = detailed.snapshots
    assert snapshot.url == fixture_site.url("/pay")
    assert snapshot.final_url == fixture_site.url("/v2/pay/")
    assert [o.script.locator for o in snapshot.observations] == [
        fixture_site.url("/v2/pay/bundle.js"),
        fixture_site.url("/v2/pay/#inline-1"),
    ]


async def test_warnings_are_kept_on_the_snapshot(
    session: AsyncSession, fixture_site: FixtureSite
) -> None:
    await sites.create_site(
        session, name="shop", allowed_origins=[fixture_site.origin], scan_interval_hours=24
    )
    await sites.add_page(session, "shop", url=fixture_site.url("/"))
    fixture_site.page("/", '<script src="javascript:void(0)"></script>')
    scan = await _scan(session)
    detailed, _ = await scanner.get_scan(session, scan.id)
    assert detailed.snapshots[0].warnings == [
        "skipped <script> with a javascript: src that can't be fetched: javascript:void(0)"
    ]


async def test_a_page_removed_during_the_scan_keeps_its_snapshot(
    session: AsyncSession, fixture_site: FixtureSite
) -> None:
    fixture_site.page("/checkout", CHECKOUT)
    fixture_site.page("/", HOME)
    await _shop(session, fixture_site)
    site = await sites.get_site(session, "shop")
    pages = await sites.list_pages(session, "shop")
    async with PageFetcher() as fetcher:
        results = await scanner.fetch_pages(site, pages, fetcher, concurrency=1)
    await sites.remove_page(session, "shop", fixture_site.url("/checkout"))

    scan = await scanner.record_scan(
        session, site, results, trigger=ScanTrigger.API, started_at=datetime.now(UTC)
    )
    detailed, _ = await scanner.get_scan(session, scan.id)
    assert [s.page_id is None for s in detailed.snapshots] == [False, True]
    assert detailed.snapshots[1].observations  # the evidence is still there


async def test_removing_a_page_later_keeps_snapshots_and_deleting_the_site_removes_scans(
    session: AsyncSession, fixture_site: FixtureSite
) -> None:
    fixture_site.page("/checkout", CHECKOUT)
    fixture_site.page("/", HOME)
    await _shop(session, fixture_site)
    scan = await _scan(session)
    await session.commit()

    await sites.remove_page(session, "shop", fixture_site.url("/checkout"))
    await session.commit()
    session.expunge_all()
    page_ids = list(await session.scalars(select(PageSnapshot.page_id).order_by(PageSnapshot.url)))
    assert page_ids[0] is not None
    assert page_ids[1] is None

    await sites.delete_site(session, "shop")
    await session.commit()
    assert await session.scalar(select(func.count()).select_from(Scan)) == 0
    assert await session.scalar(select(func.count()).select_from(PageSnapshot)) == 0
    assert await session.scalar(select(func.count()).select_from(ScriptObservation)) == 0
    with pytest.raises(sites.NotFoundError):
        await scanner.get_scan(session, scan.id)


async def test_scan_errors(session: AsyncSession) -> None:
    async with PageFetcher() as fetcher:
        with pytest.raises(sites.NotFoundError):
            await scanner.scan_site(session, "nope", fetcher, trigger=ScanTrigger.CLI)
        await sites.create_site(
            session, name="empty", allowed_origins=["https://e.test"], scan_interval_hours=1
        )
        with pytest.raises(sites.ValidationError, match="has no pages to scan"):
            await scanner.scan_site(session, "empty", fetcher, trigger=ScanTrigger.CLI)
    with pytest.raises(sites.NotFoundError):
        await scanner.get_scan(session, uuid.uuid4())
    with pytest.raises(sites.NotFoundError):
        await scanner.list_scans(session, "nope")
    with pytest.raises(sites.NotFoundError):
        await scanner.list_scripts(session, "nope")
