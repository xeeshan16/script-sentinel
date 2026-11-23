from __future__ import annotations

import hashlib
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from script_sentinel import scanner, sites, versions
from script_sentinel.db.models import (
    AuthorizationStatus,
    PageSnapshot,
    Scan,
    ScanStatus,
    ScanTrigger,
    ScriptFetch,
    ScriptFetchOutcome,
    ScriptKind,
    ScriptObservation,
    ScriptType,
    ScriptVersion,
    SnapshotOutcome,
    SriStatus,
)
from script_sentinel.fetch import PageFetcher
from script_sentinel.jstokens import normalized_sha384
from script_sentinel.sri import integrity_value
from tests.conftest import FixtureSite

# Pages reference the vendor script through this placeholder; the `shop` fixture serves
# them with the `cdn` fixture's URL filled in.
VENDOR = "{{VENDOR}}"
VENDOR_JS = b"/*! widget v1 */\nwindow.widget = function () { return 1; };\n"

CHECKOUT = """<!doctype html><html><head>
<script nonce="n1">window.checkoutConfig = {currency: "EUR"};</script>
<script src="/js/app.js" defer></script>
<script src="{{VENDOR}}" integrity="sha384-AAAA" crossorigin="anonymous" async></script>
<script type="module" src="/js/checkout.mjs"></script>
<script type="application/ld+json">{"@type": "WebPage"}</script>
</head><body><form id="pay"></form></body></html>"""

HOME = """<html><head><script src="/js/app.js"></script>
<script src="{{VENDOR}}"></script></head><body><script>track("home")</script></body></html>"""

APP_JS = b"document.body.dataset.ready = 'true';\n"
CHECKOUT_MJS = b"export const pay = () => {};\n"


class Shop:
    """The fixture site (pages and first-party scripts) plus a vendor CDN origin."""

    def __init__(self, site: FixtureSite, cdn: FixtureSite) -> None:
        self.site = site
        self.cdn = cdn
        self.vendor = cdn.url("/widget.js")
        site.set("/js/app.js", APP_JS, content_type="text/javascript")
        site.set("/js/checkout.mjs", CHECKOUT_MJS, content_type="text/javascript")
        cdn.set("/widget.js", VENDOR_JS, content_type="text/javascript")

    def page(self, path: str, html: str) -> None:
        self.site.page(path, html.replace(VENDOR, self.vendor))

    def url(self, path: str) -> str:
        return self.site.url(path)


@pytest.fixture
def shop(fixture_site: FixtureSite, cdn: FixtureSite) -> Shop:
    return Shop(fixture_site, cdn)


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
    session: AsyncSession, shop: Shop
) -> None:
    shop.page("/checkout", CHECKOUT)
    shop.page("/", HOME)
    await _shop(session, shop.site)
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
    assert checkout.url == shop.url("/checkout")
    assert checkout.payment_page
    assert checkout.outcome is SnapshotOutcome.OK
    assert checkout.http_status == 200
    served = CHECKOUT.replace(VENDOR, shop.vendor).encode()
    assert checkout.body_sha384 == hashlib.sha384(served).hexdigest()
    assert checkout.script_count == 4
    assert checkout.data_block_count == 1
    assert checkout.warnings == []
    assert [(o.position, o.script.locator) for o in checkout.observations] == [
        (1, shop.url("/checkout#inline-1")),
        (2, shop.url("/js/app.js")),
        (3, shop.vendor),
        (4, shop.url("/js/checkout.mjs")),
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
        shop.vendor,
        shop.url("/js/app.js"),
        shop.url("/js/checkout.mjs"),
        shop.url("/#inline-1"),
        shop.url("/checkout#inline-1"),
    }
    assert len(inventory) == 5
    assert {s.status for s in inventory} == {AuthorizationStatus.PENDING}
    shared = next(s for s in inventory if s.locator == shop.vendor)
    observed_on = await session.scalar(
        select(func.count())
        .select_from(ScriptObservation)
        .where(ScriptObservation.script_id == shared.id)
    )
    assert observed_on == 2  # one script, observed on both pages


async def test_rescanning_updates_the_inventory_instead_of_duplicating_it(
    session: AsyncSession, shop: Shop
) -> None:
    shop.page("/checkout", CHECKOUT)
    shop.page("/", HOME)
    await _shop(session, shop.site)
    first = await _scan(session, clock=clock_from(datetime(2026, 11, 22, 9, tzinfo=UTC)))
    ids = {s.locator: s.id for s in await scanner.list_scripts(session, "shop")}

    # The inline config changes and the vendor script disappears from the home page.
    shop.page("/checkout", CHECKOUT.replace('"EUR"', '"USD"'))
    shop.page("/", '<script src="/js/app.js"></script>')
    later = datetime(2026, 11, 23, 9, tzinfo=UTC)
    second = await _scan(session, clock=clock_from(later))

    assert (second.scripts_seen, second.scripts_new) == (4, 0)
    inventory = {s.locator: s for s in await scanner.list_scripts(session, "shop")}
    assert {loc: s.id for loc, s in inventory.items()} == ids  # same rows, no duplicates
    assert inventory[shop.url("/#inline-1")].last_seen_at < later  # not seen again
    assert inventory[shop.vendor].last_seen_at >= later  # still on checkout
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
    session: AsyncSession, shop: Shop
) -> None:
    shop.site.set("/robots.txt", "User-agent: *\nDisallow: /checkout\n", content_type="text/plain")
    shop.page("/checkout", CHECKOUT)
    shop.page("/", HOME)
    await _shop(session, shop.site)

    scan = await _scan(session)
    assert scan.status is ScanStatus.COMPLETED  # a robots refusal is not a failure
    assert (scan.pages_ok, scan.pages_skipped, scan.pages_failed) == (1, 1, 0)
    detailed, _ = await scanner.get_scan(session, scan.id)
    skipped = detailed.snapshots[1]
    assert skipped.outcome is SnapshotOutcome.ROBOTS_DISALLOWED
    assert skipped.error == "disallowed by robots.txt (parsed)"
    assert skipped.observations == []
    assert "/checkout" not in shop.site.paths()

    await sites.update_site(session, "shop", respect_robots=False)
    scan = await _scan(session)
    assert (scan.pages_ok, scan.pages_skipped) == (2, 0)
    assert "/checkout" in shop.site.paths()


async def test_partial_and_failed_scans(session: AsyncSession, shop: Shop) -> None:
    shop.page("/", HOME)
    shop.site.set("/checkout", "boom", 500)
    await _shop(session, shop.site)

    partial = await _scan(session)
    assert partial.status is ScanStatus.PARTIAL
    assert (partial.pages_ok, partial.pages_failed) == (1, 1)
    detailed, _ = await scanner.get_scan(session, partial.id)
    assert detailed.snapshots[1].outcome is SnapshotOutcome.HTTP_ERROR
    assert detailed.snapshots[1].error == "HTTP 500"

    shop.site.set("/", "gone", 404)
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
    session: AsyncSession, shop: Shop
) -> None:
    shop.page("/checkout", CHECKOUT)
    shop.page("/", HOME)
    await _shop(session, shop.site)
    site = await sites.get_site(session, "shop")
    pages = await sites.list_pages(session, "shop")
    async with PageFetcher() as fetcher:
        results = await scanner.fetch_pages(site, pages, fetcher, concurrency=1)
    await sites.remove_page(session, "shop", shop.url("/checkout"))

    scan = await scanner.record_scan(
        session, site, results, trigger=ScanTrigger.API, started_at=datetime.now(UTC)
    )
    detailed, _ = await scanner.get_scan(session, scan.id)
    assert [s.page_id is None for s in detailed.snapshots] == [False, True]
    assert detailed.snapshots[1].observations  # the evidence is still there


async def test_removing_a_page_later_keeps_snapshots_and_deleting_the_site_removes_scans(
    session: AsyncSession, shop: Shop
) -> None:
    shop.page("/checkout", CHECKOUT)
    shop.page("/", HOME)
    await _shop(session, shop.site)
    scan = await _scan(session)
    await session.commit()

    await sites.remove_page(session, "shop", shop.url("/checkout"))
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


# Bodies, versions and integrity (day 3)


async def _versions(session: AsyncSession, locator: str) -> list[ScriptVersion]:
    script = await versions.find_script(session, "shop", locator)
    return (await versions.versions_by_script(session, [script.id]))[script.id]


async def test_every_body_is_hashed_and_versioned(session: AsyncSession, shop: Shop) -> None:
    shop.page("/checkout", CHECKOUT)
    shop.page("/", HOME)
    await _shop(session, shop.site, respect_robots=False)

    scan = await _scan(session)
    # app.js, the vendor script and checkout.mjs, each fetched once even though app.js and
    # the vendor script are on both pages.
    assert (scan.scripts_fetched, scan.scripts_fetch_failed) == (3, 0)
    assert (scan.versions_new, scan.scripts_changed) == (5, 0)
    assert shop.site.paths().count("/js/app.js") == 1
    assert shop.cdn.paths() == ["/widget.js"]

    detailed, _ = await scanner.get_scan(session, scan.id)
    fetches = {f.url: f for f in detailed.script_fetches}
    assert set(fetches) == {shop.vendor, shop.url("/js/app.js"), shop.url("/js/checkout.mjs")}
    vendor_fetch = fetches[shop.vendor]
    assert vendor_fetch.outcome is ScriptFetchOutcome.OK
    assert (vendor_fetch.http_status, vendor_fetch.content_type) == (200, "text/javascript")
    assert vendor_fetch.size_bytes == len(VENDOR_JS)
    assert vendor_fetch.new_version
    assert vendor_fetch.version is not None
    assert vendor_fetch.version.sha384 == hashlib.sha384(VENDOR_JS).hexdigest()
    assert vendor_fetch.version.sri == integrity_value(VENDOR_JS)

    home, checkout = detailed.snapshots
    inline, app, vendor, module = checkout.observations
    assert inline.version is not None
    assert inline.version.sha384 == inline.inline_sha384
    assert app.version is not None
    assert app.version.sha384 == hashlib.sha384(APP_JS).hexdigest()
    assert app.sri_status is None  # no integrity attribute
    # integrity="sha384-AAAA" doesn't match the body: a browser would block it.
    assert vendor.sri_status is SriStatus.MISMATCH
    assert module.version_id == fetches[shop.url("/js/checkout.mjs")].version_id
    # Both pages point at the same version of the shared scripts.
    assert home.observations[1].version_id == vendor.version_id

    (stored,) = await _versions(session, shop.vendor)
    assert stored.size_bytes == len(VENDOR_JS)
    assert stored.normalized_sha384 == normalized_sha384(VENDOR_JS.decode())
    body = await session.scalar(select(ScriptVersion.content).where(ScriptVersion.id == stored.id))
    assert body == VENDOR_JS.decode()


async def test_a_changed_body_is_a_new_version_and_a_change(
    session: AsyncSession, shop: Shop
) -> None:
    shop.page("/checkout", CHECKOUT)
    shop.page("/", HOME)
    await _shop(session, shop.site, respect_robots=False)
    await _scan(session, clock=clock_from(datetime(2026, 11, 23, 9, tzinfo=UTC)))

    # Same body again: no new version, last_seen moves.
    later = datetime(2026, 11, 23, 10, tzinfo=UTC)
    again = await _scan(session, clock=clock_from(later))
    assert (again.versions_new, again.scripts_changed, again.scripts_new) == (0, 0, 0)
    (only,) = await _versions(session, shop.vendor)
    assert only.last_seen_at >= later
    detailed, _ = await scanner.get_scan(session, again.id)
    assert not any(f.new_version for f in detailed.script_fetches)

    # The vendor rebuilds with only a new banner comment, and the inline config changes.
    rebuilt = VENDOR_JS.replace(b"widget v1", b"widget v1 (rebuilt 2026-11-23)")
    shop.cdn.set("/widget.js", rebuilt, content_type="text/javascript")
    shop.page("/checkout", CHECKOUT.replace('"EUR"', '"USD"'))
    third = await _scan(session)
    assert (third.versions_new, third.scripts_changed) == (2, 2)
    newest, first = await _versions(session, shop.vendor)
    assert newest.sha384 == hashlib.sha384(rebuilt).hexdigest()
    assert newest.sha384 != first.sha384
    # Comments only: the normalized hash shows the code itself didn't change.
    assert newest.normalized_sha384 == first.normalized_sha384
    inline_new, inline_old = await _versions(session, shop.url("/checkout#inline-1"))
    assert inline_new.normalized_sha384 != inline_old.normalized_sha384

    # Going back to an earlier body reuses its version.
    shop.cdn.set("/widget.js", VENDOR_JS, content_type="text/javascript")
    fourth = await _scan(session)
    assert fourth.versions_new == 0
    assert [v.id for v in await _versions(session, shop.vendor)] == [first.id, newest.id]


async def test_integrity_status_per_page(session: AsyncSession, shop: Shop) -> None:
    good = integrity_value(VENDOR_JS)
    shop.page(
        "/checkout",
        f'<script src="{VENDOR}" integrity="{good}" crossorigin="anonymous"></script>'
        '<script src="/js/app.js" integrity="md5-abc"></script>'
        '<script src="/js/missing.js" integrity="sha384-abc"></script>'
        '<script integrity="sha384-abc">inline()</script>',
    )
    shop.page("/", f'<script src="{VENDOR}" integrity="sha384-wrong" crossorigin></script>')
    await _shop(session, shop.site, respect_robots=False)

    scan = await _scan(session)
    assert (scan.scripts_fetched, scan.scripts_fetch_failed) == (2, 1)
    detailed, _ = await scanner.get_scan(session, scan.id)
    home, checkout = detailed.snapshots
    assert [o.sri_status for o in checkout.observations] == [
        SriStatus.MATCH,
        SriStatus.NO_SUPPORTED_HASH,
        SriStatus.UNVERIFIED,  # couldn't be fetched
        None,  # integrity is ignored on inline scripts
    ]
    assert checkout.observations[2].version_id is None
    # The same script, same body, judged against each page's own attribute.
    assert home.observations[0].sri_status is SriStatus.MISMATCH
    assert home.observations[0].version_id == checkout.observations[0].version_id
    missing = next(f for f in detailed.script_fetches if f.url.endswith("/missing.js"))
    assert (missing.outcome, missing.error, missing.version_id) == (
        ScriptFetchOutcome.HTTP_ERROR,
        "HTTP 404",
        None,
    )
    assert not missing.new_version
    assert await _versions(session, shop.url("/js/missing.js")) == []


async def test_security_headers_and_meta_csp_are_snapshotted(
    session: AsyncSession, shop: Shop
) -> None:
    shop.site.set(
        "/checkout",
        '<meta http-equiv="Content-Security-Policy" content="script-src \'self\'">',
        content_security_policy_report_only="script-src 'self'; report-uri /r",
        strict_transport_security="max-age=31536000",
    )
    shop.page("/", "<p>no scripts</p>")
    await _shop(session, shop.site, respect_robots=False)
    scan = await _scan(session)
    detailed, _ = await scanner.get_scan(session, scan.id)
    home, checkout = detailed.snapshots
    assert checkout.security_headers == {
        "content-security-policy-report-only": ["script-src 'self'; report-uri /r"],
        "strict-transport-security": ["max-age=31536000"],
    }
    assert checkout.meta_csp == ["script-src 'self'"]
    assert (home.security_headers, home.meta_csp) == ({}, [])


async def test_record_scan_without_fetched_scripts_leaves_them_unverified(
    session: AsyncSession, shop: Shop
) -> None:
    shop.page("/checkout", CHECKOUT)
    shop.page("/", HOME)
    await _shop(session, shop.site, respect_robots=False)
    site = await sites.get_site(session, "shop")
    pages = await sites.list_pages(session, "shop")
    async with PageFetcher() as fetcher:
        results = await scanner.fetch_pages(site, pages, fetcher)
    scan = await scanner.record_scan(
        session, site, results, trigger=ScanTrigger.API, started_at=datetime.now(UTC)
    )
    assert (scan.scripts_fetched, scan.scripts_fetch_failed, scan.versions_new) == (0, 0, 2)
    detailed, _ = await scanner.get_scan(session, scan.id)
    vendor = detailed.snapshots[1].observations[2]
    assert (vendor.version_id, vendor.sri_status) == (None, SriStatus.UNVERIFIED)
    assert detailed.script_fetches == []


async def test_deleting_a_site_removes_versions_and_fetches(
    session: AsyncSession, shop: Shop
) -> None:
    shop.page("/checkout", CHECKOUT)
    shop.page("/", HOME)
    await _shop(session, shop.site, respect_robots=False)
    await _scan(session)
    await session.commit()
    assert await session.scalar(select(func.count()).select_from(ScriptFetch)) == 3
    await sites.delete_site(session, "shop")
    await session.commit()
    assert await session.scalar(select(func.count()).select_from(ScriptFetch)) == 0
    assert await session.scalar(select(func.count()).select_from(ScriptVersion)) == 0


async def test_version_lookups(session: AsyncSession, shop: Shop) -> None:
    shop.page("/checkout", "<script>a()</script>")
    shop.page("/", "<p></p>")
    await _shop(session, shop.site)
    await _scan(session)
    script = await versions.find_script(session, "shop", shop.url("/checkout#inline-1"))
    (version,) = await _versions(session, script.locator)
    full = await versions.get_version(session, "shop", script.id, version.id)
    assert full.content == "a()"
    assert (await versions.get_script(session, "shop", script.id)).id == script.id
    with pytest.raises(sites.NotFoundError, match="sentinel scripts list shop"):
        await versions.find_script(session, "shop", "https://nope.test/x.js")
    with pytest.raises(sites.NotFoundError):
        await versions.get_script(session, "shop", uuid.uuid4())
    with pytest.raises(sites.NotFoundError):
        await versions.get_version(session, "shop", script.id, uuid.uuid4())
    assert await versions.versions_by_script(session, []) == {}
