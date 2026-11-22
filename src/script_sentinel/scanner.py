"""Scanning a site: fetch its pages, find their scripts and record what was seen.

A scan has two phases so that no database transaction is held open while waiting on the
network:

1. **Fetch** every registered page concurrently (bounded by ``concurrency``) through a
   :class:`~script_sentinel.fetch.PageFetcher`, and parse each HTML page's scripts.
2. **Record** the results in one transaction: a :class:`Scan`, one :class:`PageSnapshot`
   per page, and a :class:`ScriptObservation` per script. Scripts are upserted into the
   site's inventory by locator; a script seen for the first time starts as ``pending``
   (it still needs a justification under PCI DSS 6.4.3).

The scan itself never decides whether a script is acceptable. That is the policy engine's
job (day 4), working from the inventory this builds.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from script_sentinel.db.models import (
    Page,
    PageSnapshot,
    Scan,
    ScanStatus,
    ScanTrigger,
    Script,
    ScriptKind,
    ScriptObservation,
    Site,
    SnapshotOutcome,
    utcnow,
)
from script_sentinel.fetch import FetchResult, PageFetcher
from script_sentinel.inventory import PageInventory, ParsedScript, inline_locator, parse_scripts
from script_sentinel.sites import NotFoundError, ValidationError, get_site, list_pages


@dataclass(frozen=True, slots=True)
class PageResult:
    page_id: uuid.UUID
    url: str
    payment_page: bool
    fetch: FetchResult
    inventory: PageInventory | None
    fetched_at: datetime


def locator_for(page_url: str, script: ParsedScript) -> str:
    if script.src is not None:
        return script.src
    assert script.inline_index is not None
    return inline_locator(page_url, script.inline_index)


async def fetch_pages(
    site: Site,
    pages: list[Page],
    fetcher: PageFetcher,
    *,
    concurrency: int = 4,
    clock: Callable[[], datetime] = utcnow,
) -> list[PageResult]:
    """Fetch and parse every page. Never raises for a page that fails; it's recorded."""
    semaphore = asyncio.Semaphore(max(1, concurrency))
    origins = list(site.allowed_origins)

    async def one(page: Page) -> PageResult:
        async with semaphore:
            fetched_at = clock()
            result = await fetcher.fetch_page(page.url, origins, respect_robots=site.respect_robots)
        inventory = None
        if result.outcome is SnapshotOutcome.OK and result.text is not None:
            # Relative URLs resolve against where the page ended up after redirects.
            inventory = parse_scripts(result.text, result.final_url or page.url)
        return PageResult(page.id, page.url, page.payment_page, result, inventory, fetched_at)

    return list(await asyncio.gather(*(one(p) for p in pages)))


def _status(results: list[PageResult]) -> ScanStatus:
    failed = sum(r.fetch.outcome.failed for r in results)
    if failed == 0:
        return ScanStatus.COMPLETED
    if failed == len(results):
        return ScanStatus.FAILED
    return ScanStatus.PARTIAL


async def record_scan(
    session: AsyncSession,
    site: Site,
    results: list[PageResult],
    *,
    trigger: ScanTrigger,
    started_at: datetime,
    clock: Callable[[], datetime] = utcnow,
) -> Scan:
    """Write a scan and its snapshots, and upsert the site's script inventory."""
    existing = {
        s.locator: s for s in await session.scalars(select(Script).where(Script.site_id == site.id))
    }
    live_pages = set(
        await session.scalars(select(Page.id).where(Page.id.in_([r.page_id for r in results])))
    )
    scan = Scan(
        site_id=site.id,
        status=_status(results),
        trigger=trigger,
        started_at=started_at,
        pages_total=len(results),
        pages_ok=sum(r.fetch.outcome is SnapshotOutcome.OK for r in results),
        pages_failed=sum(r.fetch.outcome.failed for r in results),
        pages_skipped=sum(r.fetch.outcome is SnapshotOutcome.ROBOTS_DISALLOWED for r in results),
    )
    session.add(scan)
    seen: set[str] = set()
    new: set[str] = set()
    for result in sorted(results, key=lambda r: r.url):
        fetch = result.fetch
        inventory = result.inventory
        snapshot = PageSnapshot(
            scan=scan,
            # The page may have been removed while the scan was fetching.
            page_id=result.page_id if result.page_id in live_pages else None,
            url=result.url,
            payment_page=result.payment_page,
            outcome=fetch.outcome,
            final_url=fetch.final_url,
            http_status=fetch.status_code,
            content_type=(fetch.content_type or "")[:255] or None,
            size_bytes=fetch.size_bytes,
            body_sha384=fetch.body_sha384,
            elapsed_ms=fetch.elapsed_ms,
            error=fetch.error[:1024] if fetch.error else None,
            warnings=list(inventory.warnings) if inventory else [],
            script_count=len(inventory.scripts) if inventory else 0,
            data_block_count=inventory.data_blocks if inventory else 0,
            fetched_at=result.fetched_at,
        )
        session.add(snapshot)
        if inventory is None:
            continue
        page_url = fetch.final_url or result.url
        for parsed in inventory.scripts:
            locator = locator_for(page_url, parsed)
            script = existing.get(locator)
            if script is None:
                script = Script(
                    site_id=site.id,
                    kind=ScriptKind.INLINE if parsed.is_inline else ScriptKind.EXTERNAL,
                    locator=locator,
                    first_seen_at=result.fetched_at,
                    last_seen_at=result.fetched_at,
                )
                session.add(script)
                existing[locator] = script
                new.add(locator)
            else:
                script.last_seen_at = max(script.last_seen_at, result.fetched_at)
            seen.add(locator)
            session.add(
                ScriptObservation(
                    snapshot=snapshot,
                    script=script,
                    position=parsed.position,
                    script_type=parsed.script_type,
                    type_attribute=(parsed.type_attribute or "")[:128] or None,
                    integrity=(parsed.integrity or "")[:1024] or None,
                    crossorigin=(parsed.crossorigin or "")[:32] or None,
                    referrerpolicy=(parsed.referrerpolicy or "")[:64] or None,
                    nonce_digest=parsed.nonce_digest,
                    is_async=parsed.is_async,
                    is_defer=parsed.is_defer,
                    nomodule=parsed.nomodule,
                    inline_sha384=parsed.body_sha384,
                    inline_size_bytes=parsed.body_size,
                )
            )
    scan.scripts_seen = len(seen)
    scan.scripts_new = len(new)
    scan.finished_at = clock()
    await session.flush()
    return scan


async def scan_site(
    session: AsyncSession,
    site_name: str,
    fetcher: PageFetcher,
    *,
    trigger: ScanTrigger,
    concurrency: int = 4,
    clock: Callable[[], datetime] = utcnow,
) -> Scan:
    """Scan every registered page of a site and record the result.

    The caller owns the transaction. Reads happen up front, the network phase holds no
    locks, and all writes happen at the end.
    """
    site = await get_site(session, site_name)
    pages = await list_pages(session, site_name)
    if not pages:
        raise ValidationError(
            f"site {site_name!r} has no pages to scan; add one with: "
            f"sentinel pages add {site_name} URL"
        )
    started_at = clock()
    results = await fetch_pages(site, pages, fetcher, concurrency=concurrency, clock=clock)
    return await record_scan(
        session, site, results, trigger=trigger, started_at=started_at, clock=clock
    )


async def list_scans(session: AsyncSession, site_name: str, *, limit: int = 20) -> list[Scan]:
    site = await get_site(session, site_name)
    result = await session.scalars(
        select(Scan)
        .where(Scan.site_id == site.id)
        .order_by(Scan.started_at.desc(), Scan.id)
        .limit(limit)
    )
    return list(result)


async def get_scan(session: AsyncSession, scan_id: uuid.UUID) -> tuple[Scan, str]:
    """A scan with its snapshots and observations loaded, and its site's name."""
    row = (
        await session.execute(
            select(Scan, Site.name)
            .join(Site, Site.id == Scan.site_id)
            .where(Scan.id == scan_id)
            .options(
                selectinload(Scan.snapshots)
                .selectinload(PageSnapshot.observations)
                .selectinload(ScriptObservation.script)
            )
        )
    ).one_or_none()
    if row is None:
        raise NotFoundError(f"scan {scan_id} not found")
    return row[0], row[1]


async def list_scripts(session: AsyncSession, site_name: str) -> list[Script]:
    """The site's script inventory, external scripts first, then by locator."""
    site = await get_site(session, site_name)
    result = await session.scalars(
        select(Script).where(Script.site_id == site.id).order_by(Script.kind, Script.locator)
    )
    return list(result)
