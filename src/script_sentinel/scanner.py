"""Scanning a site: fetch its pages, find their scripts and record what was seen.

A scan has two phases so that no database transaction is held open while waiting on the
network:

1. **Fetch** every registered page concurrently (bounded by ``concurrency``) through a
   :class:`~script_sentinel.fetch.PageFetcher`, and parse each HTML page's scripts. Then
   fetch every external script those pages reference, once per URL, and hash the bodies
   in a worker thread so large scripts don't stall the event loop.
2. **Record** the results in one transaction: a :class:`Scan`, one :class:`PageSnapshot`
   per page (with its security headers), a :class:`ScriptObservation` per script, and a
   :class:`ScriptFetch` per external script. Scripts are upserted into the site's
   inventory by locator; a script seen for the first time starts as ``pending`` (it still
   needs a justification under PCI DSS 6.4.3). Every body, inline or external, is
   recorded as a :class:`ScriptVersion`, and each ``integrity`` attribute is checked
   against the body the way a browser would.

Policies can change how external scripts are identified: one that drops cache-busting
query parameters makes ``app.js?v=1`` and ``app.js?v=2`` the same inventory entry. Inline
blocks are matched against the page's known inline scripts by content before position
(:func:`assign_inline_locators`), so inserting a block doesn't shift the others. After
recording, the status of every script the scan saw is re-evaluated (see
:mod:`script_sentinel.authorization`); status changes go to the audit trail, and each
observation keeps the status its script had when the scan finished. Finally each script
is compared with what it served last time, and new scripts and changed bodies become
findings (see :mod:`script_sentinel.findings`).
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from script_sentinel import audit, authorization, findings
from script_sentinel.changes import KnownBlock, SeenBlock, match_inline_blocks
from script_sentinel.db.models import (
    AuthorizationStatus,
    Page,
    PageSnapshot,
    Scan,
    ScanStatus,
    ScanTrigger,
    Script,
    ScriptFetch,
    ScriptFetchOutcome,
    ScriptKind,
    ScriptObservation,
    ScriptVersion,
    Site,
    SnapshotOutcome,
    SriStatus,
    utcnow,
)
from script_sentinel.fetch import FetchResult, PageFetcher, ScriptFetchResult
from script_sentinel.inventory import PageInventory, ParsedScript, inline_locator, parse_scripts
from script_sentinel.sites import NotFoundError, ValidationError, get_site, list_pages
from script_sentinel.sri import check_integrity_digests
from script_sentinel.versions import BodyDigest, VersionRecorder, digest_body


@dataclass(frozen=True, slots=True)
class PageResult:
    page_id: uuid.UUID
    url: str
    payment_page: bool
    fetch: FetchResult
    inventory: PageInventory | None
    fetched_at: datetime


@dataclass(frozen=True, slots=True)
class FetchedScript:
    fetch: ScriptFetchResult
    digest: BodyDigest | None  # set when the fetch succeeded
    fetched_at: datetime


_INLINE_MARK = "#inline-"


async def assign_inline_locators(
    session: AsyncSession,
    results: Sequence[PageResult],
    existing: Mapping[str, Script],
    digests: Mapping[int, BodyDigest],
) -> dict[int, str]:
    """The locator of every inline block in ``results``, keyed by ``id(parsed)``.

    Each page's blocks are matched against the inline scripts already recorded for that
    page by content before position (see :func:`changes.match_inline_blocks`), so adding a
    block in front of the others doesn't make every block after it look changed.
    """
    page_urls = {
        result.fetch.final_url or result.url for result in results if result.inventory is not None
    }
    known: dict[str, list[tuple[int, Script]]] = {url: [] for url in page_urls}
    for locator, script in existing.items():
        if script.kind is not ScriptKind.INLINE:
            continue
        page, mark, index = locator.rpartition(_INLINE_MARK)
        if mark and index.isdigit() and page in known:
            known[page].append((int(index), script))
    current = {
        uuid.UUID(script.current_version_ids[0])
        for blocks in known.values()
        for _, script in blocks
        if script.current_version_ids
    }
    bodies: dict[uuid.UUID, tuple[str, str | None, str | None]] = {}
    ordered = sorted(current)
    for start in range(0, len(ordered), 500):
        for row in await session.execute(
            select(
                ScriptVersion.id,
                ScriptVersion.sha384,
                ScriptVersion.normalized_sha384,
                ScriptVersion.content,
            ).where(ScriptVersion.id.in_(ordered[start : start + 500]))
        ):
            bodies[row[0]] = (row[1], row[2], row[3])

    def known_block(index: int, script: Script) -> KnownBlock:
        body = None
        if script.current_version_ids:
            body = bodies.get(uuid.UUID(script.current_version_ids[0]))
        if body is None:
            return KnownBlock(index, None, None, None)
        return KnownBlock(index, *body)

    out: dict[int, str] = {}
    for result in results:
        if result.inventory is None:
            continue
        page_url = result.fetch.final_url or result.url
        blocks = [p for p in result.inventory.scripts if p.body is not None]
        if not blocks:
            continue
        seen = []
        for parsed in blocks:
            assert parsed.inline_index is not None
            digest = digests[id(parsed)]
            seen.append(
                SeenBlock(parsed.inline_index, digest.sha384, digest.normalized_sha384, digest.text)
            )
        indexes = await asyncio.to_thread(
            match_inline_blocks,
            [known_block(i, script) for i, script in sorted(known[page_url], key=lambda k: k[0])],
            seen,
        )
        for parsed, assigned in zip(blocks, indexes, strict=True):
            out[id(parsed)] = inline_locator(page_url, assigned)
    return out


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


async def fetch_scripts(
    results: list[PageResult],
    fetcher: PageFetcher,
    *,
    concurrency: int = 4,
    clock: Callable[[], datetime] = utcnow,
) -> dict[str, FetchedScript]:
    """Fetch and hash every external script the pages reference, once per URL."""
    urls = sorted(
        {
            parsed.src
            for result in results
            if result.inventory is not None
            for parsed in result.inventory.scripts
            if parsed.src is not None
        }
    )
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def one(url: str) -> tuple[str, FetchedScript]:
        async with semaphore:
            fetched_at = clock()
            fetched = await fetcher.fetch_script(url)
        digest = None
        if fetched.outcome is ScriptFetchOutcome.OK and fetched.body is not None:
            digest = await asyncio.to_thread(digest_body, fetched.body, fetched.content_type)
            fetched.body = None  # the digest keeps what is stored; free the bytes early
        return url, FetchedScript(fetched, digest, fetched_at)

    return dict(await asyncio.gather(*(one(url) for url in urls)))


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
    scripts: Mapping[str, FetchedScript] | None = None,
    clock: Callable[[], datetime] = utcnow,
) -> Scan:
    """Write a scan, its snapshots and script fetches, and upsert the inventory and versions.

    ``scripts`` holds the external scripts fetched for this scan, by URL. An external
    script missing from it is recorded without a version (its integrity is ``unverified``).
    """
    scripts = scripts or {}
    policies = await authorization.load_policies(session, site.id)
    existing = {
        s.locator: s for s in await session.scalars(select(Script).where(Script.site_id == site.id))
    }
    live_pages = set(
        await session.scalars(select(Page.id).where(Page.id.in_([r.page_id for r in results])))
    )
    inline_digests = {
        id(parsed): digest_body(parsed.body.encode("utf-8"))
        for result in results
        if result.inventory is not None
        for parsed in result.inventory.scripts
        if parsed.body is not None
    }
    inline_locators = await assign_inline_locators(session, results, existing, inline_digests)
    baseline = await findings.baseline_pages(session, site.id)
    hosts = await findings.known_hosts(session, site)
    recorder = await VersionRecorder.load(
        session,
        site.id,
        [d.sha384 for d in inline_digests.values()]
        + [f.digest.sha384 for f in scripts.values() if f.digest is not None],
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
        scripts_fetched=0,
        scripts_fetch_failed=0,
    )
    session.add(scan)
    seen: set[str] = set()
    new: set[str] = set()
    new_versions: set[uuid.UUID] = set()
    changed: set[uuid.UUID] = set()
    # External scripts: their version for this scan, recorded once per URL.
    external: dict[str, tuple[Script, ScriptVersion | None]] = {}
    # The bodies each script served this scan; they become its current versions.
    served: dict[uuid.UUID, set[uuid.UUID]] = {}
    observations: list[ScriptObservation] = []

    def upsert_script(locator: str, parsed: ParsedScript, seen_at: datetime) -> Script:
        script = existing.get(locator)
        if script is None:
            script = Script(
                id=uuid.uuid4(),
                site_id=site.id,
                kind=ScriptKind.INLINE if parsed.is_inline else ScriptKind.EXTERNAL,
                locator=locator,
                first_seen_at=seen_at,
                last_seen_at=seen_at,
            )
            session.add(script)
            existing[locator] = script
            new.add(locator)
        else:
            script.last_seen_at = max(script.last_seen_at, seen_at)
        seen.add(locator)
        return script

    def record_version(script: Script, digest: BodyDigest, seen_at: datetime) -> ScriptVersion:
        recorded = recorder.record(session, script, digest, seen_at)
        served.setdefault(script.id, set()).add(recorded.version.id)
        if recorded.new_version:
            new_versions.add(recorded.version.id)
        if recorded.changed:
            changed.add(script.id)
        return recorded.version

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
            security_headers=dict(fetch.security_headers),
            meta_csp=list(inventory.meta_csp) if inventory else [],
            fetched_at=result.fetched_at,
        )
        session.add(snapshot)
        if inventory is None:
            continue
        for parsed in inventory.scripts:
            if parsed.src is not None:
                locator = authorization.external_locator(parsed.src, policies)
            else:
                locator = inline_locators[id(parsed)]
            script = upsert_script(locator, parsed, result.fetched_at)
            version: ScriptVersion | None = None
            sri_status: SriStatus | None = None
            if parsed.body is not None:
                version = record_version(script, inline_digests[id(parsed)], result.fetched_at)
            else:
                assert parsed.src is not None
                if parsed.src not in external:
                    fetched = scripts.get(parsed.src)
                    if fetched is not None and fetched.digest is not None:
                        version = record_version(script, fetched.digest, fetched.fetched_at)
                    external[parsed.src] = (script, version)
                version = external[parsed.src][1]
                if parsed.integrity is not None:
                    fetched = scripts.get(parsed.src)
                    if version is None or fetched is None or fetched.digest is None:
                        sri_status = SriStatus.UNVERIFIED
                    else:
                        sri_status = check_integrity_digests(
                            parsed.integrity, fetched.digest.digests
                        )
            observation = ScriptObservation(
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
                version=version,
                sri_status=sri_status,
            )
            session.add(observation)
            observations.append(observation)

    for url, (script, version) in sorted(external.items()):
        fetched = scripts.get(url)
        if fetched is None:
            continue
        sf = fetched.fetch
        session.add(
            ScriptFetch(
                scan=scan,
                script=script,
                version=version,
                url=url,
                outcome=sf.outcome,
                final_url=sf.final_url,
                http_status=sf.status_code,
                content_type=(sf.content_type or "")[:255] or None,
                size_bytes=fetched.digest.size_bytes if fetched.digest else None,
                elapsed_ms=sf.elapsed_ms,
                error=sf.error[:1024] if sf.error else None,
                new_version=version is not None and version.id in new_versions,
                fetched_at=fetched.fetched_at,
            )
        )
        if sf.outcome is ScriptFetchOutcome.OK:
            scan.scripts_fetched += 1
        else:
            scan.scripts_fetch_failed += 1

    seen_scripts = sorted((existing[locator] for locator in seen), key=lambda s: s.locator)
    activities = {
        script.id: findings.ScriptActivity(
            script=script,
            previous_ids=list(script.current_version_ids or ()),
            served_ids=set(served.get(script.id, ())),
            is_new=script.locator in new,
        )
        for script in seen_scripts
    }
    for observation in observations:
        activity = activities[observation.script.id]
        activity.pages.add(observation.snapshot.url)
        activity.payment_page = activity.payment_page or observation.snapshot.payment_page
    for script in seen_scripts:
        if script.id in served:
            # A script whose body couldn't be fetched keeps its previous current versions.
            script.current_version_ids = sorted(str(v) for v in served[script.id])
    await session.flush()
    await authorization.reevaluate(
        session,
        site,
        seen_scripts,
        audit.AuditLog(session, site.id, clock=clock),
        actor="scan",
        policies=policies,
        detail={"cause": "scan", "scan_id": str(scan.id)},
        clock=clock,
    )
    for observation in observations:
        observation.authorization_status = observation.script.status
    raised = await findings.detect(
        session,
        scan,
        list(activities.values()),
        baseline=baseline,
        hosts=hosts,
        own_hosts=findings.site_hosts(site),
        clock=clock,
    )

    scan.scripts_seen = len(seen)
    scan.scripts_new = len(new)
    scan.versions_new = len(new_versions)
    scan.scripts_changed = len(changed)
    statuses = [s.status for s in seen_scripts]
    scan.scripts_approved = statuses.count(AuthorizationStatus.APPROVED)
    scan.scripts_pending = statuses.count(AuthorizationStatus.PENDING)
    scan.scripts_rejected = statuses.count(AuthorizationStatus.REJECTED)
    scan.findings_new = len(raised)
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

    The caller owns the transaction. Reads happen up front, the network phase (pages, then
    the external scripts they reference) holds no locks, and all writes happen at the end.
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
    scripts = await fetch_scripts(results, fetcher, concurrency=concurrency, clock=clock)
    return await record_scan(
        session,
        site,
        results,
        trigger=trigger,
        started_at=started_at,
        scripts=scripts,
        clock=clock,
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


# Loaded with a scan's observations and fetches; bodies stay in the database.
_VERSION_SUMMARY = (
    ScriptVersion.id,
    ScriptVersion.script_id,
    ScriptVersion.sha384,
    ScriptVersion.size_bytes,
)


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
                .selectinload(ScriptObservation.script),
                selectinload(Scan.snapshots)
                .selectinload(PageSnapshot.observations)
                .selectinload(ScriptObservation.version)
                .load_only(*_VERSION_SUMMARY),
                selectinload(Scan.script_fetches).selectinload(ScriptFetch.script),
                selectinload(Scan.script_fetches)
                .selectinload(ScriptFetch.version)
                .load_only(*_VERSION_SUMMARY),
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
