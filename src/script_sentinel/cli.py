"""``sentinel`` command-line interface."""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Annotated, Any

import typer
from sqlalchemy.ext.asyncio import AsyncSession

from script_sentinel import __version__, scanner, sites, versions
from script_sentinel.config import Settings
from script_sentinel.db import make_engine, make_sessionmaker
from script_sentinel.db.models import (
    PageSnapshot,
    Scan,
    ScanStatus,
    ScanTrigger,
    Script,
    ScriptFetchOutcome,
    ScriptKind,
    ScriptObservation,
    ScriptVersion,
    SnapshotOutcome,
    SriStatus,
)
from script_sentinel.fetch import PageFetcher
from script_sentinel.headers import describe as describe_headers

app = typer.Typer(
    help="script-sentinel: integrity monitoring for the third-party scripts your pages load.",
    no_args_is_help=True,
    add_completion=False,
)
db_app = typer.Typer(help="Manage the database schema (Alembic migrations).", no_args_is_help=True)
app.add_typer(db_app, name="db")
sites_app = typer.Typer(help="Register and inspect monitored sites.", no_args_is_help=True)
app.add_typer(sites_app, name="sites")
pages_app = typer.Typer(help="Register the pages of a site that get scanned.", no_args_is_help=True)
app.add_typer(pages_app, name="pages")
scan_app = typer.Typer(help="Scan a site's pages and inspect past scans.", no_args_is_help=True)
app.add_typer(scan_app, name="scan")
scripts_app = typer.Typer(help="Inspect a site's script inventory.", no_args_is_help=True)
app.add_typer(scripts_app, name="scripts")

# `sentinel scan run` exits with this when any page could not be inventoried.
EXIT_SCAN_INCOMPLETE = 3

DatabaseURL = Annotated[
    str | None,
    typer.Option("--url", help="Database URL. Defaults to SENTINEL_DATABASE_URL."),
]
JsonOutput = Annotated[bool, typer.Option("--json", help="Print JSON instead of text.")]


def _url(url: str | None) -> str:
    return url or Settings().database_url


def _run[T](url: str | None, work: Callable[[AsyncSession], Awaitable[T]]) -> T:
    """Run ``work`` in one transaction, mapping domain errors to a clean exit."""

    async def main() -> T:
        engine = make_engine(_url(url))
        try:
            async with make_sessionmaker(engine)() as session, session.begin():
                return await work(session)
        finally:
            await engine.dispose()

    try:
        return asyncio.run(main())
    except sites.SiteError as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2 if isinstance(exc, sites.ValidationError) else 1) from exc


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(__version__)


@app.command()
def serve(
    host: Annotated[str, typer.Option(help="Bind address.")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Port.")] = 8080,
) -> None:  # pragma: no cover - thin wrapper around uvicorn
    """Run the HTTP API (settings come from SENTINEL_* environment variables)."""
    import uvicorn

    from script_sentinel.app import create_app

    settings = Settings()
    uvicorn.run(create_app(settings), host=host, port=port, log_level=settings.log_level)


@db_app.command("upgrade")
def db_upgrade(
    revision: Annotated[str, typer.Argument(help="Target revision.")] = "head",
    url: DatabaseURL = None,
) -> None:
    """Apply migrations up to REVISION."""
    from script_sentinel.db import migrate

    migrate.upgrade(_url(url), revision)
    typer.echo(f"database upgraded to {revision}")


@db_app.command("downgrade")
def db_downgrade(
    revision: Annotated[str, typer.Argument(help="Target revision, e.g. 'base'.")],
    url: DatabaseURL = None,
) -> None:
    """Revert migrations down to REVISION."""
    from script_sentinel.db import migrate

    migrate.downgrade(_url(url), revision)
    typer.echo(f"database downgraded to {revision}")


@db_app.command("current")
def db_current(url: DatabaseURL = None) -> None:
    """Show the applied revision."""
    from script_sentinel.db import migrate

    migrate.current(_url(url))


@sites_app.command("add")
def sites_add(
    name: Annotated[str, typer.Argument(help="Short name, e.g. 'shop'.")],
    origins: Annotated[
        list[str],
        typer.Option(
            "--origin", "-o", help="Allowed origin (repeatable), e.g. https://shop.example.com."
        ),
    ],
    interval: Annotated[
        int | None,
        typer.Option("--interval-hours", min=1, max=168, help="Hours between scans."),
    ] = None,
    ignore_robots: Annotated[
        bool,
        typer.Option(
            "--ignore-robots",
            help="Don't ask robots.txt (for your own pages that it disallows for crawlers).",
        ),
    ] = False,
    url: DatabaseURL = None,
) -> None:
    """Register a site and the origins its pages may be fetched from."""
    hours = interval or Settings().default_scan_interval_hours

    async def work(session: AsyncSession) -> None:
        site = await sites.create_site(
            session,
            name=name,
            allowed_origins=origins,
            scan_interval_hours=hours,
            respect_robots=not ignore_robots,
        )
        typer.echo(
            f"added site {site.name}: {', '.join(site.allowed_origins)} "
            f"(scan every {site.scan_interval_hours}h"
            + ("" if site.respect_robots else ", robots.txt ignored")
            + ")"
        )

    _run(url, work)


@sites_app.command("update")
def sites_update(
    name: str,
    interval: Annotated[
        int | None,
        typer.Option("--interval-hours", min=1, max=168, help="Hours between scans."),
    ] = None,
    robots: Annotated[
        bool | None,
        typer.Option(
            "--respect-robots/--ignore-robots", help="Whether scans ask robots.txt first."
        ),
    ] = None,
    url: DatabaseURL = None,
) -> None:
    """Change a site's scan interval or robots.txt handling."""

    async def work(session: AsyncSession) -> None:
        site = await sites.update_site(
            session, name, scan_interval_hours=interval, respect_robots=robots
        )
        typer.echo(
            f"updated site {site.name}: scan every {site.scan_interval_hours}h, "
            f"robots.txt {'respected' if site.respect_robots else 'ignored'}"
        )

    _run(url, work)


@sites_app.command("list")
def sites_list(as_json: JsonOutput = False, url: DatabaseURL = None) -> None:
    """List sites with their page counts."""

    async def work(session: AsyncSession) -> None:
        summaries = await sites.list_sites(session)
        if as_json:
            typer.echo(
                json.dumps(
                    [
                        {
                            "name": s.site.name,
                            "allowed_origins": s.site.allowed_origins,
                            "scan_interval_hours": s.site.scan_interval_hours,
                            "pages": s.page_count,
                            "payment_pages": s.payment_page_count,
                        }
                        for s in summaries
                    ],
                    indent=2,
                )
            )
            return
        if not summaries:
            typer.echo("no sites yet; add one with: sentinel sites add NAME --origin URL")
            return
        for s in summaries:
            typer.echo(
                f"{s.site.name:<20} pages={s.page_count:<4} payment={s.payment_page_count:<4} "
                f"every {s.site.scan_interval_hours}h  {', '.join(s.site.allowed_origins)}"
            )

    _run(url, work)


@sites_app.command("remove")
def sites_remove(
    name: str,
    yes: Annotated[bool, typer.Option("--yes", help="Don't ask for confirmation.")] = False,
    url: DatabaseURL = None,
) -> None:
    """Delete a site with its pages, inventory and findings."""
    if not yes:
        typer.confirm(f"delete site {name!r} and everything recorded for it?", abort=True)

    async def work(session: AsyncSession) -> None:
        await sites.delete_site(session, name)
        typer.echo(f"removed site {name}")

    _run(url, work)


@pages_app.command("add")
def pages_add(
    site: Annotated[str, typer.Argument(help="Site name.")],
    page_url: Annotated[str, typer.Argument(metavar="URL", help="Page URL on an allowed origin.")],
    label: Annotated[str | None, typer.Option(help="Short label, e.g. 'checkout'.")] = None,
    payment: Annotated[
        bool, typer.Option("--payment", help="Mark as a payment page (PCI DSS scope).")
    ] = False,
    url: DatabaseURL = None,
) -> None:
    """Register a page to scan."""

    async def work(session: AsyncSession) -> None:
        page = await sites.add_page(session, site, url=page_url, label=label, payment_page=payment)
        typer.echo(f"added page {page.url}" + (" (payment page)" if page.payment_page else ""))

    _run(url, work)


@pages_app.command("list")
def pages_list(site: str, as_json: JsonOutput = False, url: DatabaseURL = None) -> None:
    """List the pages of a site."""

    async def work(session: AsyncSession) -> None:
        pages = await sites.list_pages(session, site)
        if as_json:
            typer.echo(
                json.dumps(
                    [
                        {"url": p.url, "label": p.label, "payment_page": p.payment_page}
                        for p in pages
                    ],
                    indent=2,
                )
            )
            return
        for p in pages:
            flag = "payment" if p.payment_page else "       "
            typer.echo(f"{flag}  {p.url}" + (f"  ({p.label})" if p.label else ""))

    _run(url, work)


@pages_app.command("remove")
def pages_remove(
    site: str, page_url: Annotated[str, typer.Argument(metavar="URL")], url: DatabaseURL = None
) -> None:
    """Stop scanning a page."""

    async def work(session: AsyncSession) -> None:
        await sites.remove_page(session, site, page_url)
        typer.echo(f"removed page {page_url}")

    _run(url, work)


_OUTCOME_LABEL = {
    SnapshotOutcome.OK: "ok",
    SnapshotOutcome.ROBOTS_DISALLOWED: "robots",
    SnapshotOutcome.REDIRECT_BLOCKED: "blocked",
    SnapshotOutcome.HTTP_ERROR: "http",
    SnapshotOutcome.NOT_HTML: "not-html",
    SnapshotOutcome.TOO_LARGE: "too-big",
    SnapshotOutcome.FETCH_ERROR: "error",
}


def _scan_json(scan: Scan, site_name: str) -> dict[str, Any]:
    return {
        "id": str(scan.id),
        "site": site_name,
        "status": scan.status.value,
        "trigger": scan.trigger.value,
        "started_at": scan.started_at.isoformat(),
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        "pages": {
            "total": scan.pages_total,
            "ok": scan.pages_ok,
            "skipped": scan.pages_skipped,
            "failed": scan.pages_failed,
        },
        "scripts": {
            "seen": scan.scripts_seen,
            "new": scan.scripts_new,
            "fetched": scan.scripts_fetched,
            "fetch_failed": scan.scripts_fetch_failed,
            "versions_new": scan.versions_new,
            "changed": scan.scripts_changed,
        },
        "snapshots": [_snapshot_json(snap) for snap in scan.snapshots],
        "script_fetches": [
            {
                "url": f.url,
                "outcome": f.outcome.value,
                "http_status": f.http_status,
                "final_url": f.final_url,
                "content_type": f.content_type,
                "size_bytes": f.size_bytes,
                "error": f.error,
                "sha384": f.version.sha384 if f.version else None,
                "sri": f.version.sri if f.version else None,
                "new_version": f.new_version,
            }
            for f in scan.script_fetches
        ],
    }


def _snapshot_json(snap: PageSnapshot) -> dict[str, Any]:
    return {
        "url": snap.url,
        "payment_page": snap.payment_page,
        "outcome": snap.outcome.value,
        "final_url": snap.final_url,
        "http_status": snap.http_status,
        "elapsed_ms": snap.elapsed_ms,
        "error": snap.error,
        "warnings": snap.warnings,
        "security_headers": snap.security_headers,
        "meta_csp": snap.meta_csp,
        "scripts": [
            {
                "position": obs.position,
                "kind": obs.script.kind.value,
                "locator": obs.script.locator,
                "type": obs.script_type.value,
                "integrity": obs.integrity,
                "has_nonce": obs.nonce_digest is not None,
                "inline_sha384": obs.inline_sha384,
                "sha384": obs.version.sha384 if obs.version else None,
                "sri": obs.version.sri if obs.version else None,
                "sri_status": obs.sri_status.value if obs.sri_status else None,
            }
            for obs in snap.observations
        ],
    }


_SRI_LABEL = {
    SriStatus.MATCH: "integrity ok",
    SriStatus.MISMATCH: "INTEGRITY MISMATCH",
    SriStatus.NO_SUPPORTED_HASH: "integrity unusable",
    SriStatus.UNVERIFIED: "integrity unverified",
}


@dataclass(frozen=True, slots=True)
class _Changes:
    """What a scan saw for the first time (only known right after running it)."""

    new_locators: set[str] = field(default_factory=set)
    changed_scripts: set[uuid.UUID] = field(default_factory=set)


def _short(sri: str, width: int = 22) -> str:
    return sri if len(sri) <= width else sri[:width] + "…"


def _observation_line(
    obs: ScriptObservation, failed: dict[uuid.UUID, str], changes: _Changes
) -> str:
    if obs.script.locator in changes.new_locators:
        marker = "+"
    elif obs.script_id in changes.changed_scripts:
        marker = "~"
    elif obs.script_id in failed:
        marker = "!"
    else:
        marker = " "
    extras = [obs.script_type.value]
    if obs.sri_status is not None:
        extras.append(_SRI_LABEL[obs.sri_status])
    elif obs.integrity:
        extras.append("integrity")
    if obs.nonce_digest:
        extras.append("nonce")
    if obs.script_id in failed:
        extras.append(f"not fetched: {failed[obs.script_id]}")
    body = f"  {_short(obs.version.sri)}" if obs.version else ""
    return f"      {marker} {obs.script.locator}  ({', '.join(extras)}){body}"


def _print_scan(scan: Scan, site_name: str, changes: _Changes) -> None:
    elapsed = (
        f" in {(scan.finished_at - scan.started_at).total_seconds():.2f}s"
        if scan.finished_at
        else ""
    )
    parts = [f"{scan.pages_ok} ok"]
    if scan.pages_skipped:
        parts.append(f"{scan.pages_skipped} skipped")
    if scan.pages_failed:
        parts.append(f"{scan.pages_failed} failed")
    typer.echo(
        f"scan {scan.id} of {site_name}: {scan.status.value}{elapsed} "
        f"({scan.pages_total} pages: {', '.join(parts)})"
    )
    failed = {
        f.script_id: f.error or f.outcome.value
        for f in scan.script_fetches
        if f.outcome is not ScriptFetchOutcome.OK
    }
    mismatched = 0
    for snap in scan.snapshots:
        label = _OUTCOME_LABEL[snap.outcome]
        flag = " [payment]" if snap.payment_page else ""
        if snap.outcome is SnapshotOutcome.OK:
            fresh = sum(1 for o in snap.observations if o.script.locator in changes.new_locators)
            typer.echo(
                f"  {label:<8} {snap.url}{flag}  {snap.http_status}  "
                f"{len(snap.observations)} scripts" + (f" ({fresh} new)" if fresh else "")
            )
            typer.echo(f"      headers: {describe_headers(snap.security_headers, snap.meta_csp)}")
            for obs in snap.observations:
                typer.echo(_observation_line(obs, failed, changes))
                mismatched += obs.sri_status is SriStatus.MISMATCH
            for warning in snap.warnings:
                typer.echo(f"      ! {warning}")
        else:
            typer.echo(f"  {label:<8} {snap.url}{flag}  {snap.error}")
    typer.echo(
        f"inventory: {scan.scripts_seen} scripts seen, {scan.scripts_new} new (pending approval)"
    )
    typer.echo(
        f"bodies: {scan.scripts_fetched} external fetched, {scan.scripts_fetch_failed} failed; "
        f"{scan.versions_new} new versions, {scan.scripts_changed} scripts changed"
    )
    skipped_payment = [
        s.url
        for s in scan.snapshots
        if s.payment_page and s.outcome is SnapshotOutcome.ROBOTS_DISALLOWED
    ]
    if skipped_payment:
        typer.secho(
            "warning: robots.txt kept payment pages out of this scan; if they are your own "
            f"pages, run: sentinel sites update {site_name} --ignore-robots",
            fg=typer.colors.YELLOW,
            err=True,
        )
    if mismatched:
        typer.secho(
            f"warning: {mismatched} script tags fail their integrity check; "
            "browsers will refuse to run them",
            fg=typer.colors.YELLOW,
            err=True,
        )
    if failed:
        typer.secho(
            f"warning: {len(failed)} external scripts could not be fetched, so their "
            "integrity was not checked this scan",
            fg=typer.colors.YELLOW,
            err=True,
        )


@scan_app.command("run")
def scan_run(
    site: Annotated[str, typer.Argument(help="Site name.")],
    as_json: JsonOutput = False,
    url: DatabaseURL = None,
) -> None:
    """Fetch every page of SITE now, record its scripts and print what was found.

    Exits 3 when any page could not be inventoried.
    """
    settings = Settings()

    async def work(session: AsyncSession) -> tuple[Scan, str, _Changes]:
        known = await scanner.list_scripts(session, site)
        before = {s.locator for s in known}
        known_versions = await versions.versions_by_script(session, [s.id for s in known])
        async with PageFetcher(settings.fetch_limits()) as fetcher:
            scan = await scanner.scan_site(
                session,
                site,
                fetcher,
                trigger=ScanTrigger.CLI,
                concurrency=settings.scan_concurrency,
            )
        detailed, name = await scanner.get_scan(session, scan.id)
        after = {s.locator for s in await scanner.list_scripts(session, site)}
        changed = {
            obs.script_id
            for snap in detailed.snapshots
            for obs in snap.observations
            if obs.version_id is not None
            and known_versions.get(obs.script_id)
            and obs.version_id not in {v.id for v in known_versions[obs.script_id]}
        }
        return detailed, name, _Changes(after - before, changed)

    scan, name, changes = _run(url, work)
    if as_json:
        typer.echo(json.dumps(_scan_json(scan, name), indent=2))
    else:
        _print_scan(scan, name, changes)
    if scan.status is not ScanStatus.COMPLETED:
        raise typer.Exit(code=EXIT_SCAN_INCOMPLETE)


@scan_app.command("list")
def scan_list(
    site: str,
    limit: Annotated[int, typer.Option(min=1, max=200, help="How many scans.")] = 20,
    as_json: JsonOutput = False,
    url: DatabaseURL = None,
) -> None:
    """List recent scans of a site, newest first."""

    async def work(session: AsyncSession) -> list[Scan]:
        return await scanner.list_scans(session, site, limit=limit)

    scans = _run(url, work)
    if as_json:
        typer.echo(
            json.dumps(
                [
                    {
                        "id": str(s.id),
                        "status": s.status.value,
                        "trigger": s.trigger.value,
                        "started_at": s.started_at.isoformat(),
                        "pages_ok": s.pages_ok,
                        "pages_skipped": s.pages_skipped,
                        "pages_failed": s.pages_failed,
                        "scripts_seen": s.scripts_seen,
                        "scripts_new": s.scripts_new,
                    }
                    for s in scans
                ],
                indent=2,
            )
        )
        return
    if not scans:
        typer.echo(f"no scans of {site} yet; run one with: sentinel scan run {site}")
        return
    for s in scans:
        typer.echo(
            f"{s.started_at:%Y-%m-%d %H:%M:%S}Z  {s.id}  {s.status.value:<9} {s.trigger.value:<8} "
            f"pages ok={s.pages_ok} skipped={s.pages_skipped} failed={s.pages_failed}  "
            f"scripts={s.scripts_seen} new={s.scripts_new}"
        )


@scan_app.command("show")
def scan_show(
    scan_id: Annotated[str, typer.Argument(metavar="SCAN_ID")],
    as_json: JsonOutput = False,
    url: DatabaseURL = None,
) -> None:
    """Show one scan with every page and script it saw."""
    try:
        parsed = uuid.UUID(scan_id)
    except ValueError:
        typer.secho(f"error: {scan_id!r} is not a scan id", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from None

    async def work(session: AsyncSession) -> tuple[Scan, str]:
        return await scanner.get_scan(session, parsed)

    scan, name = _run(url, work)
    if as_json:
        typer.echo(json.dumps(_scan_json(scan, name), indent=2))
    else:
        _print_scan(scan, name, _Changes())


def _version_json(version: ScriptVersion) -> dict[str, Any]:
    return {
        "id": str(version.id),
        "sha384": version.sha384,
        "normalized_sha384": version.normalized_sha384,
        "sri": version.sri,
        "size_bytes": version.size_bytes,
        "first_seen_at": version.first_seen_at.isoformat(),
        "last_seen_at": version.last_seen_at.isoformat(),
    }


def _script_json(script: Script, history: list[ScriptVersion]) -> dict[str, Any]:
    return {
        "id": str(script.id),
        "kind": script.kind.value,
        "locator": script.locator,
        "status": script.status.value,
        "first_seen_at": script.first_seen_at.isoformat(),
        "last_seen_at": script.last_seen_at.isoformat(),
        "version_count": len(history),
        "current_sri": history[0].sri if history else None,
    }


@scripts_app.command("list")
def scripts_list(site: str, as_json: JsonOutput = False, url: DatabaseURL = None) -> None:
    """List every script ever seen on a site, with its status and current SRI value."""

    async def work(session: AsyncSession) -> list[dict[str, Any]]:
        scripts = await scanner.list_scripts(session, site)
        by_script = await versions.versions_by_script(session, [s.id for s in scripts])
        return [_script_json(s, by_script[s.id]) for s in scripts]

    scripts = _run(url, work)
    if as_json:
        typer.echo(json.dumps(scripts, indent=2))
        return
    if not scripts:
        typer.echo(f"no scripts recorded for {site} yet; run: sentinel scan run {site}")
        return
    for s in scripts:
        sri = _short(s["current_sri"]) if s["current_sri"] else "(no body yet)"
        count = f"v{s['version_count']}"
        typer.echo(f"{s['status']:<9} {s['kind']:<9} {count:<4} {sri:<25} {s['locator']}")


@scripts_app.command("show")
def scripts_show(
    site: str,
    locator: Annotated[str, typer.Argument(help="The script's src URL, or PAGE#inline-N.")],
    as_json: JsonOutput = False,
    url: DatabaseURL = None,
) -> None:
    """Show a script's version history, with the SRI value (or CSP hash) of each body."""

    async def work(session: AsyncSession) -> tuple[Script, list[ScriptVersion]]:
        script = await versions.find_script(session, site, locator)
        history = (await versions.versions_by_script(session, [script.id]))[script.id]
        return script, history

    script, history = _run(url, work)
    if as_json:
        typer.echo(
            json.dumps(
                {**_script_json(script, history), "versions": [_version_json(v) for v in history]},
                indent=2,
            )
        )
        return
    typer.echo(f"{script.locator}")
    typer.echo(f"  kind: {script.kind.value}   status: {script.status.value}")
    typer.echo(
        f"  seen: {script.first_seen_at:%Y-%m-%d %H:%M:%S}Z .. "
        f"{script.last_seen_at:%Y-%m-%d %H:%M:%S}Z"
    )
    if not history:
        typer.echo("  no body recorded yet (the script could not be fetched)")
        return
    typer.echo(f"  versions ({len(history)}, most recently seen first):")
    for version in history:
        typer.echo(
            f"    {version.last_seen_at:%Y-%m-%d %H:%M:%S}Z  {version.size_bytes:>8} bytes  "
            f"{version.sri}"
        )
    current = history[0]
    if script.kind is ScriptKind.EXTERNAL:
        typer.echo("  pin the current body with:")
        typer.echo(
            f'    <script src="{script.locator}" integrity="{current.sri}" '
            'crossorigin="anonymous"></script>'
        )
    else:
        typer.echo(f"  CSP hash source for the current body: '{current.sri}'")
