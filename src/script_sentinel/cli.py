"""``sentinel`` command-line interface."""

from __future__ import annotations

import asyncio
import getpass
import json
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Annotated, Any

import typer
from sqlalchemy.ext.asyncio import AsyncSession

from script_sentinel import __version__, audit, authorization, findings, scanner, sites, versions
from script_sentinel.config import Settings
from script_sentinel.db import make_engine, make_sessionmaker
from script_sentinel.db.models import (
    ApprovalScope,
    AuthorizationEvent,
    AuthorizationStatus,
    ChangePolicy,
    Finding,
    FindingKind,
    FindingStatus,
    PageSnapshot,
    Policy,
    PolicyKind,
    Scan,
    ScanStatus,
    ScanTrigger,
    Script,
    ScriptFetchOutcome,
    ScriptKind,
    ScriptObservation,
    ScriptVersion,
    Severity,
    SnapshotOutcome,
    SriStatus,
)
from script_sentinel.diff import Hunk, render_hunks
from script_sentinel.diff import render as render_diff
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
scripts_app = typer.Typer(
    help="Inspect a site's script inventory and approve or reject scripts.", no_args_is_help=True
)
app.add_typer(scripts_app, name="scripts")
policies_app = typer.Typer(
    help="Authorize scripts in bulk: by origin, URL prefix or hash.", no_args_is_help=True
)
app.add_typer(policies_app, name="policies")
audit_app = typer.Typer(help="Read and verify the authorization audit trail.", no_args_is_help=True)
app.add_typer(audit_app, name="audit")
findings_app = typer.Typer(
    help="Review what scans noticed: new scripts and changed bodies, with diffs.",
    no_args_is_help=True,
)
app.add_typer(findings_app, name="findings")

# `sentinel scan run` exits with this when any page could not be inventoried...
EXIT_SCAN_INCOMPLETE = 3
# ...and with this, under --fail-on-unauthorized, when a payment page runs a script that
# isn't approved (it wins over EXIT_SCAN_INCOMPLETE)...
EXIT_UNAUTHORIZED = 4
# ...and with this, under --fail-on SEVERITY, when the scan raised a finding at least that
# severe (it wins over both).
EXIT_FINDINGS = 5

DatabaseURL = Annotated[
    str | None,
    typer.Option("--url", help="Database URL. Defaults to SENTINEL_DATABASE_URL."),
]
JsonOutput = Annotated[bool, typer.Option("--json", help="Print JSON instead of text.")]
Actor = Annotated[
    str | None,
    typer.Option(
        "--actor",
        envvar="SENTINEL_ACTOR",
        help="Who is making the change, for the audit trail. Defaults to SENTINEL_ACTOR, "
        "then the login name.",
    ),
]


def _actor(actor: str | None) -> str:
    if actor:
        return actor
    try:
        return getpass.getuser()
    except (KeyError, OSError):  # pragma: no cover - no login name in some containers
        return "unknown"


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


def _finding_json(finding: Finding, *, detail: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": str(finding.id),
        "kind": finding.kind,
        "severity": finding.severity.value,
        "status": finding.status.value,
        "title": finding.title,
        "locator": finding.locator,
        "script_id": str(finding.script_id) if finding.script_id else None,
        "version_id": str(finding.version_id) if finding.version_id else None,
        "previous_version_id": (
            str(finding.previous_version_id) if finding.previous_version_id else None
        ),
        "scan_id": str(finding.scan_id) if finding.scan_id else None,
        "reasons": finding.detail.get("reasons", []),
        "created_at": finding.created_at.isoformat(),
        "status_changed_at": (
            finding.status_changed_at.isoformat() if finding.status_changed_at else None
        ),
        "status_changed_by": finding.status_changed_by,
        "status_note": finding.status_note,
    }
    if detail:
        out["detail"] = finding.detail
    return out


def _scan_json(scan: Scan, site_name: str, raised: list[Finding]) -> dict[str, Any]:
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
        "authorization": {
            "approved": scan.scripts_approved,
            "pending": scan.scripts_pending,
            "rejected": scan.scripts_rejected,
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
        "findings": [_finding_json(f) for f in raised],
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
                "authorization_status": (
                    obs.authorization_status.value if obs.authorization_status else None
                ),
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
    """What a scan noticed: scripts it saw first, and scripts serving a different body."""

    new_locators: set[str] = field(default_factory=set)
    changed_scripts: set[uuid.UUID] = field(default_factory=set)

    @classmethod
    def of(cls, raised: list[Finding], new_locators: set[str] | None = None) -> _Changes:
        return cls(
            new_locators if new_locators is not None else set(),
            {
                f.script_id
                for f in raised
                if f.script_id is not None and f.kind != FindingKind.SCRIPT_ADDED
            },
        )


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
    if obs.authorization_status is not None:
        extras.append(obs.authorization_status.value)
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


_SEVERITY_COLOR = {
    Severity.INFO: None,
    Severity.LOW: None,
    Severity.MEDIUM: typer.colors.YELLOW,
    Severity.HIGH: typer.colors.RED,
    Severity.CRITICAL: typer.colors.RED,
}


def _finding_line(finding: Finding, *, with_id: bool = False) -> None:
    ident = f"{finding.id}  " if with_id else ""
    typer.secho(
        f"  {finding.severity.value.upper():<8} {ident}{finding.title}",
        fg=_SEVERITY_COLOR[finding.severity],
        bold=finding.severity is Severity.CRITICAL,
    )
    typer.echo(f"           {'; '.join(finding.detail.get('reasons', []))}")


def _print_findings(raised: list[Finding]) -> None:
    if not raised:
        return
    typer.echo(f"findings: {len(raised)} (review with: sentinel findings show ID)")
    for finding in raised:
        _finding_line(finding, with_id=True)


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
    typer.echo(f"inventory: {scan.scripts_seen} scripts seen, {scan.scripts_new} new")
    typer.echo(
        f"authorization: {scan.scripts_approved} approved, {scan.scripts_pending} pending, "
        f"{scan.scripts_rejected} rejected"
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
    unauthorized = _unauthorized_on_payment_pages(scan)
    if unauthorized:
        typer.secho(
            f"warning: payment pages run {len(unauthorized)} scripts that are not approved "
            f"(PCI DSS 6.4.3); review them with: sentinel scripts list {site_name}",
            fg=typer.colors.YELLOW,
            err=True,
        )


def _unauthorized_on_payment_pages(scan: Scan) -> set[str]:
    return {
        obs.script.locator
        for snap in scan.snapshots
        if snap.payment_page
        for obs in snap.observations
        if obs.authorization_status not in (None, AuthorizationStatus.APPROVED)
    }


@scan_app.command("run")
def scan_run(
    site: Annotated[str, typer.Argument(help="Site name.")],
    fail_on_unauthorized: Annotated[
        bool,
        typer.Option(
            "--fail-on-unauthorized",
            help="Exit 4 when a payment page runs a script that isn't approved.",
        ),
    ] = False,
    fail_on: Annotated[
        Severity | None,
        typer.Option(
            "--fail-on",
            help="Exit 5 when the scan raises a finding at least this severe.",
            case_sensitive=False,
        ),
    ] = None,
    as_json: JsonOutput = False,
    url: DatabaseURL = None,
) -> None:
    """Fetch every page of SITE now, record its scripts and print what was found.

    Exits 3 when any page could not be inventoried, 4 with --fail-on-unauthorized when a
    payment page runs a script that isn't approved, and 5 with --fail-on SEVERITY when the
    scan raised a finding at least that severe (5 wins over 4, and 4 over 3).
    """
    settings = Settings()

    async def work(session: AsyncSession) -> tuple[Scan, str, list[Finding], _Changes]:
        known = await scanner.list_scripts(session, site)
        before = {s.locator for s in known}
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
        raised = await findings.scan_findings(session, scan.id)
        return detailed, name, raised, _Changes.of(raised, after - before)

    scan, name, raised, changes = _run(url, work)
    if as_json:
        typer.echo(json.dumps(_scan_json(scan, name, raised), indent=2))
    else:
        _print_scan(scan, name, changes)
        _print_findings(raised)
    if fail_on is not None and findings.any_at_least(raised, fail_on):
        raise typer.Exit(code=EXIT_FINDINGS)
    if fail_on_unauthorized and _unauthorized_on_payment_pages(scan):
        raise typer.Exit(code=EXIT_UNAUTHORIZED)
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

    async def work(session: AsyncSession) -> tuple[Scan, str, list[Finding]]:
        scan, name = await scanner.get_scan(session, parsed)
        return scan, name, await findings.scan_findings(session, parsed)

    scan, name, raised = _run(url, work)
    if as_json:
        typer.echo(json.dumps(_scan_json(scan, name, raised), indent=2))
    else:
        _print_scan(scan, name, _Changes.of(raised))
        _print_findings(raised)


def _version_json(version: ScriptVersion) -> dict[str, Any]:
    return {
        "id": str(version.id),
        "sha384": version.sha384,
        "normalized_sha384": version.normalized_sha384,
        "sri": version.sri,
        "size_bytes": version.size_bytes,
        "first_seen_at": version.first_seen_at.isoformat(),
        "last_seen_at": version.last_seen_at.isoformat(),
        "approved_at": version.approved_at.isoformat() if version.approved_at else None,
        "approved_by": version.approved_by,
    }


def _script_json(script: Script, history: list[ScriptVersion]) -> dict[str, Any]:
    return {
        "id": str(script.id),
        "kind": script.kind.value,
        "locator": script.locator,
        "status": script.status.value,
        "status_reason": script.status_reason,
        "policy_id": str(script.policy_id) if script.policy_id else None,
        "decision": script.decision.value if script.decision else None,
        "approval_scope": script.approval_scope.value if script.approval_scope else None,
        "justification": script.justification,
        "decided_by": script.decided_by,
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
    if script.status_reason:
        typer.echo(f"  why: {script.status_reason}")
    if script.decision is not None and script.decided_at is not None:
        scope = f", {script.approval_scope.value}" if script.approval_scope else ""
        typer.echo(
            f"  decision: {script.decision.value}{scope} by {script.decided_by} "
            f"at {script.decided_at:%Y-%m-%d %H:%M:%S}Z"
        )
        typer.echo(f"  justification: {script.justification}")
    typer.echo(
        f"  seen: {script.first_seen_at:%Y-%m-%d %H:%M:%S}Z .. "
        f"{script.last_seen_at:%Y-%m-%d %H:%M:%S}Z"
    )
    if not history:
        typer.echo("  no body recorded yet (the script could not be fetched)")
        return
    typer.echo(f"  versions ({len(history)}, most recently seen first):")
    for version in history:
        approved = f"  approved by {version.approved_by}" if version.approved_by else ""
        typer.echo(
            f"    {version.last_seen_at:%Y-%m-%d %H:%M:%S}Z  {version.size_bytes:>8} bytes  "
            f"{version.sri}{approved}"
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


Locator = Annotated[str, typer.Argument(help="The script's src URL, or PAGE#inline-N.")]


def _print_analysis(detail: dict[str, Any], hunks_text: str) -> None:
    size, ent, tokens = detail["size"], detail["entropy"], detail["tokens"]
    entropy_delta = round(ent["delta"], 2) or 0.0  # never "-0.00"
    typer.echo(
        f"  size: {size['old']} -> {size['new']} bytes ({size['delta']:+d})   "
        f"entropy: {ent['old']:.2f} -> {ent['new']:.2f} bits/char ({entropy_delta:+.2f})"
    )
    typer.echo(
        f"  tokens: -{tokens['removed']} +{tokens['added']} of {tokens['old']} -> "
        f"{tokens['new']} (similarity {tokens['similarity']:.0%})"
        + ("  [coarse: parts compared whole]" if detail.get("coarse") else "")
    )
    for label, key in (
        ("new hosts", "hosts_added"),
        ("hosts no longer referenced", "hosts_removed"),
        ("new URLs", "urls_added"),
    ):
        if detail.get(key):
            typer.echo(f"  {label}: {', '.join(detail[key][:10])}")
    if hunks_text:
        typer.echo(hunks_text)


@scripts_app.command("diff")
def scripts_diff(
    site: str,
    locator: Locator,
    from_ref: Annotated[
        str | None,
        typer.Option(
            "--from", help="Version id, or a SHA-384 or SRI prefix. Default: the one before."
        ),
    ] = None,
    to_ref: Annotated[
        str | None,
        typer.Option("--to", help="Version id, or a SHA-384 or SRI prefix. Default: the latest."),
    ] = None,
    max_hunks: Annotated[int, typer.Option(min=1, help="Hunks to print.")] = 20,
    as_json: JsonOutput = False,
    url: DatabaseURL = None,
) -> None:
    """Show the token diff between two versions of a script.

    Comments and whitespace are ignored, so a minified one-line bundle diffs down to the
    tokens that changed.
    """

    async def work(session: AsyncSession) -> versions.VersionDiff:
        script = await versions.find_script(session, site, locator)
        return await versions.diff_versions(
            session, site, script.id, from_ref=from_ref, to_ref=to_ref
        )

    result = _run(url, work)
    detail = result.analysis.to_dict(max_hunks=max_hunks)
    if as_json:
        typer.echo(
            json.dumps(
                {
                    "locator": result.script.locator,
                    "from": _version_json(result.old),
                    "to": _version_json(result.new),
                    **detail,
                },
                indent=2,
            )
        )
        return
    typer.echo(result.script.locator)
    typer.echo(f"  from {result.old.sri}  (first seen {result.old.first_seen_at:%Y-%m-%d %H:%M}Z)")
    typer.echo(f"  to   {result.new.sri}  (first seen {result.new.first_seen_at:%Y-%m-%d %H:%M}Z)")
    if result.analysis.diff.identical:
        typer.echo("  same code: only comments or whitespace differ")
    _print_analysis(detail, render_diff(result.analysis.diff, max_hunks=max_hunks))


def _decision(
    site: str,
    locator: str,
    url: str | None,
    decide: Callable[[AsyncSession, uuid.UUID], Awaitable[Script]],
) -> None:
    async def work(session: AsyncSession) -> Script:
        script = await versions.find_script(session, site, locator)
        return await decide(session, script.id)

    script = _run(url, work)
    typer.echo(f"{script.status.value}: {script.locator}")
    typer.echo(f"  why: {script.status_reason}")


@scripts_app.command("approve")
def scripts_approve(
    site: str,
    locator: Locator,
    justification: Annotated[
        str,
        typer.Option("--justification", "-j", help="Why the script is necessary (PCI DSS 6.4.3)."),
    ],
    any_version: Annotated[
        bool,
        typer.Option(
            "--any-version",
            help="Approve whatever the vendor serves, not just the current body.",
        ),
    ] = False,
    actor: Actor = None,
    url: DatabaseURL = None,
) -> None:
    """Approve a script. By default the approval is pinned to the bodies it serves now."""
    scope = ApprovalScope.ANY_VERSION if any_version else ApprovalScope.PINNED
    _decision(
        site,
        locator,
        url,
        lambda session, script_id: authorization.approve_script(
            session,
            site,
            script_id,
            actor=_actor(actor),
            justification=justification,
            scope=scope,
        ),
    )


@scripts_app.command("reject")
def scripts_reject(
    site: str,
    locator: Locator,
    reason: Annotated[str, typer.Option("--reason", "-r", help="Why it must not run.")],
    actor: Actor = None,
    url: DatabaseURL = None,
) -> None:
    """Reject a script. A rejection overrides every policy."""
    _decision(
        site,
        locator,
        url,
        lambda session, script_id: authorization.reject_script(
            session, site, script_id, actor=_actor(actor), reason=reason
        ),
    )


@scripts_app.command("reset")
def scripts_reset(
    site: str,
    locator: Locator,
    reason: Annotated[str, typer.Option("--reason", "-r", help="Why the decision goes.")],
    actor: Actor = None,
    url: DatabaseURL = None,
) -> None:
    """Withdraw the decision about a script, so policies alone decide its status."""
    _decision(
        site,
        locator,
        url,
        lambda session, script_id: authorization.reset_script(
            session, site, script_id, actor=_actor(actor), reason=reason
        ),
    )


def _policy_json(policy: Policy) -> dict[str, Any]:
    return {
        "id": str(policy.id),
        "kind": policy.kind.value,
        "match": policy.match,
        "change": policy.change.value,
        "ignore_query": list(policy.ignore_query),
        "justification": policy.justification,
        "created_by": policy.created_by,
        "created_at": policy.created_at.isoformat(),
    }


def _changes_json(changes: list[authorization.Change]) -> list[dict[str, Any]]:
    return [
        {
            "locator": c.script.locator,
            "from_status": c.from_status.value if c.from_status else None,
            "to_status": c.to_status.value,
        }
        for c in changes
    ]


def _print_changes(changes: list[authorization.Change]) -> None:
    for c in changes:
        before = c.from_status.value if c.from_status else "new"
        typer.echo(
            f"  {before} -> {c.to_status.value}: {c.script.locator}  ({c.script.status_reason})"
        )
    if not changes:
        typer.echo("  no script changed status")


@policies_app.command("add")
def policies_add(
    site: str,
    justification: Annotated[
        str, typer.Option("--justification", "-j", help="Why these scripts are acceptable.")
    ],
    origin: Annotated[
        str | None, typer.Option("--origin", help="Every external script from this origin.")
    ] = None,
    prefix: Annotated[
        str | None,
        typer.Option("--prefix", help="Every external script under this URL prefix."),
    ] = None,
    sha384: Annotated[
        str | None,
        typer.Option("--hash", help="Any body with this SHA-384 (hex or sha384-<base64>)."),
    ] = None,
    expected_to_change: Annotated[
        bool,
        typer.Option(
            "--expected-to-change",
            help="Accept every body. Without it the first body seen is pinned.",
        ),
    ] = False,
    ignore_query: Annotated[
        list[str] | None,
        typer.Option(
            "--ignore-query",
            help="Query parameter to drop from matching URLs, e.g. a cache buster "
            "(repeatable; '*' drops the whole query).",
        ),
    ] = None,
    actor: Actor = None,
    as_json: JsonOutput = False,
    url: DatabaseURL = None,
) -> None:
    """Add a policy and re-evaluate the site's scripts under it."""
    given = [
        (k, v)
        for k, v in (
            (PolicyKind.ORIGIN, origin),
            (PolicyKind.PREFIX, prefix),
            (PolicyKind.HASH, sha384),
        )
        if v is not None
    ]
    if len(given) != 1:
        typer.secho(
            "error: give exactly one of --origin, --prefix or --hash", fg=typer.colors.RED, err=True
        )
        raise typer.Exit(code=2)
    kind, match = given[0]
    change = ChangePolicy.EXPECTED_TO_CHANGE if expected_to_change else ChangePolicy.PINNED

    async def work(session: AsyncSession) -> tuple[Policy, list[authorization.Change]]:
        return await authorization.create_policy(
            session,
            site,
            kind=kind,
            match=match,
            change=change,
            ignore_query=ignore_query or [],
            justification=justification,
            actor=_actor(actor),
        )

    policy, changes = _run(url, work)
    if as_json:
        typer.echo(
            json.dumps(
                {"policy": _policy_json(policy), "scripts_changed": _changes_json(changes)},
                indent=2,
            )
        )
        return
    typer.echo(f"added policy {policy.id}: {authorization.describe_policy(policy)}")
    _print_changes(changes)


@policies_app.command("list")
def policies_list(site: str, as_json: JsonOutput = False, url: DatabaseURL = None) -> None:
    """List a site's policies, oldest first."""

    async def work(session: AsyncSession) -> list[Policy]:
        return await authorization.list_policies(session, site)

    policies = _run(url, work)
    if as_json:
        typer.echo(json.dumps([_policy_json(p) for p in policies], indent=2))
        return
    if not policies:
        typer.echo(f"no policies for {site}; add one with: sentinel policies add {site} --help")
        return
    for p in policies:
        query = f"  ignore query: {', '.join(p.ignore_query)}" if p.ignore_query else ""
        typer.echo(f"{p.id}  {p.kind.value:<6} {p.change.value:<18} {p.match}{query}")
        typer.echo(f"    {p.justification} ({p.created_by}, {p.created_at:%Y-%m-%d})")


@policies_app.command("remove")
def policies_remove(
    site: str,
    policy_id: Annotated[str, typer.Argument(metavar="POLICY_ID")],
    reason: Annotated[str, typer.Option("--reason", "-r", help="Why the policy goes.")],
    actor: Actor = None,
    url: DatabaseURL = None,
) -> None:
    """Remove a policy and re-evaluate the scripts it covered."""
    try:
        parsed = uuid.UUID(policy_id)
    except ValueError:
        typer.secho(f"error: {policy_id!r} is not a policy id", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from None

    async def work(session: AsyncSession) -> list[authorization.Change]:
        return await authorization.remove_policy(
            session, site, parsed, actor=_actor(actor), reason=reason
        )

    changes = _run(url, work)
    typer.echo(f"removed policy {parsed}")
    _print_changes(changes)


def _event_json(event: AuthorizationEvent) -> dict[str, Any]:
    return {
        "seq": event.seq,
        "action": event.action,
        "actor": event.actor,
        "locator": event.locator,
        "script_id": str(event.script_id) if event.script_id else None,
        "policy_id": str(event.policy_id) if event.policy_id else None,
        "from_status": event.from_status,
        "to_status": event.to_status,
        "reason": event.reason,
        "detail": event.detail,
        "created_at": event.created_at.isoformat(),
        "prev_hash": event.prev_hash,
        "hash": event.hash,
    }


@audit_app.command("list")
def audit_list(
    site: str,
    locator: Annotated[
        str | None, typer.Option("--script", help="Only events about this script.")
    ] = None,
    limit: Annotated[int, typer.Option(min=1, max=1000, help="How many events.")] = 50,
    as_json: JsonOutput = False,
    url: DatabaseURL = None,
) -> None:
    """Show the authorization audit trail of a site, newest first."""

    async def work(session: AsyncSession) -> list[AuthorizationEvent]:
        found = await sites.get_site(session, site)
        script_id = (await versions.find_script(session, site, locator)).id if locator else None
        return await audit.list_events(session, found.id, script_id=script_id, limit=limit)

    events = _run(url, work)
    if as_json:
        typer.echo(json.dumps([_event_json(e) for e in events], indent=2))
        return
    if not events:
        typer.echo(f"no audit events for {site} yet")
        return
    for e in events:
        move = f"{e.from_status or 'new'} -> {e.to_status}" if e.to_status else ""
        subject = e.locator or (
            f"{e.detail.get('kind')} {e.detail.get('match')}" if e.policy_id else ""
        )
        typer.echo(
            f"#{e.seq:<4} {e.created_at:%Y-%m-%d %H:%M:%S}Z  {e.action:<21} {e.actor:<16} "
            f"{move:<21} {subject}"
        )
        if e.reason:
            typer.echo(f"      {e.reason}")


@audit_app.command("verify")
def audit_verify(site: str, as_json: JsonOutput = False, url: DatabaseURL = None) -> None:
    """Recompute the audit trail's hash chain. Exits 1 when it is broken."""

    async def work(session: AsyncSession) -> audit.ChainReport:
        found = await sites.get_site(session, site)
        return await audit.verify_chain(session, found.id)

    report = _run(url, work)
    if as_json:
        typer.echo(
            json.dumps(
                {
                    "site": site,
                    "ok": report.ok,
                    "events": report.events,
                    "head_hash": report.head_hash,
                    "first_bad_seq": report.first_bad_seq,
                    "problem": report.problem,
                },
                indent=2,
            )
        )
    elif report.ok:
        typer.echo(
            f"audit trail of {site} is intact: {report.events} events, head {report.head_hash}"
        )
    else:
        typer.secho(
            f"audit trail of {site} is BROKEN at event {report.first_bad_seq}: {report.problem} "
            f"({report.events} events verified before it)",
            fg=typer.colors.RED,
            err=True,
        )
    if not report.ok:
        raise typer.Exit(code=1)


def _finding_id(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError:
        typer.secho(f"error: {value!r} is not a finding id", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from None


@findings_app.command("list")
def findings_list(
    site: str,
    status: Annotated[
        FindingStatus | None,
        typer.Option(help="Only findings with this status.", case_sensitive=False),
    ] = None,
    min_severity: Annotated[
        Severity | None,
        typer.Option("--min-severity", help="Only this severe or worse.", case_sensitive=False),
    ] = None,
    locator: Annotated[
        str | None, typer.Option("--script", help="Only findings about this script.")
    ] = None,
    limit: Annotated[int, typer.Option(min=1, max=500, help="How many findings.")] = 50,
    as_json: JsonOutput = False,
    url: DatabaseURL = None,
) -> None:
    """List a site's findings, newest first."""

    async def work(session: AsyncSession) -> list[Finding]:
        script_id = (await versions.find_script(session, site, locator)).id if locator else None
        return await findings.list_findings(
            session,
            site,
            status=status,
            min_severity=min_severity,
            script_id=script_id,
            limit=limit,
        )

    rows = _run(url, work)
    if as_json:
        typer.echo(json.dumps([_finding_json(f) for f in rows], indent=2))
        return
    if not rows:
        typer.echo(f"no findings for {site}")
        return
    for finding in rows:
        typer.echo(
            f"{finding.created_at:%Y-%m-%d %H:%M:%S}Z  {finding.status.value:<12} {finding.id}"
        )
        _finding_line(finding)


@findings_app.command("show")
def findings_show(
    finding_id: Annotated[str, typer.Argument(metavar="FINDING_ID")],
    max_hunks: Annotated[int, typer.Option(min=1, help="Hunks to print.")] = 20,
    as_json: JsonOutput = False,
    url: DatabaseURL = None,
) -> None:
    """Show a finding with its evidence: for a change, the diff and what it references."""
    parsed = _finding_id(finding_id)

    async def work(session: AsyncSession) -> tuple[Finding, str]:
        return await findings.get_finding(session, parsed)

    finding, site = _run(url, work)
    if as_json:
        typer.echo(json.dumps({**_finding_json(finding, detail=True), "site": site}, indent=2))
        return
    detail = finding.detail
    typer.echo(f"finding {finding.id} ({site}): {finding.kind}, {finding.status.value}")
    _finding_line(finding)
    flag = " [payment]" if detail.get("payment_page") else ""
    typer.echo(f"  pages{flag}: {', '.join(detail.get('pages', []))}")
    if finding.status_changed_by:
        typer.echo(
            f"  {finding.status.value} by {finding.status_changed_by}"
            + (f": {finding.status_note}" if finding.status_note else "")
        )
    if "tokens" in detail:
        hunks = [Hunk.from_dict(h) for h in detail.get("hunks") or []]
        text = render_hunks(hunks, max_hunks=max_hunks, total=detail.get("hunk_count"))
        _print_analysis(detail, text)
    elif detail.get("hosts_referenced"):
        typer.echo(f"  hosts referenced: {', '.join(detail['hosts_referenced'][:10])}")


def _set_finding(
    finding_id: str, status: FindingStatus, note: str | None, actor: str | None, url: str | None
) -> None:
    parsed = _finding_id(finding_id)

    async def work(session: AsyncSession) -> Finding:
        finding, _ = await findings.set_status(
            session, parsed, status, actor=_actor(actor), note=note
        )
        return finding

    finding = _run(url, work)
    typer.echo(f"finding {finding.id} is now {finding.status.value}")


Note = Annotated[str | None, typer.Option("--note", "-n", help="What was done or decided.")]


@findings_app.command("ack")
def findings_ack(
    finding_id: Annotated[str, typer.Argument(metavar="FINDING_ID")],
    note: Note = None,
    actor: Actor = None,
    url: DatabaseURL = None,
) -> None:
    """Acknowledge a finding (someone is on it). Recorded in the audit trail."""
    _set_finding(finding_id, FindingStatus.ACKNOWLEDGED, note, actor, url)


@findings_app.command("resolve")
def findings_resolve(
    finding_id: Annotated[str, typer.Argument(metavar="FINDING_ID")],
    note: Note = None,
    actor: Actor = None,
    url: DatabaseURL = None,
) -> None:
    """Resolve a finding; --note saying what was done is required. Audited."""
    _set_finding(finding_id, FindingStatus.RESOLVED, note, actor, url)


@findings_app.command("reopen")
def findings_reopen(
    finding_id: Annotated[str, typer.Argument(metavar="FINDING_ID")],
    note: Note = None,
    actor: Actor = None,
    url: DatabaseURL = None,
) -> None:
    """Reopen an acknowledged or resolved finding. Audited."""
    _set_finding(finding_id, FindingStatus.OPEN, note, actor, url)
