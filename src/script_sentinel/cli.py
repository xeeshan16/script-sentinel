"""``sentinel`` command-line interface."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from typing import Annotated

import typer
from sqlalchemy.ext.asyncio import AsyncSession

from script_sentinel import __version__, sites
from script_sentinel.config import Settings
from script_sentinel.db import make_engine, make_sessionmaker

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
    url: DatabaseURL = None,
) -> None:
    """Register a site and the origins its pages may be fetched from."""
    hours = interval or Settings().default_scan_interval_hours

    async def work(session: AsyncSession) -> None:
        site = await sites.create_site(
            session, name=name, allowed_origins=origins, scan_interval_hours=hours
        )
        typer.echo(
            f"added site {site.name}: {', '.join(site.allowed_origins)} "
            f"(scan every {site.scan_interval_hours}h)"
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
