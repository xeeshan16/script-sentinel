"""Registering sites and pages, and keeping the scan allowlist consistent.

Two rules hold at all times:

* every page URL is on one of its site's allowed origins, so the scanner never fetches a
  page nobody listed;
* an origin can't be removed from a site while pages still use it.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from script_sentinel.config import MAX_SCAN_INTERVAL_HOURS
from script_sentinel.db.models import Page, Site
from script_sentinel.origins import (
    InvalidUrlError,
    is_allowed,
    normalize_origins,
    normalize_page_url,
)

SITE_NAME_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")


class SiteError(Exception):
    """Base class for errors the API maps to a 4xx response."""


class NotFoundError(SiteError):
    pass


class ConflictError(SiteError):
    pass


class ValidationError(SiteError):
    pass


@dataclass(frozen=True, slots=True)
class SiteSummary:
    site: Site
    page_count: int
    payment_page_count: int


def validate_site_name(name: str) -> str:
    if not SITE_NAME_PATTERN.fullmatch(name):
        raise ValidationError(
            "site names are 1-64 lowercase letters, digits and hyphens, "
            "starting and ending with a letter or digit"
        )
    return name


def validate_scan_interval(hours: int) -> int:
    if not 1 <= hours <= MAX_SCAN_INTERVAL_HOURS:
        raise ValidationError(
            f"scan_interval_hours must be between 1 and {MAX_SCAN_INTERVAL_HOURS} "
            "(PCI DSS 11.6.1 asks for a check at least every 7 days)"
        )
    return hours


def _origins(values: Sequence[str]) -> list[str]:
    try:
        return normalize_origins(list(values))
    except InvalidUrlError as exc:
        raise ValidationError(str(exc)) from exc


async def create_site(
    session: AsyncSession,
    *,
    name: str,
    allowed_origins: Sequence[str],
    scan_interval_hours: int,
    respect_robots: bool = True,
) -> Site:
    site = Site(
        name=validate_site_name(name),
        allowed_origins=_origins(allowed_origins),
        scan_interval_hours=validate_scan_interval(scan_interval_hours),
        respect_robots=respect_robots,
    )
    session.add(site)
    try:
        await session.flush()
    except IntegrityError as exc:
        raise ConflictError(f"site {name!r} already exists") from exc
    return site


async def get_site(session: AsyncSession, name: str) -> Site:
    site = await session.scalar(select(Site).where(Site.name == name))
    if site is None:
        raise NotFoundError(f"site {name!r} not found")
    return site


async def list_sites(session: AsyncSession) -> list[SiteSummary]:
    counts = (
        select(
            Page.site_id,
            func.count().label("pages"),
            func.count().filter(Page.payment_page.is_(True)).label("payment_pages"),
        )
        .group_by(Page.site_id)
        .subquery()
    )
    rows = await session.execute(
        select(Site, counts.c.pages, counts.c.payment_pages)
        .outerjoin(counts, counts.c.site_id == Site.id)
        .order_by(Site.name)
    )
    return [SiteSummary(site, pages or 0, payment or 0) for site, pages, payment in rows]


async def update_site(
    session: AsyncSession,
    name: str,
    *,
    allowed_origins: Sequence[str] | None = None,
    scan_interval_hours: int | None = None,
    respect_robots: bool | None = None,
) -> Site:
    site = await get_site(session, name)
    if allowed_origins is not None:
        origins = _origins(allowed_origins)
        pages = await list_pages(session, name)
        orphaned = [p.url for p in pages if not is_allowed(p.url, origins)]
        if orphaned:
            raise ConflictError(
                "removing these origins would leave pages outside the allowlist: "
                + ", ".join(orphaned[:5])
                + (f" (and {len(orphaned) - 5} more)" if len(orphaned) > 5 else "")
            )
        site.allowed_origins = origins
    if scan_interval_hours is not None:
        site.scan_interval_hours = validate_scan_interval(scan_interval_hours)
    if respect_robots is not None:
        site.respect_robots = respect_robots
    await session.flush()
    return site


async def delete_site(session: AsyncSession, name: str) -> None:
    site = await get_site(session, name)
    await session.delete(site)
    await session.flush()


async def add_page(
    session: AsyncSession,
    site_name: str,
    *,
    url: str,
    label: str | None = None,
    payment_page: bool = False,
) -> Page:
    site = await get_site(session, site_name)
    try:
        normalized = normalize_page_url(url)
    except InvalidUrlError as exc:
        raise ValidationError(str(exc)) from exc
    if not is_allowed(normalized, site.allowed_origins):
        raise ValidationError(
            f"{normalized} is not on an allowed origin of site {site.name!r} "
            f"({', '.join(site.allowed_origins)})"
        )
    page = Page(site_id=site.id, url=normalized, label=label, payment_page=payment_page)
    session.add(page)
    try:
        await session.flush()
    except IntegrityError as exc:
        raise ConflictError(f"page {normalized} is already registered") from exc
    return page


async def list_pages(session: AsyncSession, site_name: str) -> list[Page]:
    site = await get_site(session, site_name)
    result = await session.scalars(select(Page).where(Page.site_id == site.id).order_by(Page.url))
    return list(result)


async def remove_page(session: AsyncSession, site_name: str, url: str) -> None:
    site = await get_site(session, site_name)
    try:
        normalized = normalize_page_url(url)
    except InvalidUrlError as exc:
        raise ValidationError(str(exc)) from exc
    page = await session.scalar(select(Page).where(Page.site_id == site.id, Page.url == normalized))
    if page is None:
        raise NotFoundError(f"page {normalized} not found in site {site.name!r}")
    await session.delete(page)
    await session.flush()
