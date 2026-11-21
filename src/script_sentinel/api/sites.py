"""``/v1/sites``: register what gets monitored."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from script_sentinel import sites
from script_sentinel.api.schemas import (
    ErrorOut,
    PageCreate,
    PageList,
    PageOut,
    SiteCreate,
    SiteList,
    SiteOut,
    SiteUpdate,
)
from script_sentinel.config import Settings
from script_sentinel.db.models import Site

router = APIRouter(prefix="/v1/sites", tags=["sites"])

_ERRORS: dict[int | str, dict[str, object]] = {
    404: {"model": ErrorOut},
    409: {"model": ErrorOut},
    422: {"model": ErrorOut},
}


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    async with request.app.state.sessionmaker() as session, session.begin():
        yield session


def get_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


Session = Annotated[AsyncSession, Depends(get_session)]
AppSettings = Annotated[Settings, Depends(get_settings)]


async def _site_out(session: AsyncSession, site: Site) -> SiteOut:
    pages = await sites.list_pages(session, site.name)
    return SiteOut(
        id=site.id,
        name=site.name,
        allowed_origins=site.allowed_origins,
        scan_interval_hours=site.scan_interval_hours,
        page_count=len(pages),
        payment_page_count=sum(p.payment_page for p in pages),
        created_at=site.created_at,
        updated_at=site.updated_at,
    )


@router.post("", status_code=status.HTTP_201_CREATED, responses=_ERRORS)
async def create_site(body: SiteCreate, session: Session, settings: AppSettings) -> SiteOut:
    site = await sites.create_site(
        session,
        name=body.name,
        allowed_origins=body.allowed_origins,
        scan_interval_hours=body.scan_interval_hours or settings.default_scan_interval_hours,
    )
    return await _site_out(session, site)


@router.get("")
async def list_sites(session: Session) -> SiteList:
    return SiteList(
        sites=[
            SiteOut(
                id=s.site.id,
                name=s.site.name,
                allowed_origins=s.site.allowed_origins,
                scan_interval_hours=s.site.scan_interval_hours,
                page_count=s.page_count,
                payment_page_count=s.payment_page_count,
                created_at=s.site.created_at,
                updated_at=s.site.updated_at,
            )
            for s in await sites.list_sites(session)
        ]
    )


@router.get("/{name}", responses=_ERRORS)
async def get_site(name: str, session: Session) -> SiteOut:
    return await _site_out(session, await sites.get_site(session, name))


@router.patch("/{name}", responses=_ERRORS)
async def update_site(name: str, body: SiteUpdate, session: Session) -> SiteOut:
    site = await sites.update_site(
        session,
        name,
        allowed_origins=body.allowed_origins,
        scan_interval_hours=body.scan_interval_hours,
    )
    return await _site_out(session, site)


@router.delete("/{name}", status_code=status.HTTP_204_NO_CONTENT, responses=_ERRORS)
async def delete_site(name: str, session: Session) -> Response:
    await sites.delete_site(session, name)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{name}/pages", status_code=status.HTTP_201_CREATED, responses=_ERRORS)
async def add_page(name: str, body: PageCreate, session: Session) -> PageOut:
    page = await sites.add_page(
        session, name, url=body.url, label=body.label, payment_page=body.payment_page
    )
    return PageOut.model_validate(page)


@router.delete("/{name}/pages", status_code=status.HTTP_204_NO_CONTENT, responses=_ERRORS)
async def remove_page(name: str, url: str, session: Session) -> Response:
    await sites.remove_page(session, name, url)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{name}/pages", responses=_ERRORS)
async def list_pages(name: str, session: Session) -> PageList:
    pages = await sites.list_pages(session, name)
    return PageList(site=name, pages=[PageOut.model_validate(p) for p in pages])
