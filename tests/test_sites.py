from __future__ import annotations

import re

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from script_sentinel import sites
from script_sentinel.sites import ConflictError, NotFoundError, ValidationError

SHOP = "https://shop.example.com"


async def _shop(session: AsyncSession, *origins: str) -> None:
    await sites.create_site(
        session, name="shop", allowed_origins=list(origins) or [SHOP], scan_interval_hours=24
    )


@pytest.mark.parametrize("name", ["shop", "a", "shop-eu-2", "0", "a" * 64])
def test_valid_site_names(name: str) -> None:
    assert sites.validate_site_name(name) == name


@pytest.mark.parametrize("name", ["", "Shop", "-shop", "shop-", "shop_eu", "shop eu", "a" * 65])
def test_invalid_site_names(name: str) -> None:
    with pytest.raises(ValidationError):
        sites.validate_site_name(name)


@pytest.mark.parametrize("hours", [0, 169, -1])
def test_scan_interval_bounds(hours: int) -> None:
    with pytest.raises(ValidationError, match="7 days"):
        sites.validate_scan_interval(hours)


async def test_create_normalizes_origins(session: AsyncSession) -> None:
    site = await sites.create_site(
        session,
        name="shop",
        allowed_origins=["HTTPS://Shop.Example.com:443/", SHOP, "http://localhost:8000"],
        scan_interval_hours=168,
    )
    assert site.allowed_origins == ["http://localhost:8000", SHOP]


async def test_create_rejects_bad_origins(session: AsyncSession) -> None:
    with pytest.raises(ValidationError, match="bare origin"):
        await sites.create_site(
            session, name="shop", allowed_origins=[SHOP + "/checkout"], scan_interval_hours=24
        )


async def test_duplicate_site_is_a_conflict(session: AsyncSession) -> None:
    await _shop(session)
    await session.commit()
    with pytest.raises(ConflictError, match="already exists"):
        await _shop(session)


async def test_unknown_site(session: AsyncSession) -> None:
    with pytest.raises(NotFoundError):
        await sites.get_site(session, "nope")
    with pytest.raises(NotFoundError):
        await sites.list_pages(session, "nope")


async def test_pages_must_be_on_an_allowed_origin(session: AsyncSession) -> None:
    await _shop(session)
    page = await sites.add_page(
        session, "shop", url="https://SHOP.example.com/checkout#card", payment_page=True
    )
    assert page.url == "https://shop.example.com/checkout"
    assert page.payment_page is True
    with pytest.raises(ValidationError, match="not on an allowed origin"):
        await sites.add_page(session, "shop", url="https://cdn.vendor.test/")
    with pytest.raises(ValidationError, match="credentials"):
        await sites.add_page(session, "shop", url="https://u:p@shop.example.com/")


async def test_duplicate_page_is_a_conflict(session: AsyncSession) -> None:
    await _shop(session)
    await sites.add_page(session, "shop", url=SHOP + "/cart")
    await session.commit()
    with pytest.raises(ConflictError, match="already registered"):
        await sites.add_page(session, "shop", url=SHOP + "/cart#x")


async def test_list_sites_counts_pages(session: AsyncSession) -> None:
    await _shop(session)
    await sites.create_site(
        session, name="blog", allowed_origins=["https://blog.example.com"], scan_interval_hours=1
    )
    await sites.add_page(session, "shop", url=SHOP + "/", label="home")
    await sites.add_page(session, "shop", url=SHOP + "/checkout", payment_page=True)
    summaries = await sites.list_sites(session)
    assert [(s.site.name, s.page_count, s.payment_page_count) for s in summaries] == [
        ("blog", 0, 0),
        ("shop", 2, 1),
    ]


async def test_cannot_remove_an_origin_that_pages_use(session: AsyncSession) -> None:
    await _shop(session, SHOP, "https://pay.example.com")
    await sites.add_page(session, "shop", url="https://pay.example.com/form")
    with pytest.raises(ConflictError, match=re.escape("https://pay.example.com/form")):
        await sites.update_site(session, "shop", allowed_origins=[SHOP])
    # Unused origins can go, and the interval can change.
    await sites.add_page(session, "shop", url=SHOP + "/")
    site = await sites.update_site(
        session,
        "shop",
        allowed_origins=["https://pay.example.com", SHOP, "https://new.example.com"],
        scan_interval_hours=12,
    )
    assert site.allowed_origins == [
        "https://new.example.com",
        "https://pay.example.com",
        SHOP,
    ]
    assert site.scan_interval_hours == 12


async def test_orphan_message_is_truncated(session: AsyncSession) -> None:
    await _shop(session, SHOP, "https://pay.example.com")
    for i in range(7):
        await sites.add_page(session, "shop", url=f"https://pay.example.com/{i}")
    with pytest.raises(ConflictError, match=r"and 2 more"):
        await sites.update_site(session, "shop", allowed_origins=[SHOP])


async def test_update_validates(session: AsyncSession) -> None:
    await _shop(session)
    with pytest.raises(ValidationError):
        await sites.update_site(session, "shop", scan_interval_hours=200)
    with pytest.raises(ValidationError):
        await sites.update_site(session, "shop", allowed_origins=[])
    site = await sites.update_site(session, "shop", allowed_origins=[SHOP + ":8443"])
    assert (site.allowed_origins, site.scan_interval_hours) == ([SHOP + ":8443"], 24)


async def test_remove_page_and_site(session: AsyncSession) -> None:
    await _shop(session)
    await sites.add_page(session, "shop", url=SHOP + "/cart")
    with pytest.raises(NotFoundError):
        await sites.remove_page(session, "shop", SHOP + "/other")
    with pytest.raises(ValidationError):
        await sites.remove_page(session, "shop", "ftp://x")
    await sites.remove_page(session, "shop", SHOP + "/cart#frag")
    assert await sites.list_pages(session, "shop") == []
    await sites.delete_site(session, "shop")
    assert await sites.list_sites(session) == []
