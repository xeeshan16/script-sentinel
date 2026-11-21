from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.ext.asyncio import AsyncSession

from script_sentinel.db.models import (
    AuthorizationStatus,
    Finding,
    FindingStatus,
    Page,
    Script,
    ScriptKind,
    ScriptVersion,
    Severity,
    Site,
    sri_from_sha384_hex,
)

BODY = b"console.log('hello');\n"


def _site(name: str = "shop") -> Site:
    return Site(name=name, allowed_origins=["https://shop.example.com"], scan_interval_hours=24)


async def _graph(session: AsyncSession) -> tuple[Site, Script, ScriptVersion, Finding]:
    site = _site()
    session.add(site)
    await session.flush()
    script = Script(
        site_id=site.id, kind=ScriptKind.EXTERNAL, locator="https://cdn.vendor.test/tag.js"
    )
    session.add(script)
    await session.flush()
    version = ScriptVersion(
        script_id=script.id, sha384=hashlib.sha384(BODY).hexdigest(), size_bytes=len(BODY)
    )
    session.add(version)
    await session.flush()
    finding = Finding(
        site_id=site.id,
        script_id=script.id,
        version_id=version.id,
        kind="script.unapproved",
        severity=Severity.MEDIUM,
        title="New script is not approved",
        detail={"locator": script.locator},
    )
    session.add_all([finding, Page(site_id=site.id, url="https://shop.example.com/")])
    await session.commit()
    return site, script, version, finding


def test_sri_matches_openssl_style_digest() -> None:
    digest = hashlib.sha384(BODY)
    expected = "sha384-" + base64.b64encode(digest.digest()).decode()
    assert sri_from_sha384_hex(digest.hexdigest()) == expected


def test_sri_rejects_wrong_length() -> None:
    with pytest.raises(ValueError, match="48 bytes"):
        sri_from_sha384_hex(hashlib.sha256(BODY).hexdigest())


async def test_defaults_and_round_trip(session: AsyncSession) -> None:
    _site_row, script, version, finding = await _graph(session)
    session.expunge_all()

    loaded = await session.get(Script, script.id)
    assert loaded is not None
    assert loaded.kind is ScriptKind.EXTERNAL
    assert loaded.status is AuthorizationStatus.PENDING
    assert loaded.first_seen_at.tzinfo is not None

    stored = await session.get(Finding, finding.id)
    assert stored is not None
    assert stored.status is FindingStatus.OPEN
    assert stored.detail == {"locator": "https://cdn.vendor.test/tag.js"}

    v = await session.get(ScriptVersion, version.id)
    assert v is not None
    assert v.sri.startswith("sha384-")
    page = await session.scalar(select(Page))
    assert page is not None
    assert page.payment_page is False


async def test_timestamps_come_back_as_utc(session: AsyncSession) -> None:
    site = _site()
    dubai = timezone(timedelta(hours=4))
    site.created_at = datetime(2026, 11, 21, 13, 0, tzinfo=dubai)
    session.add(site)
    await session.commit()
    session.expunge_all()
    loaded = await session.scalar(select(Site))
    assert loaded is not None
    assert loaded.created_at == datetime(2026, 11, 21, 9, 0, tzinfo=UTC)
    assert loaded.created_at.utcoffset() == timedelta(0)


async def test_naive_timestamps_are_rejected(session: AsyncSession) -> None:
    site = _site()
    site.created_at = datetime(2026, 11, 21, 9, 0)  # naive on purpose
    session.add(site)
    with pytest.raises(StatementError, match="naive datetimes"):
        await session.flush()


async def test_deleting_a_site_cascades(session: AsyncSession) -> None:
    site, *_ = await _graph(session)
    await session.delete(site)
    await session.commit()
    for model in (Site, Page, Script, ScriptVersion, Finding):
        assert await session.scalar(select(func.count()).select_from(model)) == 0


async def test_deleting_a_script_keeps_its_findings(session: AsyncSession) -> None:
    _site_row, script, _version, finding = await _graph(session)
    await session.delete(script)
    await session.commit()
    session.expunge_all()
    kept = await session.get(Finding, finding.id)
    assert kept is not None
    assert kept.script_id is None
    assert kept.version_id is None


async def test_a_body_is_stored_once_per_script(session: AsyncSession) -> None:
    _site_row, script, version, _finding = await _graph(session)
    session.add(ScriptVersion(script_id=script.id, sha384=version.sha384, size_bytes=1))
    with pytest.raises(IntegrityError):
        await session.flush()


async def test_scan_interval_is_capped_by_the_database(session: AsyncSession) -> None:
    site = _site()
    site.scan_interval_hours = 169
    session.add(site)
    with pytest.raises(IntegrityError):
        await session.flush()


async def test_locators_are_unique_per_site(session: AsyncSession) -> None:
    site, script, *_ = await _graph(session)
    other = _site("blog")
    session.add(other)
    await session.flush()
    # The same URL in another site is fine…
    session.add(Script(site_id=other.id, kind=ScriptKind.EXTERNAL, locator=script.locator))
    await session.flush()
    # …but not twice in one site.
    session.add(Script(site_id=site.id, kind=ScriptKind.INLINE, locator=script.locator))
    with pytest.raises(IntegrityError):
        await session.flush()
