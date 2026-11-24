"""Decisions, policies and the audit trail against a real database and real scans."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from script_sentinel import audit, authorization, scanner, sites, versions
from script_sentinel.db.models import (
    ApprovalScope,
    AuthorizationEvent,
    AuthorizationStatus,
    ChangePolicy,
    Decision,
    PolicyKind,
    Scan,
    ScanTrigger,
    Script,
    ScriptFetch,
    ScriptObservation,
    ScriptVersion,
)
from script_sentinel.fetch import PageFetcher
from script_sentinel.sites import ConflictError, NotFoundError, ValidationError
from script_sentinel.sri import integrity_value
from tests.conftest import FixtureSite

PENDING = AuthorizationStatus.PENDING
APPROVED = AuthorizationStatus.APPROVED
REJECTED = AuthorizationStatus.REJECTED


class Shop:
    """A checkout page on the fixture site that loads a vendor script from a second origin."""

    def __init__(self, site: FixtureSite, cdn: FixtureSite) -> None:
        self.site = site
        self.cdn = cdn
        self.vendor = cdn.url("/sdk/widget.js")
        self.set_vendor(b"widget(1);\n")
        self.set_page()

    def set_vendor(self, body: bytes, path: str = "/sdk/widget.js") -> None:
        self.cdn.set(path, body, content_type="text/javascript")

    def set_page(self, *srcs: str, inline: str = "pay();") -> None:
        tags = "".join(f'<script src="{s}"></script>' for s in (srcs or (self.vendor,)))
        self.site.page("/checkout", f"<html><head>{tags}<script>{inline}</script></head></html>")

    @property
    def inline(self) -> str:
        return self.site.url("/checkout#inline-1")


@pytest.fixture
def shop(fixture_site: FixtureSite, cdn: FixtureSite) -> Shop:
    return Shop(fixture_site, cdn)


async def _register(session: AsyncSession, shop: Shop) -> None:
    await sites.create_site(
        session, name="shop", allowed_origins=[shop.site.origin], scan_interval_hours=24
    )
    await sites.add_page(session, "shop", url=shop.site.url("/checkout"), payment_page=True)


async def _scan(session: AsyncSession) -> Scan:
    async with PageFetcher() as fetcher:
        scan = await scanner.scan_site(session, "shop", fetcher, trigger=ScanTrigger.CLI)
    await session.commit()
    return scan


async def _script(session: AsyncSession, locator: str) -> Script:
    return await versions.find_script(session, "shop", locator)


async def _status(session: AsyncSession, locator: str) -> AuthorizationStatus:
    script = await _script(session, locator)
    await session.refresh(script)
    return script.status


async def _events(session: AsyncSession) -> list[AuthorizationEvent]:
    site = await sites.get_site(session, "shop")
    return list(reversed(await audit.list_events(session, site.id, limit=1000)))


async def _verify(session: AsyncSession) -> audit.ChainReport:
    site = await sites.get_site(session, "shop")
    return await audit.verify_chain(session, site.id)


async def test_new_scripts_are_pending_and_enter_the_audit_trail(
    session: AsyncSession, shop: Shop
) -> None:
    await _register(session, shop)
    scan = await _scan(session)

    assert (scan.scripts_approved, scan.scripts_pending, scan.scripts_rejected) == (0, 2, 0)
    vendor = await _script(session, shop.vendor)
    assert vendor.status is PENDING
    assert vendor.status_reason == "no decision or policy covers this script yet"
    assert vendor.status_changed_at is not None
    assert len(vendor.current_version_ids) == 1

    events = await _events(session)
    assert [(e.seq, e.action, e.actor, e.from_status, e.to_status) for e in events] == [
        (1, audit.STATUS_CHANGED, "scan", None, "pending"),
        (2, audit.STATUS_CHANGED, "scan", None, "pending"),
    ]
    assert events[0].prev_hash == audit.GENESIS_HASH
    assert events[1].prev_hash == events[0].hash
    assert events[0].detail["scan_id"] == str(scan.id)
    assert {e.locator for e in events} == {shop.vendor, shop.inline}

    observations = (await session.scalars(select(ScriptObservation))).all()
    assert {o.authorization_status for o in observations} == {PENDING}

    # Scanning again without changes writes nothing new.
    await _scan(session)
    assert len(await _events(session)) == 2
    assert (await _verify(session)).ok


async def test_a_pinned_approval_lapses_when_the_body_changes(
    session: AsyncSession, shop: Shop
) -> None:
    await _register(session, shop)
    await _scan(session)
    vendor = await _script(session, shop.vendor)

    approved = await authorization.approve_script(
        session,
        "shop",
        vendor.id,
        actor="alice",
        justification="Card widget from our PSP; required on checkout.",
    )
    await session.commit()
    assert approved.status is APPROVED
    assert approved.decision is Decision.APPROVED
    assert approved.approval_scope is ApprovalScope.PINNED
    assert approved.status_reason == "approved by alice"
    v1 = (await versions.versions_by_script(session, [vendor.id]))[vendor.id][0]
    assert v1.approved_by == "alice"
    assert v1.approved_at is not None

    # The vendor ships a new body: the approval no longer covers what runs.
    shop.set_vendor(b"widget(2);\n")
    scan = await _scan(session)
    assert await _status(session, shop.vendor) is PENDING
    assert (scan.scripts_approved, scan.scripts_pending) == (0, 2)
    vendor = await _script(session, shop.vendor)
    assert vendor.status_reason == "the body changed since alice approved it (pinned)"
    lapse = (await _events(session))[-1]
    assert (lapse.action, lapse.actor, lapse.from_status, lapse.to_status) == (
        audit.STATUS_CHANGED,
        "scan",
        "approved",
        "pending",
    )
    assert lapse.detail["current_sha384"] != [v1.sha384]

    # Approving again covers the new body (the old one stays approved); reverting to the
    # old body keeps the script approved.
    await authorization.approve_script(
        session, "shop", vendor.id, actor="bob", justification="Reviewed widget v2 diff."
    )
    await session.commit()
    assert await _status(session, shop.vendor) is APPROVED
    shop.set_vendor(b"widget(1);\n")
    await _scan(session)
    assert await _status(session, shop.vendor) is APPROVED

    actions = [e.action for e in await _events(session)]
    assert actions.count(audit.SCRIPT_APPROVED) == 2
    assert (await _verify(session)).ok


async def test_approval_for_any_version_rejection_and_reset(
    session: AsyncSession, shop: Shop
) -> None:
    await _register(session, shop)
    await _scan(session)
    vendor = await _script(session, shop.vendor)

    script = await authorization.approve_script(
        session,
        "shop",
        vendor.id,
        actor="alice",
        justification="Tag manager; the vendor updates it weekly.",
        scope=ApprovalScope.ANY_VERSION,
    )
    await session.commit()
    assert script.status is APPROVED
    # Nothing is pinned, so no body is marked approved.
    history = (await versions.versions_by_script(session, [vendor.id]))[vendor.id]
    assert all(v.approved_at is None for v in history)
    shop.set_vendor(b"widget(2);\n")
    await _scan(session)
    assert await _status(session, shop.vendor) is APPROVED

    # A rejection wins even over an "expected to change" policy for the whole origin.
    await authorization.create_policy(
        session,
        "shop",
        kind=PolicyKind.ORIGIN,
        match=shop.cdn.origin,
        change=ChangePolicy.EXPECTED_TO_CHANGE,
        actor="alice",
        justification="All of our PSP's scripts.",
    )
    script = await authorization.reject_script(
        session, "shop", vendor.id, actor="carol", reason="Loads a keylogger in v2."
    )
    await session.commit()
    assert (script.status, script.decision, script.approval_scope) == (
        REJECTED,
        Decision.REJECTED,
        None,
    )
    assert script.status_reason == "rejected by carol"
    assert script.justification == "Loads a keylogger in v2."

    # Withdrawing the decision hands the script back to the policy.
    script = await authorization.reset_script(
        session, "shop", vendor.id, actor="carol", reason="False alarm; v2 is clean."
    )
    await session.commit()
    assert script.status is APPROVED
    assert script.decision is None
    assert script.decided_by is None
    assert script.status_reason == (
        f"approved by origin policy {shop.cdn.origin} (expected to change)"
    )
    with pytest.raises(ConflictError, match="no decision"):
        await authorization.reset_script(session, "shop", vendor.id, actor="carol", reason="again")

    trail = [(e.action, e.actor, e.from_status, e.to_status) for e in await _events(session)]
    assert (audit.SCRIPT_REJECTED, "carol", "approved", "rejected") in trail
    assert (audit.SCRIPT_RESET, "carol", "rejected", "approved") in trail
    assert (await _verify(session)).ok


async def test_decisions_are_validated(session: AsyncSession, shop: Shop) -> None:
    await _register(session, shop)
    shop.cdn.set("/sdk/widget.js", b"gone", status=404)
    await _scan(session)
    vendor = await _script(session, shop.vendor)
    assert vendor.current_version_ids == []

    with pytest.raises(ValidationError, match="no fetched body to pin"):
        await authorization.approve_script(
            session, "shop", vendor.id, actor="alice", justification="ok"
        )
    with pytest.raises(ValidationError, match="justification"):
        await authorization.approve_script(
            session, "shop", vendor.id, actor="alice", justification=" "
        )
    with pytest.raises(ValidationError, match="actor"):
        await authorization.reject_script(session, "shop", vendor.id, actor="", reason="no")
    with pytest.raises(NotFoundError, match="script"):
        await authorization.approve_script(
            session, "shop", uuid.uuid4(), actor="alice", justification="ok"
        )
    # Without a body to pin, approving for any version is the way to go.
    script = await authorization.approve_script(
        session,
        "shop",
        vendor.id,
        actor="alice",
        justification="Vendor endpoint is down; approved by contract.",
        scope=ApprovalScope.ANY_VERSION,
    )
    assert script.status is APPROVED


async def test_a_failed_fetch_does_not_change_the_status(session: AsyncSession, shop: Shop) -> None:
    await _register(session, shop)
    await _scan(session)
    vendor = await _script(session, shop.vendor)
    await authorization.approve_script(
        session, "shop", vendor.id, actor="alice", justification="PSP widget."
    )
    await session.commit()
    before = list(vendor.current_version_ids)

    shop.cdn.set("/sdk/widget.js", b"error", status=503)
    scan = await _scan(session)
    assert scan.scripts_fetch_failed == 1
    vendor = await _script(session, shop.vendor)
    await session.refresh(vendor)
    assert vendor.status is APPROVED
    assert vendor.current_version_ids == before


async def test_pinning_policies_trust_the_first_body(session: AsyncSession, shop: Shop) -> None:
    await _register(session, shop)
    await _scan(session)

    policy, changes = await authorization.create_policy(
        session,
        "shop",
        kind=PolicyKind.PREFIX,
        match=shop.cdn.url("/sdk/"),
        actor="alice",
        justification="PSP SDK; any change must be reviewed.",
    )
    await session.commit()
    assert policy.change is ChangePolicy.PINNED
    assert [(c.script.locator, c.from_status, c.to_status) for c in changes] == [
        (shop.vendor, PENDING, APPROVED)
    ]
    vendor = await _script(session, shop.vendor)
    assert vendor.policy_id == policy.id
    v1 = (await versions.versions_by_script(session, [vendor.id]))[vendor.id][0]
    assert v1.approved_by == f"policy:{policy.id}"

    shop.set_vendor(b"widget(2);\n")
    await _scan(session)
    vendor = await _script(session, shop.vendor)
    await session.refresh(vendor)
    assert vendor.status is PENDING
    assert vendor.status_reason == f"the body changed since prefix policy {policy.match} pinned it"

    events = await _events(session)
    created = next(e for e in events if e.action == audit.POLICY_CREATED)
    assert created.detail["match"] == policy.match
    assert created.policy_id == policy.id
    assert events[-1].detail["cause"] == "scan"


async def test_hash_policies_cover_inline_code(session: AsyncSession, shop: Shop) -> None:
    await _register(session, shop)
    scan = await _scan(session)
    assert scan.scripts_pending == 2

    policy, changes = await authorization.create_policy(
        session,
        "shop",
        kind=PolicyKind.HASH,
        match=integrity_value(b"pay();"),
        actor="alice",
        justification="Our own checkout bootstrap.",
    )
    await session.commit()
    assert [c.script.locator for c in changes] == [shop.inline]
    assert await _status(session, shop.inline) is APPROVED

    # Edited inline code no longer matches the hash.
    shop.set_page(inline="pay(); exfiltrate();")
    await _scan(session)
    assert await _status(session, shop.inline) is PENDING

    for kwargs, message in (
        ({"change": ChangePolicy.EXPECTED_TO_CHANGE}, "cannot change"),
        ({"ignore_query": ["v"]}, "origin and prefix policies only"),
    ):
        with pytest.raises(ValidationError, match=message):
            await authorization.create_policy(
                session,
                "shop",
                kind=PolicyKind.HASH,
                match=policy.match.upper(),
                actor="alice",
                justification="again",
                **kwargs,
            )
    with pytest.raises(ConflictError, match="already has a hash policy"):
        await authorization.create_policy(
            session,
            "shop",
            kind=PolicyKind.HASH,
            match=policy.match.upper(),
            actor="alice",
            justification="again",
        )


async def test_removing_a_policy_sends_its_scripts_back_to_review(
    session: AsyncSession, shop: Shop
) -> None:
    await _register(session, shop)
    await _scan(session)
    policy, _ = await authorization.create_policy(
        session,
        "shop",
        kind=PolicyKind.ORIGIN,
        match=shop.cdn.origin,
        change=ChangePolicy.EXPECTED_TO_CHANGE,
        actor="alice",
        justification="PSP origin.",
    )
    await session.commit()
    assert [p.id for p in await authorization.list_policies(session, "shop")] == [policy.id]

    changes = await authorization.remove_policy(
        session, "shop", policy.id, actor="bob", reason="Contract with the PSP ended."
    )
    await session.commit()
    assert [(c.script.locator, c.from_status, c.to_status) for c in changes] == [
        (shop.vendor, APPROVED, PENDING)
    ]
    vendor = await _script(session, shop.vendor)
    await session.refresh(vendor)
    assert vendor.policy_id is None
    assert await authorization.list_policies(session, "shop") == []

    events = await _events(session)
    removed = next(e for e in events if e.action == audit.POLICY_REMOVED)
    # Events keep the policy's id and details after the row is gone.
    assert removed.policy_id == policy.id
    assert removed.reason == "Contract with the PSP ended."
    assert removed.detail["kind"] == "origin"
    assert (await _verify(session)).ok

    with pytest.raises(NotFoundError, match="policy"):
        await authorization.remove_policy(session, "shop", policy.id, actor="bob", reason="twice")


async def test_cache_busting_query_parameters_collapse_into_one_script(
    session: AsyncSession, shop: Shop
) -> None:
    await _register(session, shop)
    tag = shop.cdn.url("/tag.js")
    for query in ("v=1", "v=2&site=shop", "v=3", "v=4"):
        shop.set_vendor(b"tag(1);\n", f"/tag.js?{query}")
    shop.set_vendor(b"tag(5);\n", "/tag.js?v=5")
    await authorization.create_policy(
        session,
        "shop",
        kind=PolicyKind.ORIGIN,
        match=shop.cdn.origin,
        change=ChangePolicy.EXPECTED_TO_CHANGE,
        ignore_query=["v"],
        actor="alice",
        justification="Analytics vendor; ships often.",
    )
    shop.set_page(f"{tag}?v=1", f"{tag}?v=2&site=shop")
    scan = await _scan(session)

    locators = {s.locator for s in await scanner.list_scripts(session, "shop")}
    assert locators == {tag, f"{tag}?site=shop", shop.inline}
    shop.set_page(f"{tag}?v=3")
    scan = await _scan(session)
    assert (scan.scripts_new, scan.versions_new, scan.scripts_fetch_failed) == (0, 0, 0)
    assert (scan.scripts_approved, scan.scripts_pending) == (1, 1)

    # Two URLs that map to one script in the same scan are both fetched and recorded.
    shop.set_page(f"{tag}?v=4", f"{tag}?v=5")
    scan = await _scan(session)
    fetches = (
        await session.scalars(select(ScriptFetch).where(ScriptFetch.scan_id == scan.id))
    ).all()
    assert sorted(f.url for f in fetches) == [f"{tag}?v=4", f"{tag}?v=5"]
    assert len({f.script_id for f in fetches}) == 1
    script = await _script(session, tag)
    assert len(script.current_version_ids) == 2


async def test_verification_pages_through_long_trails(
    session: AsyncSession, shop: Shop, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(audit, "_VERIFY_PAGE", 2)
    await _register(session, shop)
    await _scan(session)
    vendor = await _script(session, shop.vendor)
    for _ in range(3):
        await authorization.approve_script(
            session, "shop", vendor.id, actor="alice", justification="PSP widget."
        )
    await session.commit()
    report = await _verify(session)
    assert (report.ok, report.events) == (True, 5)


async def test_tampering_with_the_trail_is_detected(session: AsyncSession, shop: Shop) -> None:
    await _register(session, shop)
    await _scan(session)
    vendor = await _script(session, shop.vendor)
    await authorization.approve_script(
        session, "shop", vendor.id, actor="alice", justification="PSP widget."
    )
    await session.commit()
    report = await _verify(session)
    assert (report.ok, report.events) == (True, 3)
    events = await _events(session)
    assert report.head_hash == events[-1].hash

    # Someone rewrites who approved the script.
    await session.execute(
        update(AuthorizationEvent).where(AuthorizationEvent.seq == 3).values(actor="mallory")
    )
    await session.commit()
    session.expire_all()
    report = await _verify(session)
    assert (report.ok, report.first_bad_seq, report.events) == (False, 3, 2)
    assert report.problem == "the event's contents do not match its hash"

    # Someone deletes an event.
    await session.execute(delete(AuthorizationEvent).where(AuthorizationEvent.seq == 2))
    await session.commit()
    report = await _verify(session)
    assert (report.ok, report.first_bad_seq) == (False, 3)
    assert report.problem == "event 2 is missing"


async def test_a_rewritten_event_with_a_fresh_hash_breaks_the_link(
    session: AsyncSession, shop: Shop
) -> None:
    await _register(session, shop)
    await _scan(session)
    await _scan(session)
    first = (await _events(session))[0]
    first.reason = "edited"
    first.hash = audit.event_hash(first)  # recomputed, but the next event still points back
    await session.commit()
    report = await _verify(session)
    assert (report.ok, report.first_bad_seq) == (False, 2)
    assert "prev_hash" in (report.problem or "")


async def test_trails_are_per_site_and_survive_script_removal(
    session: AsyncSession, shop: Shop
) -> None:
    await _register(session, shop)
    await sites.create_site(
        session, name="blog", allowed_origins=[shop.site.origin], scan_interval_hours=24
    )
    await _scan(session)
    blog = await sites.get_site(session, "blog")
    assert (await audit.verify_chain(session, blog.id)).events == 0

    vendor = await _script(session, shop.vendor)
    await session.execute(delete(Script).where(Script.id == vendor.id))
    await session.commit()
    events = await _events(session)
    assert any(e.script_id == vendor.id for e in events)
    assert (await _verify(session)).ok
    assert await session.scalar(select(func.count()).select_from(ScriptVersion)) == 1
