from __future__ import annotations

import uuid

from fastapi.testclient import TestClient

from script_sentinel.sri import integrity_value
from tests.conftest import FixtureSite


def _scanned_shop(client: TestClient, site: FixtureSite, cdn: FixtureSite) -> dict[str, str]:
    cdn.set("/sdk/widget.js", b"widget(1);", content_type="text/javascript")
    site.page(
        "/checkout",
        f'<script src="{cdn.url("/sdk/widget.js")}"></script><script>pay();</script>',
    )
    client.post("/v1/sites", json={"name": "shop", "allowed_origins": [site.origin]})
    client.post("/v1/sites/shop/pages", json={"url": site.url("/checkout"), "payment_page": True})
    scan = client.post("/v1/sites/shop/scans").json()
    assert (scan["scripts_approved"], scan["scripts_pending"], scan["scripts_rejected"]) == (
        0,
        2,
        0,
    )
    assert {s["authorization_status"] for s in scan["pages"][0]["scripts"]} == {"pending"}
    scripts = client.get("/v1/sites/shop/scripts").json()["scripts"]
    return {s["kind"]: s["id"] for s in scripts}


def test_approve_reject_and_reset(
    client: TestClient, fixture_site: FixtureSite, cdn: FixtureSite
) -> None:
    ids = _scanned_shop(client, fixture_site, cdn)
    base = f"/v1/sites/shop/scripts/{ids['external']}"

    response = client.post(
        f"{base}/approve", json={"actor": "alice", "justification": "PSP card widget."}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["status"], body["decision"], body["approval_scope"]) == (
        "approved",
        "approved",
        "pinned",
    )
    assert (body["decided_by"], body["justification"]) == ("alice", "PSP card widget.")
    assert body["status_reason"] == "approved by alice"
    assert body["versions"][0]["approved_by"] == "alice"

    # The vendor changes the script: pending again, and the scan says so.
    cdn.set("/sdk/widget.js", b"widget(2);", content_type="text/javascript")
    scan = client.post("/v1/sites/shop/scans").json()
    assert scan["scripts_pending"] == 2
    detail = client.get(base).json()
    assert detail["status"] == "pending"
    assert [v["approved_by"] for v in detail["versions"]] == [None, "alice"]

    rejected = client.post(f"{base}/reject", json={"actor": "bob", "reason": "Unreviewed v2."})
    assert rejected.json()["status"] == "rejected"
    reset = client.post(f"{base}/reset", json={"actor": "bob", "reason": "Reviewing v2."})
    assert (reset.json()["status"], reset.json()["decision"]) == ("pending", None)
    again = client.post(f"{base}/reset", json={"actor": "bob", "reason": "again"})
    assert again.status_code == 409

    any_version = client.post(
        f"{base}/approve",
        json={"actor": "alice", "justification": "Vendor ships weekly.", "scope": "any_version"},
    )
    assert any_version.json()["status_reason"] == "approved by alice for any version"

    for path, payload, code in (
        (f"{base}/approve", {"actor": "alice"}, 422),
        (f"{base}/approve", {"actor": "", "justification": "x"}, 422),
        (f"{base}/approve", {"actor": "a", "justification": " "}, 422),
        (f"{base}/approve", {"actor": "a", "justification": "x", "extra": 1}, 422),
        (f"{base}/reject", {"actor": "a", "reason": "x", "scope": "pinned"}, 422),
        (
            f"/v1/sites/shop/scripts/{uuid.uuid4()}/approve",
            {"actor": "a", "justification": "x"},
            404,
        ),
        (f"/v1/sites/nope/scripts/{ids['external']}/reject", {"actor": "a", "reason": "x"}, 404),
    ):
        assert client.post(path, json=payload).status_code == code, path

    trail = client.get("/v1/sites/shop/audit").json()["events"]
    assert [e["action"] for e in trail[:5]] == [
        "script.approved",
        "script.reset",
        "script.rejected",
        "script.status_changed",
        "script.approved",
    ]
    assert trail[0]["seq"] == len(trail) == 7
    assert trail[0]["detail"]["scope"] == "any_version"
    only = client.get("/v1/sites/shop/audit", params={"script_id": ids["inline"]}).json()
    assert [e["locator"] for e in only["events"]] == [fixture_site.url("/checkout#inline-1")]
    verified = client.get("/v1/sites/shop/audit/verify").json()
    assert (verified["ok"], verified["events"], verified["head_hash"]) == (
        True,
        7,
        trail[0]["hash"],
    )
    assert client.get("/v1/sites/nope/audit").status_code == 404
    assert client.get("/v1/sites/nope/audit/verify").status_code == 404


def test_policies(client: TestClient, fixture_site: FixtureSite, cdn: FixtureSite) -> None:
    ids = _scanned_shop(client, fixture_site, cdn)
    assert client.get("/v1/sites/shop/policies").json() == {"site": "shop", "policies": []}

    created = client.post(
        "/v1/sites/shop/policies",
        json={
            "kind": "origin",
            "match": cdn.origin.upper(),
            "change": "expected_to_change",
            "ignore_query": ["v"],
            "justification": "PSP origin.",
            "actor": "alice",
        },
    )
    assert created.status_code == 201, created.text
    body = created.json()
    policy = body["policy"]
    assert (policy["match"], policy["ignore_query"], policy["created_by"]) == (
        cdn.origin,
        ["v"],
        "alice",
    )
    assert body["scripts_changed"] == [
        {
            "script_id": ids["external"],
            "locator": cdn.url("/sdk/widget.js"),
            "from_status": "pending",
            "to_status": "approved",
        }
    ]
    script = client.get(f"/v1/sites/shop/scripts/{ids['external']}").json()
    assert script["policy_id"] == policy["id"]

    by_hash = client.post(
        "/v1/sites/shop/policies",
        json={
            "kind": "hash",
            "match": integrity_value(b"pay();"),
            "justification": "Checkout bootstrap.",
            "actor": "alice",
        },
    )
    assert [c["to_status"] for c in by_hash.json()["scripts_changed"]] == ["approved"]
    listed = client.get("/v1/sites/shop/policies").json()["policies"]
    assert [p["kind"] for p in listed] == ["origin", "hash"]

    duplicate = client.post(
        "/v1/sites/shop/policies",
        json={"kind": "origin", "match": cdn.origin, "justification": "x", "actor": "a"},
    )
    assert duplicate.status_code == 409
    for bad in (
        {"kind": "origin", "match": cdn.url("/sdk/"), "justification": "x", "actor": "a"},
        {"kind": "hash", "match": "abc", "justification": "x", "actor": "a"},
        {"kind": "prefix", "match": cdn.url("/a"), "justification": "x", "actor": "a", "x": 1},
        {"kind": "glob", "match": "*", "justification": "x", "actor": "a"},
    ):
        assert client.post("/v1/sites/shop/policies", json=bad).status_code == 422, bad

    removed = client.delete(
        f"/v1/sites/shop/policies/{policy['id']}",
        params={"actor": "bob", "reason": "Vendor offboarded."},
    )
    assert removed.status_code == 200
    assert removed.json() == {
        "policy": None,
        "scripts_changed": [
            {
                "script_id": ids["external"],
                "locator": cdn.url("/sdk/widget.js"),
                "from_status": "approved",
                "to_status": "pending",
            }
        ],
    }
    gone = client.delete(
        f"/v1/sites/shop/policies/{policy['id']}", params={"actor": "bob", "reason": "x"}
    )
    assert gone.status_code == 404
    assert client.delete(f"/v1/sites/shop/policies/{policy['id']}").status_code == 422
    assert client.get("/v1/sites/nope/policies").status_code == 404
