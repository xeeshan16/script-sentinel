from __future__ import annotations

import uuid

import httpx
from fastapi.testclient import TestClient

from script_sentinel.app import create_app
from script_sentinel.config import Settings
from tests.conftest import FixtureSite

SHOP = "https://shop.example.com"


def _create_shop(client: TestClient) -> None:
    response = client.post("/v1/sites", json={"name": "shop", "allowed_origins": [SHOP]})
    assert response.status_code == 201, response.text


def test_health(client: TestClient) -> None:
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/readyz").json() == {"status": "ok", "database": "ok"}


def test_readyz_reports_an_unreachable_database() -> None:
    settings = Settings(database_url="postgresql+asyncpg://nobody:x@127.0.0.1:1/none")
    with TestClient(create_app(settings)) as client:
        response = client.get("/readyz")
    assert response.status_code == 503
    assert response.json()["status"] == "unavailable"
    assert "x@" not in response.text  # never echo the connection string


def test_site_lifecycle(client: TestClient) -> None:
    response = client.post(
        "/v1/sites", json={"name": "shop", "allowed_origins": ["HTTPS://shop.example.com/"]}
    )
    assert response.status_code == 201
    site = response.json()
    assert site["allowed_origins"] == [SHOP]
    assert site["scan_interval_hours"] == 24  # the configured default
    assert site["page_count"] == 0

    response = client.post(
        "/v1/sites/shop/pages",
        json={"url": SHOP + "/checkout", "label": "checkout", "payment_page": True},
    )
    assert response.status_code == 201
    assert response.json()["url"] == SHOP + "/checkout"

    shop = client.get("/v1/sites/shop").json()
    assert (shop["page_count"], shop["payment_page_count"]) == (1, 1)
    listing = client.get("/v1/sites").json()["sites"]
    assert [(s["name"], s["page_count"], s["payment_page_count"]) for s in listing] == [
        ("shop", 1, 1)
    ]
    pages = client.get("/v1/sites/shop/pages").json()
    assert pages["site"] == "shop"
    assert [p["label"] for p in pages["pages"]] == ["checkout"]

    response = client.patch("/v1/sites/shop", json={"scan_interval_hours": 6})
    assert response.json()["scan_interval_hours"] == 6

    response = client.delete("/v1/sites/shop/pages", params={"url": SHOP + "/checkout"})
    assert response.status_code == 204
    assert client.delete("/v1/sites/shop").status_code == 204
    assert client.get("/v1/sites/shop").status_code == 404


def test_errors_map_to_status_codes(client: TestClient) -> None:
    _create_shop(client)
    duplicate = client.post("/v1/sites", json={"name": "shop", "allowed_origins": [SHOP]})
    assert duplicate.status_code == 409
    assert duplicate.json() == {"detail": "site 'shop' already exists"}

    outside = client.post("/v1/sites/shop/pages", json={"url": "https://evil.test/"})
    assert outside.status_code == 422
    assert "not on an allowed origin" in outside.json()["detail"]

    bad_name = client.post("/v1/sites", json={"name": "Shop!", "allowed_origins": [SHOP]})
    assert bad_name.status_code == 422

    assert client.post("/v1/sites/nope/pages", json={"url": SHOP}).status_code == 404
    assert client.get("/v1/sites/nope/pages").status_code == 404
    assert client.delete("/v1/sites/nope").status_code == 404


def test_request_bodies_are_strict(client: TestClient) -> None:
    unknown_field = client.post(
        "/v1/sites", json={"name": "shop", "allowed_origins": [SHOP], "owner": "me"}
    )
    assert unknown_field.status_code == 422
    too_long = client.post(
        "/v1/sites",
        json={"name": "shop", "allowed_origins": [SHOP], "scan_interval_hours": 500},
    )
    assert too_long.status_code == 422
    no_origins = client.post("/v1/sites", json={"name": "shop", "allowed_origins": []})
    assert no_origins.status_code == 422


def test_origin_removal_conflict(client: TestClient) -> None:
    _create_shop(client)
    client.post("/v1/sites/shop/pages", json={"url": SHOP + "/"})
    response = client.patch("/v1/sites/shop", json={"allowed_origins": ["https://other.test"]})
    assert response.status_code == 409


def test_openapi_lists_the_routes(client: TestClient) -> None:
    paths = client.get("/openapi.json").json()["paths"]
    assert {
        "/v1/sites",
        "/v1/sites/{name}",
        "/v1/sites/{name}/pages",
        "/v1/sites/{name}/scans",
        "/v1/sites/{name}/scripts",
        "/v1/scans/{scan_id}",
        "/healthz",
    } <= set(paths)


def test_scans_and_inventory(client: TestClient, fixture_site: FixtureSite) -> None:
    fixture_site.set("/robots.txt", "User-agent: *\nDisallow: /checkout\n")
    fixture_site.page(
        "/checkout",
        '<script src="/app.js" integrity="sha384-x"></script><script nonce="z">pay()</script>',
    )
    response = client.post(
        "/v1/sites",
        json={"name": "shop", "allowed_origins": [fixture_site.origin], "respect_robots": True},
    )
    assert response.json()["respect_robots"] is True
    page = {"url": fixture_site.url("/checkout"), "payment_page": True}
    assert client.post("/v1/sites/shop/pages", json=page).status_code == 201

    skipped = client.post("/v1/sites/shop/scans")
    assert skipped.status_code == 201
    body = skipped.json()
    assert (body["status"], body["pages_skipped"], body["trigger"]) == ("completed", 1, "api")
    assert body["pages"][0]["outcome"] == "robots_disallowed"

    patched = client.patch("/v1/sites/shop", json={"respect_robots": False})
    assert patched.json()["respect_robots"] is False
    scan = client.post("/v1/sites/shop/scans").json()
    assert (scan["site"], scan["status"], scan["pages_ok"], scan["scripts_new"]) == (
        "shop",
        "completed",
        1,
        2,
    )
    (snapshot,) = scan["pages"]
    assert snapshot["payment_page"] is True
    assert snapshot["http_status"] == 200
    external, inline = snapshot["scripts"]
    assert external["locator"] == fixture_site.url("/app.js")
    assert (external["kind"], external["integrity"], external["has_nonce"]) == (
        "external",
        "sha384-x",
        False,
    )
    assert (inline["kind"], inline["has_nonce"], inline["inline_size_bytes"]) == (
        "inline",
        True,
        5,
    )

    assert client.get(f"/v1/scans/{scan['id']}").json() == scan
    listing = client.get("/v1/sites/shop/scans").json()
    assert listing["site"] == "shop"
    assert [s["id"] for s in listing["scans"]] == [scan["id"], body["id"]]
    assert len(client.get("/v1/sites/shop/scans", params={"limit": 1}).json()["scans"]) == 1

    scripts = client.get("/v1/sites/shop/scripts").json()
    assert [(s["kind"], s["status"]) for s in scripts["scripts"]] == [
        ("external", "pending"),
        ("inline", "pending"),
    ]


def test_scan_errors(client: TestClient) -> None:
    _create_shop(client)
    no_pages = client.post("/v1/sites/shop/scans")
    assert no_pages.status_code == 422
    assert "has no pages to scan" in no_pages.json()["detail"]
    assert client.post("/v1/sites/nope/scans").status_code == 404
    assert client.get("/v1/sites/nope/scans").status_code == 404
    assert client.get("/v1/sites/nope/scripts").status_code == 404
    assert client.get(f"/v1/scans/{uuid.uuid4()}").status_code == 404
    assert client.get("/v1/scans/not-a-uuid").status_code == 422
    assert client.get("/v1/sites/shop/scans", params={"limit": 0}).status_code == 422


def test_scans_use_the_injected_transport(database_url: str) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(404)
        return httpx.Response(200, headers={"content-type": "text/html"}, text="<script>a</script>")

    app = create_app(Settings(database_url=database_url), transport=httpx.MockTransport(handler))
    with TestClient(app) as client:
        _create_shop(client)
        client.post("/v1/sites/shop/pages", json={"url": SHOP + "/"})
        scan = client.post("/v1/sites/shop/scans").json()
    assert scan["pages"][0]["scripts"][0]["locator"] == SHOP + "/#inline-1"
