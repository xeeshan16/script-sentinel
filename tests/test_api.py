from __future__ import annotations

from fastapi.testclient import TestClient

from script_sentinel.app import create_app
from script_sentinel.config import Settings

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
    assert {"/v1/sites", "/v1/sites/{name}", "/v1/sites/{name}/pages", "/healthz"} <= set(paths)
