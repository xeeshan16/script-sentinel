from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

from script_sentinel.api.csp import _read_body
from script_sentinel.app import create_app
from script_sentinel.config import Settings
from script_sentinel.ratelimit import RateLimiter

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "csp-reports"
ORIGIN = "https://shop.example.com"
REPORTS = "/v1/reports/csp/shop"
CSP = {"content-type": "application/csp-report"}
BATCH = {"content-type": "application/reports+json"}


def _shop(client: TestClient) -> None:
    response = client.post("/v1/sites", json={"name": "shop", "allowed_origins": [ORIGIN]})
    assert response.status_code == 201, response.text


def _report(**body: Any) -> dict[str, Any]:
    base = {
        "documentURL": f"{ORIGIN}/",
        "effectiveDirective": "img-src",
        "blockedURL": "https://pixel.test/p.gif",
        "disposition": "enforce",
    }
    return {"type": "csp-violation", "body": {**base, **body}}


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def limited(sqlite_url: str) -> Iterator[tuple[TestClient, Clock]]:
    """A client whose collector allows bursts of 5 reports, refilling 1 per second."""
    settings = Settings(
        database_url=sqlite_url,
        csp_reports_per_minute=60,
        csp_burst=5,
        csp_max_reports_per_request=5,
        csp_max_body_bytes=2048,
    )
    app = create_app(settings)
    clock = Clock()
    app.state.csp_limiter = RateLimiter(1.0, 5, clock=clock)
    with TestClient(app) as client:
        _shop(client)
        yield client, clock


def test_the_example_payloads_are_collected_and_grouped(client: TestClient) -> None:
    _shop(client)
    legacy = client.post(REPORTS, content=(EXAMPLES / "report-uri.json").read_bytes(), headers=CSP)
    assert legacy.status_code == 202, legacy.text
    assert legacy.json() == {
        "site": "shop",
        "format": "csp-report",
        "received": 1,
        "accepted": 1,
        "groups_new": 1,
        "groups_updated": 0,
        "dropped": {},
    }
    batch = client.post(
        REPORTS, content=(EXAMPLES / "reporting-api.json").read_bytes(), headers=BATCH
    )
    assert batch.status_code == 202, batch.text
    assert batch.json()["dropped"] == {"not_csp": 1, "foreign_document": 1, "extension": 1}
    assert (batch.json()["accepted"], batch.json()["groups_new"]) == (3, 2)

    listing = client.get("/v1/sites/shop/csp/violations", params={"order": "count"}).json()
    assert (listing["total_groups"], listing["total_reports"]) == (3, 4)
    top = listing["violations"][0]
    assert top["count"] == 2
    assert top["blocked"] == "https://collect.skim.test/beacon"
    assert top["source_file"] == "https://cdn.vendor.test/analytics/v2/tag.js"
    assert "original_policy" not in top
    # No query string from any report was stored.
    assert "4111" not in json.dumps(listing)
    assert "jane" not in json.dumps(listing)

    detail = client.get(f"/v1/sites/shop/csp/violations/{top['id']}")
    assert detail.status_code == 200
    assert detail.json()["original_policy"].startswith("default-src 'self'")


def test_listing_filters(client: TestClient) -> None:
    _shop(client)
    client.post(
        REPORTS,
        content=json.dumps(
            [_report(), _report(effectiveDirective="script-src-elem", disposition="report")]
        ),
        headers=BATCH,
    )
    params: dict[str, str | int] = {"directive": "script-src-elem"}
    assert client.get("/v1/sites/shop/csp/violations", params=params).json()["total_groups"] == 1
    params = {"disposition": "enforce", "blocked_host": "pixel.test", "limit": 1}
    body = client.get("/v1/sites/shop/csp/violations", params=params).json()
    assert (body["total_groups"], len(body["violations"])) == (1, 1)
    params = {"since": "2999-01-01T00:00:00Z"}
    assert client.get("/v1/sites/shop/csp/violations", params=params).json()["violations"] == []
    assert client.get("/v1/sites/shop/csp/violations?order=size").status_code == 422


def test_unknown_sites_and_groups_are_404(client: TestClient) -> None:
    _shop(client)
    assert client.post("/v1/reports/csp/nope", content=b"[]", headers=BATCH).status_code == 404
    assert client.options("/v1/reports/csp/nope").status_code == 404
    assert client.get("/v1/sites/nope/csp/violations").status_code == 404
    missing = "/v1/sites/shop/csp/violations/00000000-0000-0000-0000-000000000000"
    assert client.get(missing).status_code == 404


def test_refused_payloads(client: TestClient) -> None:
    _shop(client)
    wrong_type = client.post(REPORTS, content=b"{}", headers={"content-type": "text/plain"})
    assert wrong_type.status_code == 415
    assert "application/csp-report" in wrong_type.json()["detail"]
    assert client.post(REPORTS, content=b"{", headers=CSP).status_code == 400
    assert client.post(REPORTS, content=b"[]", headers=CSP).status_code == 400
    gzip = client.post(REPORTS, content=b"[]", headers={**BATCH, "content-encoding": "gzip"})
    assert gzip.status_code == 415
    identity = client.post(
        REPORTS, content=b"[]", headers={**BATCH, "content-encoding": "identity"}
    )
    assert identity.status_code == 202


def test_bodies_over_the_limit_are_refused(limited: tuple[TestClient, Clock]) -> None:
    client, _ = limited
    big = json.dumps([_report(sample="x" * 3000)]).encode()
    declared = client.post(REPORTS, content=big, headers=BATCH)
    assert declared.status_code == 413
    assert "2048 bytes" in declared.json()["detail"]

    def chunks() -> Iterator[bytes]:  # no Content-Length: caught while streaming
        for _ in range(5):
            yield b" " * 1000

    streamed = client.post(REPORTS, content=chunks(), headers=BATCH)
    assert streamed.status_code == 413


def test_the_rate_limit_is_charged_per_report(limited: tuple[TestClient, Clock]) -> None:
    client, clock = limited
    four = json.dumps([_report(lineNumber=n) for n in range(4)])
    assert client.post(REPORTS, content=four, headers=BATCH).status_code == 202
    refused = client.post(REPORTS, content=four, headers=BATCH)
    assert refused.status_code == 429
    assert refused.headers["retry-after"] == "3"
    # Nothing from the refused batch was recorded.
    assert client.get("/v1/sites/shop/csp/violations").json()["total_reports"] == 4
    clock.now += 3
    assert client.post(REPORTS, content=four, headers=BATCH).status_code == 202


def test_batches_are_capped_and_charged_for_what_was_read(
    limited: tuple[TestClient, Clock],
) -> None:
    client, _ = limited
    eight = json.dumps([_report()] * 8)
    response = client.post(REPORTS, content=eight, headers=BATCH)
    assert response.status_code == 202
    assert (response.json()["accepted"], response.json()["dropped"]) == (5, {"batch_limit": 3})
    assert client.post(REPORTS, content=json.dumps([_report()]), headers=BATCH).status_code == 429


def test_refused_requests_still_cost_a_token(limited: tuple[TestClient, Clock]) -> None:
    client, _ = limited
    for _ in range(5):
        assert client.post(REPORTS, content=b"{", headers=CSP).status_code == 400
    # The bucket is empty now: even garbage gets 429 instead of being parsed for free.
    assert client.post(REPORTS, content=b"{", headers=CSP).status_code == 429


def test_cors_preflight_lets_only_the_sites_origins_through(client: TestClient) -> None:
    _shop(client)
    allowed = client.options(
        REPORTS,
        headers={"origin": "https://SHOP.example.com", "access-control-request-method": "POST"},
    )
    assert allowed.status_code == 204
    assert allowed.headers["access-control-allow-origin"] == "https://SHOP.example.com"
    assert allowed.headers["access-control-allow-methods"] == "POST"
    assert allowed.headers["access-control-allow-headers"] == "content-type"
    assert allowed.headers["vary"] == "Origin"
    for origin in ("https://evil.test", "null", "not an origin"):
        refused = client.options(REPORTS, headers={"origin": origin})
        assert refused.status_code == 204
        assert "access-control-allow-origin" not in refused.headers
    assert "access-control-allow-origin" not in client.options(REPORTS).headers


def test_cors_headers_on_collected_and_refused_reports(client: TestClient) -> None:
    _shop(client)
    origin = {"origin": ORIGIN}
    ok = client.post(REPORTS, content=json.dumps([_report()]), headers={**BATCH, **origin})
    assert ok.headers["access-control-allow-origin"] == ORIGIN
    bad = client.post(REPORTS, content=b"{", headers={**CSP, **origin})
    assert bad.status_code == 400
    assert bad.headers["access-control-allow-origin"] == ORIGIN
    foreign = client.post(
        REPORTS, content=json.dumps([_report()]), headers={**BATCH, "origin": "https://evil.test"}
    )
    assert foreign.status_code == 202
    assert "access-control-allow-origin" not in foreign.headers


def _request(headers: dict[str, str], chunks: list[bytes]) -> Request:
    messages = [{"type": "http.request", "body": c, "more_body": True} for c in chunks]
    messages.append({"type": "http.request", "body": b"", "more_body": False})

    async def receive() -> dict[str, Any]:
        return messages.pop(0)

    scope = {
        "type": "http",
        "method": "POST",
        "path": REPORTS,
        "headers": [(k.encode(), v.encode()) for k, v in headers.items()],
    }
    return Request(scope, receive)


async def test_read_body_checks_the_declared_length() -> None:
    with pytest.raises(HTTPException) as bad:
        await _read_body(_request({"content-length": "ten"}, []), 100)
    assert bad.value.status_code == 400
    with pytest.raises(HTTPException) as large:
        await _read_body(_request({"content-length": "101"}, []), 100)
    assert large.value.status_code == 413
    # An understated length doesn't help: the stream is counted too.
    with pytest.raises(HTTPException) as lied:
        await _read_body(_request({"content-length": "10"}, [b"x" * 60, b"x" * 60]), 100)
    assert lied.value.status_code == 413
    assert await _read_body(_request({}, [b"ab", b"cd"]), 100) == b"abcd"


def test_settings_refuse_a_burst_smaller_than_a_batch() -> None:
    with pytest.raises(ValueError, match="csp_burst"):
        Settings(csp_burst=10, csp_max_reports_per_request=20)
    assert Settings().ingest_limits().max_reports == 100
