from __future__ import annotations

import importlib.util
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from script_sentinel import sites, violations
from script_sentinel.app import create_app
from script_sentinel.config import Settings
from script_sentinel.db import make_engine, make_sessionmaker
from script_sentinel.ingest import BufferedSink, MemoryBroker, ReportConsumer, decode

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "csp-reports"
ORIGIN = "https://shop.example.com"
REPORTS = "/v1/reports/csp/shop"
CSP = {"content-type": "application/csp-report"}
BATCH = {"content-type": "application/reports+json"}


def _shop(client: TestClient) -> None:
    response = client.post("/v1/sites", json={"name": "shop", "allowed_origins": [ORIGIN]})
    assert response.status_code == 201, response.text


def _post_examples(client: TestClient) -> tuple[dict[str, Any], dict[str, Any]]:
    legacy = client.post(REPORTS, content=(EXAMPLES / "report-uri.json").read_bytes(), headers=CSP)
    batch = client.post(
        REPORTS, content=(EXAMPLES / "reporting-api.json").read_bytes(), headers=BATCH
    )
    assert (legacy.status_code, batch.status_code) == (202, 202), batch.text
    return legacy.json(), batch.json()


def _total(client: TestClient) -> int:
    body = client.get("/v1/sites/shop/csp/violations").json()
    return int(body["total_reports"])


def test_direct_mode_writes_rollups_and_reports_its_mode(client: TestClient) -> None:
    _shop(client)
    legacy, batch = _post_examples(client)
    assert (legacy["mode"], legacy["groups_new"]) == ("direct", 1)
    assert batch["groups_new"] == 2
    assert client.get("/v1/csp/ingest").json() == {"mode": "direct"}

    body = client.get("/v1/sites/shop/csp/rollups").json()
    assert (body["by"], body["hours"], body["total"], body["previous_total"]) == ("both", 24, 4, 0)
    assert [(r["directive"], r["blocked"], r["count"], r["new"]) for r in body["rows"]] == [
        ("connect-src", "collect.skim.test", 2, True),
        ("script-src-elem", "collect.skim.test", 1, True),
        ("script-src-elem", "inline", 1, True),
    ]
    assert len(body["buckets"]) == 24
    assert body["buckets"][-1]["count"] == 4

    by_blocked = client.get("/v1/sites/shop/csp/rollups?by=blocked&hours=1").json()
    assert [(r["blocked"], r["count"]) for r in by_blocked["rows"]] == [
        ("collect.skim.test", 3),
        ("inline", 1),
    ]
    by_directive = client.get(
        "/v1/sites/shop/csp/rollups", params={"by": "directive", "disposition": "report"}
    ).json()
    assert [(r["directive"], r["count"]) for r in by_directive["rows"]] == [("script-src-elem", 1)]
    filtered = client.get(
        "/v1/sites/shop/csp/rollups", params={"directive": "connect-src", "limit": 1}
    ).json()
    assert filtered["total"] == 2


def test_rollup_errors(client: TestClient) -> None:
    _shop(client)
    assert client.get("/v1/sites/nope/csp/rollups").status_code == 404
    assert client.get("/v1/sites/shop/csp/rollups?hours=0").status_code == 422
    assert client.get("/v1/sites/shop/csp/rollups?hours=745").status_code == 422
    assert client.get("/v1/sites/shop/csp/rollups?by=page").status_code == 422


@pytest.fixture
def buffered(database_url: str) -> Iterator[TestClient]:
    settings = Settings(
        database_url=database_url,
        csp_ingest_mode="buffered",
        csp_flush_interval_seconds=30,
        csp_flush_reports=5,
        csp_buffer_max_reports=5,
        csp_max_reports_per_request=5,
        csp_burst=50,
    )
    with TestClient(create_app(settings)) as client:
        yield client


def _sink(client: TestClient) -> BufferedSink:
    sink = client.app.state.csp_sink  # type: ignore[attr-defined]
    assert isinstance(sink, BufferedSink)
    return sink


def test_buffered_mode_answers_first_and_writes_on_flush(buffered: TestClient) -> None:
    _shop(buffered)
    legacy = buffered.post(
        REPORTS, content=(EXAMPLES / "report-uri.json").read_bytes(), headers=CSP
    ).json()
    assert legacy == {
        "site": "shop",
        "format": "csp-report",
        "mode": "buffered",
        "received": 1,
        "accepted": 1,
        "groups_new": None,
        "groups_updated": None,
        "dropped": {},
    }
    assert _total(buffered) == 0  # queued, not written yet
    status = buffered.get("/v1/csp/ingest").json()
    assert (status["mode"], status["pending"], status["max_pending"]) == ("buffered", 1, 5)
    assert buffered.portal is not None
    buffered.portal.call(_sink(buffered).flush)
    assert _total(buffered) == 1
    status = buffered.get("/v1/csp/ingest").json()
    assert (status["pending"], status["flushes"], status["written"]) == (0, 1, 1)


def test_a_full_buffer_answers_503_with_retry_after(buffered: TestClient) -> None:
    _shop(buffered)
    report = {
        "type": "csp-violation",
        "body": {
            "documentURL": f"{ORIGIN}/",
            "effectiveDirective": "img-src",
            "blockedURL": "https://pixel.test/p.gif",
        },
    }
    assert buffered.post(REPORTS, json=[report] * 3, headers=BATCH).status_code == 202
    response = buffered.post(REPORTS, json=[report] * 3, headers={**BATCH, "origin": ORIGIN})
    assert response.status_code == 503
    assert response.headers["retry-after"] == "30"
    assert response.headers["access-control-allow-origin"] == ORIGIN
    assert "buffer is full" in response.json()["detail"]
    assert buffered.get("/v1/csp/ingest").json()["refused"] == 3
    # A payload with nothing to keep doesn't need room.
    noise = [{"type": "deprecation", "body": {}}]
    assert buffered.post(REPORTS, json=noise, headers=BATCH).status_code == 202


def test_shutdown_flushes_the_buffer(database_url: str) -> None:
    settings = Settings(
        database_url=database_url, csp_ingest_mode="buffered", csp_flush_interval_seconds=30
    )
    with TestClient(create_app(settings)) as client:
        _shop(client)
        _post_examples(client)
        assert _total(client) == 0
    with TestClient(create_app(Settings(database_url=database_url))) as client:
        assert _total(client) == 4
        assert client.get("/v1/sites/shop/csp/rollups").json()["total"] == 4


async def test_kafka_mode_publishes_and_the_consumer_writes(database_url: str) -> None:
    broker = MemoryBroker(partitions=3)
    settings = Settings(
        database_url=database_url,
        csp_ingest_mode="kafka",
        kafka_bootstrap_servers="kafka.invalid:9092",
        kafka_send_timeout_seconds=2,
    )
    with TestClient(create_app(settings, publisher=broker.publisher())) as client:
        _shop(client)
        legacy, batch = _post_examples(client)
        assert (legacy["mode"], batch["mode"], batch["accepted"]) == ("kafka", "kafka", 3)
        assert batch["groups_new"] is None
        messages = [m for log in broker.logs for m in log]
        assert [len(decode(m).violations) for m in messages] == [1, 3]
        assert client.get("/v1/csp/ingest").json()["published"] == 4
        broker.fail_publish = ConnectionError("no brokers")
        response = client.post(
            REPORTS, content=(EXAMPLES / "report-uri.json").read_bytes(), headers=CSP
        )
        assert response.status_code == 503
        assert response.headers["retry-after"] == "2"
        assert _total(client) == 0

    engine = make_engine(database_url)
    try:
        consumer = ReportConsumer(
            broker.subscriber(), make_sessionmaker(engine), group="sentinel", max_groups=100
        )
        await consumer.start()
        stats = await consumer.run(idle_exit=0.05, timeout=0.01)
        assert (stats.messages, stats.written) == (2, 4)
    finally:
        await engine.dispose()
    with TestClient(create_app(Settings(database_url=database_url))) as client:
        assert _total(client) == 4


def test_settings_validate_the_ingest_options() -> None:
    with pytest.raises(ValueError, match="needs kafka_bootstrap_servers"):
        Settings(csp_ingest_mode="kafka")
    with pytest.raises(ValueError, match="csp_buffer_max_reports must be at least"):
        Settings(csp_buffer_max_reports=10, csp_flush_reports=20)
    with pytest.raises(ValueError, match="csp_buffer_max_reports must be at least"):
        Settings(csp_buffer_max_reports=50, csp_flush_reports=10)  # < 100 per request
    with pytest.raises(ValueError, match="kafka_topic"):
        Settings(kafka_topic="bad topic")


def test_kafka_mode_builds_an_aiokafka_publisher(sqlite_url: str) -> None:
    from script_sentinel.app import make_sink
    from script_sentinel.ingest import QueueSink
    from script_sentinel.kafka import AioKafkaPublisher

    settings = Settings(
        database_url=sqlite_url,
        csp_ingest_mode="kafka",
        kafka_bootstrap_servers="broker-1:9092,broker-2:9092",
        kafka_topic="csp",
    )
    sink = make_sink(settings, None)  # type: ignore[arg-type]
    assert isinstance(sink, QueueSink)
    publisher = sink._publisher
    assert isinstance(publisher, AioKafkaPublisher)
    assert (publisher.bootstrap_servers, publisher.topic) == ("broker-1:9092,broker-2:9092", "csp")
    assert make_sink(Settings(database_url=sqlite_url), None) is None  # type: ignore[arg-type]


async def test_the_load_generator_against_the_buffered_collector(database_url: str) -> None:
    spec = importlib.util.spec_from_file_location("csp_load", EXAMPLES.parent / "csp_load.py")
    assert spec is not None
    assert spec.loader is not None
    load = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(load)
    settings = Settings(
        database_url=database_url,
        csp_ingest_mode="buffered",
        csp_flush_interval_seconds=0.05,
        csp_reports_per_minute=1_000_000,
        csp_burst=100_000,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        async with app.state.sessionmaker() as session, session.begin():
            await sites.create_site(
                session, name="shop", allowed_origins=[ORIGIN], scan_interval_hours=24
            )
        result = await load.run(
            "http://collector",
            "shop",
            ORIGIN,
            requests=40,
            batch=10,
            concurrency=4,
            hosts=5,
            transport=httpx.ASGITransport(app=app),
        )
    assert (result["requests"], result["reports"], result["status"]) == (40, 400, {"202": 40})
    assert result["reports_per_second"] > 0
    engine = make_engine(database_url)
    try:
        async with make_sessionmaker(engine)() as session:
            page = await violations.list_violations(session, "shop", limit=500)
            assert page.total_reports == 400  # flushed on shutdown at the latest
            report = await violations.rollup(session, "shop", by=violations.RollupDimension.BLOCKED)
            assert {r.blocked for r in report.rows} == {f"px{i}.load.test" for i in range(5)}
    finally:
        await engine.dispose()
