"""The aiokafka adapters against a real broker (CI runs one; locally, set
SENTINEL_TEST_KAFKA_BOOTSTRAP=localhost:9092 with a broker running)."""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncIterator, Sequence
from typing import Any, NamedTuple

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from script_sentinel import kafka, sites
from script_sentinel.db import make_engine, make_sessionmaker
from script_sentinel.ingest import QueueSink, Record, ReportConsumer
from script_sentinel.kafka import AioKafkaPublisher, AioKafkaSubscriber
from script_sentinel.violations import Pending, list_violations
from tests.test_rollups import INLINE, ORIGIN, T0, _v

BOOTSTRAP = os.environ.get("SENTINEL_TEST_KAFKA_BOOTSTRAP")
needs_kafka = pytest.mark.skipif(
    not BOOTSTRAP, reason="set SENTINEL_TEST_KAFKA_BOOTSTRAP to run the Kafka tests"
)


def test_aiokafka_is_loaded_lazily() -> None:
    assert kafka._aiokafka().__name__ == "aiokafka"


async def test_publish_before_start_and_close_without_start() -> None:
    publisher = AioKafkaPublisher("127.0.0.1:9", "t")
    with pytest.raises(RuntimeError, match="isn't started"):
        await publisher.publish(b"k", b"v")
    await publisher.close()
    await AioKafkaSubscriber("127.0.0.1:9", "t", group_id="g").close()


@pytest.fixture
async def topic() -> AsyncIterator[str]:
    assert BOOTSTRAP is not None
    from aiokafka.admin import AIOKafkaAdminClient, NewTopic

    name = f"sentinel-test-{uuid.uuid4().hex[:12]}"
    admin = AIOKafkaAdminClient(bootstrap_servers=BOOTSTRAP)
    await admin.start()
    try:
        await admin.create_topics([NewTopic(name, num_partitions=3, replication_factor=1)])
        yield name
        await admin.delete_topics([name])
    finally:
        await admin.close()


@pytest.fixture
async def maker(sqlite_url: str) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = make_engine(sqlite_url)
    try:
        yield make_sessionmaker(engine)
    finally:
        await engine.dispose()


async def _consume(consumer: ReportConsumer, messages: int, deadline: float = 60) -> None:
    """Run batches until ``messages`` more have been read (joining a group takes a while)."""
    target = consumer.stats.messages + messages
    loop = asyncio.get_running_loop()
    end = loop.time() + deadline
    while consumer.stats.messages < target:
        assert loop.time() < end, f"read {consumer.stats.messages} of {target} messages"
        await consumer.run_once(timeout=0.5)


@needs_kafka
@pytest.mark.kafka
async def test_reports_round_trip_through_kafka_effectively_once(
    topic: str, maker: async_sessionmaker[AsyncSession]
) -> None:
    assert BOOTSTRAP is not None
    async with maker() as session, session.begin():
        shop = await sites.create_site(
            session, name="shop", allowed_origins=[ORIGIN], scan_interval_hours=24
        )
        blog = await sites.create_site(
            session, name="blog", allowed_origins=[ORIGIN], scan_interval_hours=24
        )
        shop_id, blog_id = shop.id, blog.id

    sink = QueueSink(AioKafkaPublisher(BOOTSTRAP, topic, send_timeout=10))
    await sink.start()
    try:
        await sink.submit(Pending(shop_id, T0, [_v(), _v()]))
        await sink.submit(Pending(blog_id, T0, [INLINE]))
        await sink.submit(Pending(shop_id, T0, [_v()]))
    finally:
        await sink.close()
    assert (sink.messages, sink.published, sink.failures) == (3, 4, 0)

    group = f"g-{uuid.uuid4().hex[:8]}"
    consumer = ReportConsumer(
        AioKafkaSubscriber(BOOTSTRAP, topic, group_id=group), maker, group=group, max_groups=100
    )
    await consumer.start()
    try:
        await _consume(consumer, 3)
    finally:
        await consumer.close()
    assert (consumer.stats.written, consumer.stats.duplicates) == (4, 0)

    # A consumer whose broker-side group has never committed anything (as if every broker
    # commit had been lost) still starts where the database says, so nothing is counted
    # twice and nothing is even reread: it seeks past what was applied.
    sink = QueueSink(AioKafkaPublisher(BOOTSTRAP, topic))
    await sink.start()
    await sink.submit(Pending(shop_id, T0, [_v()]))
    await sink.close()
    fresh = ReportConsumer(
        AioKafkaSubscriber(BOOTSTRAP, topic, group_id=f"{group}-fresh"),
        maker,
        group=group,
        max_groups=100,
    )
    await fresh.start()
    try:
        await _consume(fresh, 1)
        await fresh._rewind()  # seeking again to the stored offsets rereads nothing
        assert await fresh.run_once(timeout=1) == 0
    finally:
        await fresh.close()
    assert (fresh.stats.messages, fresh.stats.duplicates, fresh.stats.written) == (1, 0, 1)

    async with maker() as session:
        assert (await list_violations(session, "shop")).total_reports == 4
        assert (await list_violations(session, "blog")).total_reports == 1


# --- The adapters against a stand-in for aiokafka -------------------------------------------------


class _TP(NamedTuple):
    topic: str
    partition: int


class _Message(NamedTuple):
    offset: int
    value: bytes | None


class _FakeAioKafka:
    """Just enough of aiokafka's surface to check what the adapters ask of it."""

    TopicPartition = _TP

    class ConsumerRebalanceListener:
        pass

    def __init__(self) -> None:
        self.producers: list[Any] = []
        self.consumers: list[Any] = []
        lib = self

        class Producer:
            def __init__(self, **kwargs: Any) -> None:
                self.kwargs = kwargs
                self.sent: list[tuple[str, bytes, bytes]] = []
                self.stopped = False
                self.delay = 0.0
                lib.producers.append(self)

            async def start(self) -> None:
                pass

            async def send_and_wait(self, topic: str, value: bytes, key: bytes) -> None:
                await asyncio.sleep(self.delay)
                self.sent.append((topic, key, value))

            async def stop(self) -> None:
                self.stopped = True

        class Consumer:
            def __init__(self, **kwargs: Any) -> None:
                self.kwargs = kwargs
                self.seeks: list[tuple[_TP, int]] = []
                self.commits: list[dict[_TP, int]] = []
                self.batch: dict[_TP, list[_Message]] = {}
                self.assigned: list[_TP] = []
                self.stopped = False
                lib.consumers.append(self)

            def subscribe(self, topics: list[str], listener: Any) -> None:
                self.topics = topics
                self.listener = listener

            async def start(self) -> None:
                self.assigned = [_TP(self.topics[0], 0), _TP(self.topics[0], 1)]
                await self.listener.on_partitions_revoked([])
                await self.listener.on_partitions_assigned(self.assigned)

            def seek(self, tp: _TP, offset: int) -> None:
                self.seeks.append((tp, offset))

            async def getmany(self, timeout_ms: int, max_records: int) -> dict[_TP, Any]:
                self.last_getmany = (timeout_ms, max_records)
                batch, self.batch = self.batch, {}
                return batch

            async def commit(self, offsets: dict[_TP, int]) -> None:
                self.commits.append(offsets)

            def assignment(self) -> set[_TP]:
                return set(self.assigned)

            async def stop(self) -> None:
                self.stopped = True

        self.AIOKafkaProducer = Producer
        self.AIOKafkaConsumer = Consumer


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> _FakeAioKafka:
    lib = _FakeAioKafka()
    monkeypatch.setattr(kafka, "_aiokafka", lambda: lib)
    return lib


async def test_publisher_waits_for_acks_with_a_deadline(fake: _FakeAioKafka) -> None:
    publisher = AioKafkaPublisher("b:9092", "csp", send_timeout=0.05, linger_ms=2)
    await publisher.start()
    (producer,) = fake.producers
    assert producer.kwargs == {
        "bootstrap_servers": "b:9092",
        "client_id": "script-sentinel",
        "acks": "all",
        "enable_idempotence": True,
        "linger_ms": 2,
        "request_timeout_ms": 1000,
    }
    await publisher.publish(b"key", b"value")
    assert producer.sent == [("csp", b"key", b"value")]
    producer.delay = 1
    with pytest.raises(TimeoutError):
        await publisher.publish(b"key", b"late")
    await publisher.close()
    assert producer.stopped
    await publisher.close()


async def test_subscriber_seeks_to_stored_offsets_and_commits(fake: _FakeAioKafka) -> None:
    subscriber = AioKafkaSubscriber("b:9092", "csp", group_id="grp")
    asked: list[tuple[str, list[int]]] = []

    async def positions(topic: str, partitions: Sequence[int]) -> dict[int, int]:
        asked.append((topic, list(partitions)))
        return {1: 42}  # the database knows partition 1 only

    await subscriber.start(positions)
    (consumer,) = fake.consumers
    assert consumer.kwargs["enable_auto_commit"] is False
    assert consumer.kwargs["auto_offset_reset"] == "earliest"
    assert consumer.kwargs["group_id"] == "grp"
    assert asked == [("csp", [0, 1])]
    assert consumer.seeks == [(_TP("csp", 1), 42)]

    consumer.batch = {
        _TP("csp", 1): [_Message(42, b"b"), _Message(43, None)],
        _TP("csp", 0): [_Message(7, b"a")],
    }
    records = await subscriber.fetch(10, 0.25)
    assert consumer.last_getmany == (250, 10)
    assert records == [Record(0, 7, b"a"), Record(1, 42, b"b"), Record(1, 43, b"")]
    await subscriber.commit({0: 8, 1: 44})
    assert consumer.commits == [{_TP("csp", 0): 8, _TP("csp", 1): 44}]
    await subscriber.rewind(positions)
    assert consumer.seeks[-1] == (_TP("csp", 1), 42)
    consumer.assigned = []
    await subscriber.rewind(positions)  # nothing assigned: nothing to seek
    assert len(asked) == 2
    await subscriber.close()
    assert consumer.stopped
