from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from script_sentinel import sites
from script_sentinel.db import make_engine, make_sessionmaker
from script_sentinel.db.models import CspReportFormat, CspRollup, CspViolation, IngestOffset
from script_sentinel.ingest import (
    BufferedSink,
    IngestUnavailableError,
    MemoryBroker,
    MessageError,
    QueueSink,
    ReportConsumer,
    decode,
    encode,
)
from script_sentinel.violations import Pending
from tests.test_rollups import INLINE, ORIGIN, T0, _v


@pytest.fixture
async def maker(database_url: str) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = make_engine(database_url)
    try:
        yield make_sessionmaker(engine)
    finally:
        await engine.dispose()


async def _site(maker: async_sessionmaker[AsyncSession], name: str = "shop") -> uuid.UUID:
    async with maker() as session, session.begin():
        await sites.create_site(
            session, name=name, allowed_origins=[ORIGIN], scan_interval_hours=24
        )
        return (await sites.get_site(session, name)).id


async def _reports(maker: async_sessionmaker[AsyncSession]) -> int:
    async with maker() as session:
        total = await session.scalar(select(func.coalesce(func.sum(CspViolation.count), 0)))
        return int(total or 0)


class Flaky:
    """A sessionmaker that fails the next ``failures`` sessions on first use."""

    def __init__(self, maker: async_sessionmaker[AsyncSession], failures: int = 1) -> None:
        self.maker = maker
        self.failures = failures

    def __call__(self) -> Any:
        if self.failures:
            self.failures -= 1
            return _broken()
        return self.maker()


@asynccontextmanager
async def _broken() -> AsyncIterator[Any]:
    class Session:
        @asynccontextmanager
        async def begin(self) -> AsyncIterator[None]:
            raise ConnectionError("database is down")
            yield  # pragma: no cover

    yield Session()


class Slow:
    """A sessionmaker whose first transaction stalls before writing."""

    def __init__(self, maker: async_sessionmaker[AsyncSession], delay: float) -> None:
        self.maker = maker
        self.delay = delay
        self.started = asyncio.Event()

    def __call__(self) -> Any:
        if self.started.is_set():
            return self.maker()
        return self._stalled()

    @asynccontextmanager
    async def _stalled(self) -> AsyncIterator[Any]:
        self.started.set()
        async with self.maker() as session:
            await asyncio.sleep(self.delay)
            yield session


# --- Wire format ---------------------------------------------------------------------------------


def test_messages_round_trip() -> None:
    pending = Pending(uuid.uuid4(), T0, [_v(), INLINE])
    raw = encode(pending)
    assert decode(raw) == pending
    assert json.loads(raw)["v"] == 1


@pytest.mark.parametrize(
    "raw",
    [
        b"not json",
        b"{}",
        b'{"v": 2, "site_id": "00000000-0000-0000-0000-000000000000", '
        b'"received_at": "2026-11-28T10:00:00Z", "violations": []}',
        b'{"v": 1, "site_id": "x", "received_at": "2026-11-28T10:00:00Z", "violations": []}',
        b'{"v": 1, "site_id": "00000000-0000-0000-0000-000000000000", '
        b'"received_at": "2026-11-28T10:00:00Z", "violations": [{"format": "csp-report"}]}',
        b'{"v": 1, "site_id": "00000000-0000-0000-0000-000000000000", '
        b'"received_at": "2026-11-28T10:00:00Z", "violations": [], "extra": 1}',
    ],
)
def test_bad_messages_are_refused(raw: bytes) -> None:
    with pytest.raises(MessageError, match="not a pending report batch"):
        decode(raw)


def test_a_naive_timestamp_is_refused() -> None:
    raw = encode(Pending(uuid.uuid4(), T0, [_v()])).replace(b"+00:00", b"")
    with pytest.raises(MessageError, match="no timezone"):
        decode(raw)


# --- The buffered sink -------------------------------------------------------------------------


async def test_buffered_sink_flushes_when_full_enough(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    site = await _site(maker)
    sink = BufferedSink(maker, max_groups=100, max_pending=10, flush_at=3, flush_interval=30)
    await sink.start()
    await sink.start()  # idempotent
    try:
        await sink.submit(Pending(site, T0, []))  # nothing to queue
        await sink.submit(Pending(site, T0, [_v(), _v()]))
        assert sink.pending == 2
        await asyncio.sleep(0.05)
        assert await _reports(maker) == 0  # below flush_at, and the interval is long
        await sink.submit(Pending(site, T0, [INLINE]))
        for _ in range(100):
            if sink.pending == 0 and sink.stats.flushes:
                break
            await asyncio.sleep(0.01)
        assert await _reports(maker) == 3
        status = sink.status()
        assert status["mode"] == "buffered"
        assert (status["pending"], status["flushes"], status["written"]) == (0, 1, 3)
        assert status["last_flush_at"] is not None
        assert status["last_error"] is None
    finally:
        await sink.close()


async def test_buffered_sink_flushes_on_its_interval_and_on_close(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    site = await _site(maker)
    sink = BufferedSink(maker, max_groups=100, max_pending=100, flush_at=50, flush_interval=0.02)
    await sink.start()
    await sink.submit(Pending(site, T0, [_v()]))
    for _ in range(100):
        if sink.stats.flushes:
            break
        await asyncio.sleep(0.01)
    assert await _reports(maker) == 1
    await sink.submit(Pending(site, T0, [_v()]))
    sink.flush_interval = 30  # the next tick is far away; close() must flush
    await sink.close()
    assert await _reports(maker) == 2
    assert await sink.flush() is None  # nothing left
    await sink.close()  # closing twice is harmless


async def test_a_full_buffer_answers_with_backpressure(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    site = await _site(maker)
    sink = BufferedSink(maker, max_groups=100, max_pending=3, flush_at=3, flush_interval=0.5)
    await sink.submit(Pending(site, T0, [_v(), _v()]))
    with pytest.raises(IngestUnavailableError, match="buffer is full") as exc:
        await sink.submit(Pending(site, T0, [_v(), _v()]))
    assert exc.value.retry_after == 0.5
    assert sink.stats.refused == 2
    await sink.submit(Pending(site, T0, [_v()]))  # exactly full is fine
    assert sink.pending == 3


async def test_a_failed_flush_keeps_the_batch_in_order_and_backs_off(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    site = await _site(maker)
    flaky = Flaky(maker, failures=2)
    sink = BufferedSink(flaky, max_groups=100, max_pending=4, flush_at=4, flush_interval=0.25)  # type: ignore[arg-type]
    first = Pending(site, T0, [_v(fmt=CspReportFormat.CSP_REPORT)])
    await sink.submit(first)
    with pytest.raises(ConnectionError):
        await sink.flush()
    assert sink.backoff() == 0.5
    # More arrives while the database is down; the old batch stays in front of it.
    late = Pending(site, T0 - timedelta(minutes=1), [_v()])
    await sink.submit(late)
    with pytest.raises(ConnectionError):
        await sink.flush()
    assert sink.backoff() == 1.0
    assert sink.pending == 2
    assert sink.status()["failed_flushes"] == 2
    assert "database is down" in sink.status()["last_error"]
    # Still bounded while it can't write: backpressure tells clients to wait out the backoff.
    with pytest.raises(IngestUnavailableError) as exc:
        await sink.submit(Pending(site, T0, [_v(), _v(), _v()]))
    assert exc.value.retry_after == 1.0
    result = await sink.flush()
    assert result is not None
    assert result.accepted == 2
    assert sink.backoff() == 0.25
    assert sink.status()["last_error"] is None
    assert await _reports(maker) == 2


async def test_the_flusher_survives_failures(
    maker: async_sessionmaker[AsyncSession], caplog: pytest.LogCaptureFixture
) -> None:
    site = await _site(maker)
    flaky = Flaky(maker, failures=1)
    sink = BufferedSink(flaky, max_groups=100, max_pending=10, flush_at=1, flush_interval=0.01)  # type: ignore[arg-type]
    await sink.start()
    with caplog.at_level(logging.ERROR, logger="script_sentinel.ingest"):
        await sink.submit(Pending(site, T0, [_v()]))
        for _ in range(200):
            if sink.stats.flushes:
                break
            await asyncio.sleep(0.01)
    await sink.close()
    assert (sink.stats.failed_flushes, sink.stats.flushes) == (1, 1)
    assert await _reports(maker) == 1
    assert "flushing 1 CSP reports failed" in caplog.text


async def test_close_lets_a_flush_in_progress_finish(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    site = await _site(maker)
    slow = Slow(maker, delay=0.2)
    sink = BufferedSink(slow, max_groups=100, flush_at=1, flush_interval=30)  # type: ignore[arg-type]
    await sink.start()
    await sink.submit(Pending(site, T0, [_v(), _v()]))
    await slow.started.wait()
    await sink.submit(Pending(site, T0, [INLINE]))  # arrives during the flush
    await sink.close()
    assert await _reports(maker) == 3
    assert (sink.stats.flushes, sink.stats.written, sink.pending) == (2, 3, 0)


async def test_close_cancels_a_stuck_flush_without_losing_its_batch(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    site = await _site(maker)
    slow = Slow(maker, delay=30)
    sink = BufferedSink(
        slow,  # type: ignore[arg-type]
        max_groups=100,
        flush_at=1,
        flush_interval=30,
        stop_timeout=0.05,
    )
    await sink.start()
    await sink.submit(Pending(site, T0, [_v(), _v()]))
    await slow.started.wait()
    await sink.close()  # the stuck flush is cancelled; its batch is written by close()
    assert await _reports(maker) == 2
    assert (sink.stats.flushes, sink.stats.failed_flushes, sink.pending) == (1, 0, 0)
    await sink.start()  # a closed sink can be started again
    await sink.submit(Pending(site, T0, [_v()]))
    await sink.close()
    assert await _reports(maker) == 3


async def test_close_logs_what_it_could_not_flush(
    maker: async_sessionmaker[AsyncSession], caplog: pytest.LogCaptureFixture
) -> None:
    site = await _site(maker)
    sink = BufferedSink(Flaky(maker, failures=1), max_groups=100)  # type: ignore[arg-type]
    await sink.submit(Pending(site, T0, [_v()]))
    with caplog.at_level(logging.ERROR, logger="script_sentinel.ingest"):
        await sink.close()
    assert "could not flush 1 CSP reports on shutdown" in caplog.text


async def test_flushes_count_group_limit_and_deleted_sites(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    site = await _site(maker)
    sink = BufferedSink(maker, max_groups=1)
    await sink.submit(Pending(site, T0, [_v(), INLINE]))
    await sink.submit(Pending(uuid.uuid4(), T0, [_v()]))
    await sink.flush()
    assert sink.status()["dropped"] == {"group_limit": 1, "site_gone": 1}
    assert sink.status()["written"] == 1


async def test_flushes_prune_old_rollups_at_most_hourly(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    site = await _site(maker)
    now = [T0]
    sink = BufferedSink(maker, max_groups=100, retention=timedelta(days=2), clock=lambda: now[0])
    await sink.submit(Pending(site, T0 - timedelta(days=3), [_v()]))
    await sink.flush()  # writes the old bucket, then prunes it in the same transaction
    async with maker() as session:
        assert await session.scalar(select(func.count()).select_from(CspRollup)) == 0
    await sink.submit(Pending(site, T0 - timedelta(days=3), [_v()]))
    now[0] = T0 + timedelta(minutes=30)
    await sink.flush()  # within the hour: no prune
    async with maker() as session:
        assert await session.scalar(select(func.count()).select_from(CspRollup)) == 1
    now[0] = T0 + timedelta(hours=1)
    await sink.submit(Pending(site, T0, [_v()]))
    await sink.flush()
    async with maker() as session:
        assert await session.scalar(select(func.count()).select_from(CspRollup)) == 1


def test_buffered_sink_validates_its_settings() -> None:
    with pytest.raises(ValueError, match="flush_at"):
        BufferedSink(None, max_groups=1, max_pending=5, flush_at=6)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="flush_at"):
        BufferedSink(None, max_groups=1, flush_at=0)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="flush_interval"):
        BufferedSink(None, max_groups=1, flush_interval=0)  # type: ignore[arg-type]


# --- The queue sink and the consumer --------------------------------------------------------------


async def test_queue_sink_publishes_one_message_per_request() -> None:
    broker = MemoryBroker(partitions=2)
    sink = QueueSink(broker.publisher(), retry_after=3)
    await sink.start()
    site = uuid.uuid4()
    await sink.submit(Pending(site, T0, [_v(), INLINE]))
    await sink.submit(Pending(site, T0, []))  # nothing to publish
    await sink.submit(Pending(site, T0, [_v()]))
    log = broker.logs[broker.partition_for(site.bytes)]
    assert [len(decode(m).violations) for m in log] == [2, 1]
    assert sum(len(p) for p in broker.logs) == 2  # one site, one partition
    broker.fail_publish = TimeoutError("broker unreachable")
    with pytest.raises(IngestUnavailableError, match="queue is unavailable") as exc:
        await sink.submit(Pending(site, T0, [_v()]))
    assert exc.value.retry_after == 3
    assert sink.status() == {
        "mode": "kafka",
        "messages": 2,
        "published": 3,
        "failures": 1,
        "last_error": "TimeoutError: broker unreachable",
    }
    await sink.close()


def test_memory_broker_needs_a_partition() -> None:
    with pytest.raises(ValueError, match="partitions"):
        MemoryBroker(partitions=0)


async def _publish(broker: MemoryBroker, *batches: Pending) -> None:
    publisher = broker.publisher()
    for pending in batches:
        await publisher.publish(pending.site_id.bytes, encode(pending))


def _consumer(
    broker: MemoryBroker, maker: Any, *, batch_size: int = 1_000, group: str = "g"
) -> ReportConsumer:
    return ReportConsumer(
        broker.subscriber(group), maker, group=group, max_groups=100, batch_size=batch_size
    )


async def _offsets(maker: async_sessionmaker[AsyncSession]) -> dict[int, int]:
    async with maker() as session:
        rows = await session.scalars(select(IngestOffset))
        return {r.partition: r.next_offset for r in rows}


async def test_the_consumer_applies_batches_and_stores_offsets(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    shop, blog = await _site(maker), await _site(maker, "blog")
    broker = MemoryBroker(partitions=4)
    await _publish(
        broker,
        Pending(shop, T0, [_v(), _v()]),
        Pending(blog, T0, [INLINE]),
        Pending(shop, T0 + timedelta(minutes=1), [_v()]),
    )
    consumer = _consumer(broker, maker, batch_size=2)
    await consumer.start()
    assert await consumer.run_once(0) == 2
    assert await consumer.run_once(0) == 1
    assert await consumer.run_once(0) == 0
    assert await _reports(maker) == 4
    expected: dict[int, int] = {}
    for key in (shop, blog, shop):
        partition = broker.partition_for(key.bytes)
        expected[partition] = expected.get(partition, 0) + 1
    assert await _offsets(maker) == expected
    assert broker.committed == {"g": expected}
    assert consumer.stats.to_dict() == {
        "batches": 2,
        "messages": 3,
        "duplicates": 0,
        "poison": 0,
        "written": 4,
        "dropped": {},
        "commit_failures": 0,
    }
    await consumer.close()


async def test_redelivery_after_a_failed_broker_commit_is_not_counted_twice(
    maker: async_sessionmaker[AsyncSession], caplog: pytest.LogCaptureFixture
) -> None:
    site = await _site(maker)
    broker = MemoryBroker(partitions=1)
    await _publish(broker, Pending(site, T0, [_v()]), Pending(site, T0, [_v()]))
    broker.fail_commit = ConnectionError("coordinator moved")
    consumer = _consumer(broker, maker)
    await consumer.start()
    with caplog.at_level(logging.WARNING, logger="script_sentinel.ingest"):
        assert await consumer.run_once(0) == 2
    assert "broker commit failed" in caplog.text
    assert consumer.stats.commit_failures == 1
    assert broker.committed == {}
    # The process restarts. The broker would redeliver from offset 0, but the consumer
    # seeks to what the database applied, and skips anything below it regardless.
    broker.fail_commit = None
    await _publish(broker, Pending(site, T0, [_v()]))
    restarted = _consumer(broker, maker)
    await restarted.start()
    restarted._subscriber.position = {0: 0}  # type: ignore[attr-defined]  # a stale seek
    assert await restarted.run_once(0) == 3
    assert restarted.stats.duplicates == 2
    assert await _reports(maker) == 3
    assert await _offsets(maker) == {0: 3}


async def test_a_batch_that_fails_to_apply_is_retried_without_loss(
    maker: async_sessionmaker[AsyncSession], caplog: pytest.LogCaptureFixture
) -> None:
    site = await _site(maker)
    broker = MemoryBroker(partitions=2)
    await _publish(broker, Pending(site, T0, [_v(), INLINE]))
    flaky = Flaky(maker, failures=0)
    consumer = ReportConsumer(broker.subscriber("g"), flaky, group="g", max_groups=100)  # type: ignore[arg-type]
    await consumer.start()
    flaky.failures = 1
    with caplog.at_level(logging.ERROR, logger="script_sentinel.ingest"):
        stats = await consumer.run(idle_exit=0.05, timeout=0.01)
    assert "applying a batch failed" in caplog.text
    assert (stats.batches, stats.written, stats.duplicates) == (1, 2, 0)
    assert await _reports(maker) == 2


async def test_poison_messages_are_skipped_and_their_offsets_stored(
    maker: async_sessionmaker[AsyncSession], caplog: pytest.LogCaptureFixture
) -> None:
    site = await _site(maker)
    broker = MemoryBroker(partitions=1)
    broker.append(0, b"garbage")
    await _publish(broker, Pending(site, T0, [_v()]), Pending(uuid.uuid4(), T0, [_v()]))
    consumer = _consumer(broker, maker)
    await consumer.start()
    with caplog.at_level(logging.WARNING, logger="script_sentinel.ingest"):
        assert await consumer.run_once(0) == 3
    assert "skipping message sentinel.csp-reports/0@0" in caplog.text
    assert (consumer.stats.poison, consumer.stats.written) == (1, 1)
    assert consumer.stats.dropped == {"site_gone": 1}
    assert await _offsets(maker) == {0: 3}


async def test_consumer_groups_keep_their_own_offsets_and_the_cap_applies(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    site = await _site(maker)
    broker = MemoryBroker(partitions=1)
    await _publish(broker, Pending(site, T0, [_v(), INLINE, _v(page="/x")]))
    capped = ReportConsumer(broker.subscriber("a"), maker, group="a", max_groups=2)
    await capped.start()
    await capped.run_once(0)
    assert capped.stats.dropped == {"group_limit": 1}
    other = _consumer(broker, maker, group="b")
    await other.start()
    assert await other.run_once(0) == 1  # group b starts from the beginning
    async with maker() as session:
        rows = await session.execute(select(IngestOffset.consumer_group, IngestOffset.next_offset))
        assert sorted(rows) == [("a", 1), ("b", 1)]


async def test_run_stops_on_the_event_or_when_idle(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    await _site(maker)
    broker = MemoryBroker()
    consumer = _consumer(broker, maker)
    await consumer.start()
    stop = asyncio.Event()
    stop.set()
    assert (await consumer.run(stop=stop)).batches == 0
    started = asyncio.get_running_loop().time()
    await consumer.run(idle_exit=0.05, timeout=0.01)
    assert asyncio.get_running_loop().time() - started >= 0.05


async def test_a_failed_rewind_is_logged(
    maker: async_sessionmaker[AsyncSession], caplog: pytest.LogCaptureFixture
) -> None:
    broker = MemoryBroker()
    consumer = _consumer(broker, maker)

    async def broken(*_: Any) -> None:
        raise RuntimeError("no assignment")

    consumer._subscriber.rewind = broken  # type: ignore[method-assign,assignment]
    with caplog.at_level(logging.ERROR, logger="script_sentinel.ingest"):
        await consumer._rewind()
    assert "could not rewind" in caplog.text


def test_timestamps_survive_the_queue() -> None:
    received = datetime(2026, 11, 28, 23, 59, 59, 123456, tzinfo=UTC)
    assert decode(encode(Pending(uuid.uuid4(), received, [_v()]))).received_at == received
