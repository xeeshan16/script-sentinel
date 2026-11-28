"""The high-volume path for CSP reports: buffering, backpressure and an optional queue.

The collector can hand what it accepted to the database in three ways
(``SENTINEL_CSP_INGEST_MODE``):

* **direct** (the default): written inside the request, so the response says how many
  groups were new. One transaction per request; fine for modest traffic.
* **buffered**: appended to an in-process buffer and answered at once. A background
  flusher drains the buffer every ``flush_interval`` seconds, or as soon as ``flush_at``
  reports are waiting, and writes the whole batch with one upsert per distinct group (see
  ``violations.write_batch``). The buffer is bounded: when it holds ``max_pending``
  reports the collector answers ``503`` with ``Retry-After`` instead of growing, which is
  also what happens while the database is down, because a failed flush keeps its batch.
* **kafka**: published to a topic, keyed by site so a site's reports stay in order on one
  partition, and answered once the broker has acknowledged them. A separate consumer
  (``sentinel csp consume``) writes them in batches. It stores how far it has applied
  each partition in the same transaction as the counts, so a message redelivered after a
  crash or a failed commit is skipped instead of counted twice.

The broker sits behind two small protocols, :class:`Publisher` and :class:`Subscriber`.
``kafka.py`` implements them with aiokafka (an optional dependency); :class:`MemoryBroker`
implements them in memory for tests and for trying the consumer without a broker.
"""

from __future__ import annotations

import asyncio
import contextlib
import enum
import json
import logging
import uuid
import zlib
from collections import Counter, deque
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field
from pydantic import ValidationError as PydanticValidationError
from sqlalchemy import select, update
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from script_sentinel.csp_reports import Blocked, Violation
from script_sentinel.db.models import (
    CspBlockedKind,
    CspDisposition,
    CspReportFormat,
    IngestOffset,
    utcnow,
)
from script_sentinel.violations import BatchResult, Pending, prune_rollups, write_batch

log = logging.getLogger(__name__)

MESSAGE_VERSION = 1


class IngestMode(enum.StrEnum):
    DIRECT = "direct"
    BUFFERED = "buffered"
    KAFKA = "kafka"


class IngestUnavailableError(Exception):
    """The sink can't take more reports right now; the client should retry later."""

    def __init__(self, message: str, retry_after: float) -> None:
        super().__init__(message)
        self.retry_after = retry_after


# --- Wire format --------------------------------------------------------------------------------


class _BlockedMsg(BaseModel):
    model_config = ConfigDict(extra="forbid")

    value: str = Field(max_length=2048)
    kind: CspBlockedKind
    host: str | None = Field(default=None, max_length=255)


class _ViolationMsg(BaseModel):
    model_config = ConfigDict(extra="forbid")

    format: CspReportFormat
    document_url: str = Field(max_length=2048)
    effective_directive: str = Field(min_length=1, max_length=64)
    blocked: _BlockedMsg
    disposition: CspDisposition
    source_file: str | None = Field(default=None, max_length=2048)
    line: int | None = None
    column: int | None = None
    status_code: int | None = None
    sample: str | None = Field(default=None, max_length=64)
    original_policy: str | None = None
    policy_sha256: str | None = Field(default=None, max_length=64)


class _PendingMsg(BaseModel):
    model_config = ConfigDict(extra="forbid")

    v: int = Field(ge=MESSAGE_VERSION, le=MESSAGE_VERSION)
    site_id: uuid.UUID
    received_at: datetime
    violations: list[_ViolationMsg] = Field(max_length=10_000)


class MessageError(ValueError):
    """A message on the topic that isn't a pending batch of this version."""


def encode(pending: Pending) -> bytes:
    """A pending batch as a compact JSON message."""
    return json.dumps(
        {
            "v": MESSAGE_VERSION,
            "site_id": str(pending.site_id),
            "received_at": pending.received_at.isoformat(),
            "violations": [asdict(v) for v in pending.violations],
        },
        separators=(",", ":"),
    ).encode("utf-8")


def decode(raw: bytes) -> Pending:
    """The pending batch in a message; :class:`MessageError` for anything else."""
    try:
        msg = _PendingMsg.model_validate_json(raw)
    except PydanticValidationError as exc:
        raise MessageError(f"not a pending report batch: {exc.error_count()} errors") from None
    if msg.received_at.tzinfo is None:
        raise MessageError("received_at has no timezone")
    return Pending(
        site_id=msg.site_id,
        received_at=msg.received_at,
        violations=[
            Violation(
                format=v.format,
                document_url=v.document_url,
                effective_directive=v.effective_directive,
                blocked=Blocked(v.blocked.value, v.blocked.kind, v.blocked.host),
                disposition=v.disposition,
                source_file=v.source_file,
                line=v.line,
                column=v.column,
                status_code=v.status_code,
                sample=v.sample,
                original_policy=v.original_policy,
                policy_sha256=v.policy_sha256,
            )
            for v in msg.violations
        ],
    )


# --- Sinks ----------------------------------------------------------------------------------------


class ReportSink(Protocol):
    """Where the collector hands accepted reports when it doesn't write them itself."""

    mode: IngestMode

    async def start(self) -> None: ...

    async def submit(self, pending: Pending) -> None:
        """Take the reports or raise :class:`IngestUnavailableError`."""

    async def close(self) -> None: ...

    def status(self) -> dict[str, Any]: ...


@dataclass(slots=True)
class FlushStats:
    flushes: int = 0
    failed_flushes: int = 0
    written: int = 0  # reports counted towards a group
    dropped: Counter[str] = field(default_factory=Counter)  # group_limit, site_gone
    refused: int = 0  # reports answered with 503 because the buffer was full
    last_flush_at: datetime | None = None
    last_error: str | None = None

    def count(self, result: BatchResult) -> None:
        self.written += result.accepted
        if result.over_limit:
            self.dropped["group_limit"] += result.over_limit
        if result.site_gone:
            self.dropped["site_gone"] += result.site_gone


class BufferedSink:
    """An in-process buffer drained in batches by a background task."""

    mode = IngestMode.BUFFERED

    def __init__(
        self,
        sessionmaker: async_sessionmaker[AsyncSession],
        *,
        max_groups: int,
        max_pending: int = 50_000,
        flush_at: int = 1_000,
        flush_interval: float = 1.0,
        retention: timedelta | None = None,
        clock: Callable[[], datetime] = utcnow,
        stop_timeout: float = 30.0,
    ) -> None:
        if not 1 <= flush_at <= max_pending:
            raise ValueError("flush_at must be between 1 and max_pending")
        if flush_interval <= 0:
            raise ValueError("flush_interval must be positive")
        self._sessionmaker = sessionmaker
        self.max_groups = max_groups
        self.max_pending = max_pending
        self.flush_at = flush_at
        self.flush_interval = flush_interval
        self.retention = retention
        self._clock = clock
        self._queue: deque[Pending] = deque()
        self._pending = 0
        self._wake = asyncio.Event()
        self._flush_lock = asyncio.Lock()
        self._task: asyncio.Task[None] | None = None
        self._stopping = False
        self._stop_timeout = stop_timeout
        self._failures = 0
        self._last_prune: datetime | None = None
        self.stats = FlushStats()

    @property
    def pending(self) -> int:
        """Reports waiting to be written."""
        return self._pending

    async def start(self) -> None:
        if self._task is None:
            self._stopping = False
            self._task = asyncio.create_task(self._run(), name="csp-ingest-flusher")

    async def submit(self, pending: Pending) -> None:
        n = len(pending.violations)
        if n == 0:
            return
        if self._pending + n > self.max_pending:
            self.stats.refused += n
            raise IngestUnavailableError(
                f"the report buffer is full ({self._pending} reports waiting)",
                retry_after=self.backoff(),
            )
        self._queue.append(pending)
        self._pending += n
        if self._pending >= self.flush_at:
            self._wake.set()

    def backoff(self) -> float:
        """Seconds until the next flush attempt: the interval, doubled per failure (≤ 60)."""
        return min(60.0, self.flush_interval * float(2 ** min(self._failures, 16)))

    async def flush(self) -> BatchResult | None:
        """Write everything waiting. On failure the batch goes back to the front of the
        buffer (still counting against ``max_pending``) and the error is re-raised."""
        async with self._flush_lock:
            if not self._queue:
                return None
            batch = list(self._queue)
            size = self._pending
            self._queue.clear()
            self._pending = 0
            try:
                async with self._sessionmaker() as session, session.begin():
                    result = await write_batch(session, batch, max_groups=self.max_groups)
                    await self._maybe_prune(session)
            except BaseException as exc:
                # Put it back in front of whatever arrived meanwhile, in order. That
                # includes being cancelled mid-write: the transaction is rolled back, so
                # the batch would otherwise be lost.
                self._queue.extendleft(reversed(batch))
                self._pending += size
                if isinstance(exc, Exception):
                    self._failures += 1
                    self.stats.failed_flushes += 1
                    self.stats.last_error = f"{type(exc).__name__}: {exc}"[:500]
                raise
            self._failures = 0
            self.stats.flushes += 1
            self.stats.last_flush_at = self._clock()
            self.stats.last_error = None
            self.stats.count(result)
            return result

    async def _maybe_prune(self, session: AsyncSession) -> None:
        if self.retention is None:
            return
        now = self._clock()
        if self._last_prune is not None and now - self._last_prune < timedelta(hours=1):
            return
        await prune_rollups(session, before=now - self.retention)
        self._last_prune = now

    async def _run(self) -> None:
        while not self._stopping:
            timeout = self.backoff() if self._failures else self.flush_interval
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._wake.wait(), timeout)
            self._wake.clear()
            if self._stopping:
                break  # close() writes what is left
            try:
                await self.flush()
            except Exception:
                log.exception(
                    "flushing %d CSP reports failed; retrying in %.1fs",
                    self._pending,
                    self.backoff(),
                )

    async def close(self) -> None:
        """Stop the flusher and write what is left (once; a failure is logged).

        The flusher is asked to stop rather than cancelled, so a flush in progress
        finishes; only one that takes longer than ``stop_timeout`` is cancelled (and its
        batch goes back into the buffer for the final flush).
        """
        if self._task is not None:
            self._stopping = True
            self._wake.set()
            try:
                await asyncio.wait_for(asyncio.shield(self._task), self._stop_timeout)
            except TimeoutError:
                self._task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await self._task
            self._task = None
        try:
            await self.flush()
        except Exception:
            log.exception("could not flush %d CSP reports on shutdown", self._pending)

    def status(self) -> dict[str, Any]:
        s = self.stats
        return {
            "mode": self.mode.value,
            "pending": self._pending,
            "max_pending": self.max_pending,
            "flush_at": self.flush_at,
            "flush_interval_seconds": self.flush_interval,
            "flushes": s.flushes,
            "failed_flushes": s.failed_flushes,
            "written": s.written,
            "dropped": dict(s.dropped),
            "refused": s.refused,
            "last_flush_at": s.last_flush_at.isoformat() if s.last_flush_at else None,
            "last_error": s.last_error,
        }


class Publisher(Protocol):
    async def start(self) -> None: ...

    async def publish(self, key: bytes, value: bytes) -> None:
        """Return once the broker has the message; raise on failure or timeout."""

    async def close(self) -> None: ...


class QueueSink:
    """Publishes each request's reports as one message, keyed by site."""

    mode = IngestMode.KAFKA

    def __init__(self, publisher: Publisher, *, retry_after: float = 5.0) -> None:
        self._publisher = publisher
        self._retry_after = retry_after
        self.published = 0  # reports
        self.messages = 0
        self.failures = 0
        self.last_error: str | None = None

    async def start(self) -> None:
        await self._publisher.start()

    async def submit(self, pending: Pending) -> None:
        if not pending.violations:
            return
        try:
            await self._publisher.publish(pending.site_id.bytes, encode(pending))
        except Exception as exc:
            self.failures += 1
            self.last_error = f"{type(exc).__name__}: {exc}"[:500]
            log.warning("publishing CSP reports failed: %s", self.last_error)
            raise IngestUnavailableError(
                "the report queue is unavailable", retry_after=self._retry_after
            ) from exc
        self.messages += 1
        self.published += len(pending.violations)

    async def close(self) -> None:
        await self._publisher.close()

    def status(self) -> dict[str, Any]:
        return {
            "mode": self.mode.value,
            "messages": self.messages,
            "published": self.published,
            "failures": self.failures,
            "last_error": self.last_error,
        }


# --- The consumer ---------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Record:
    partition: int
    offset: int
    value: bytes


# Called with the partitions a subscriber was just given; returns the next offset to read
# for each partition the database knows about.
PositionLoader = Callable[[str, Sequence[int]], Awaitable[dict[int, int]]]


class Subscriber(Protocol):
    topic: str

    async def start(self, positions: PositionLoader) -> None:
        """Join the group; seek every assigned partition to what ``positions`` returns."""

    async def fetch(self, max_records: int, timeout: float) -> list[Record]: ...

    async def commit(self, positions: dict[int, int]) -> None:
        """Tell the broker how far the group got (an optimization; the database decides)."""

    async def rewind(self, positions: PositionLoader) -> None:
        """Seek the assigned partitions back to what ``positions`` returns (after a batch
        failed to apply, so it is read again)."""

    async def close(self) -> None: ...


@dataclass(slots=True)
class ConsumeStats:
    batches: int = 0
    messages: int = 0
    duplicates: int = 0  # messages at offsets already applied
    poison: int = 0  # messages that weren't a pending batch (skipped)
    written: int = 0
    dropped: Counter[str] = field(default_factory=Counter)
    commit_failures: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "batches": self.batches,
            "messages": self.messages,
            "duplicates": self.duplicates,
            "poison": self.poison,
            "written": self.written,
            "dropped": dict(self.dropped),
            "commit_failures": self.commit_failures,
        }


def _insert(dialect: str) -> Any:
    return postgresql.insert if dialect == "postgresql" else sqlite.insert


class ReportConsumer:
    """Applies messages from a :class:`Subscriber` to the database, effectively once.

    For every batch it reads, in one transaction: lock the partitions' stored offsets,
    skip records below them (already applied), write the rest with ``write_batch``, and
    move the offsets past the batch. The broker commit afterwards only saves rereading; if
    it fails, or the process dies before it, the records come back and are skipped.
    """

    def __init__(
        self,
        subscriber: Subscriber,
        sessionmaker: async_sessionmaker[AsyncSession],
        *,
        group: str,
        max_groups: int,
        batch_size: int = 1_000,
    ) -> None:
        self._subscriber = subscriber
        self._sessionmaker = sessionmaker
        self.group = group
        self.max_groups = max_groups
        self.batch_size = batch_size
        self.stats = ConsumeStats()

    async def positions(self, topic: str, partitions: Sequence[int]) -> dict[int, int]:
        async with self._sessionmaker() as session:
            rows = await session.execute(
                select(IngestOffset.partition, IngestOffset.next_offset).where(
                    IngestOffset.consumer_group == self.group,
                    IngestOffset.topic == topic,
                    IngestOffset.partition.in_(list(partitions)),
                )
            )
            return {int(p): int(o) for p, o in rows}

    async def start(self) -> None:
        await self._subscriber.start(self.positions)

    async def close(self) -> None:
        await self._subscriber.close()

    async def run_once(self, timeout: float = 1.0) -> int:
        """Read and apply one batch; returns how many records it read."""
        records = await self._subscriber.fetch(self.batch_size, timeout)
        if not records:
            return 0
        topic = self._subscriber.topic
        partitions = sorted({r.partition for r in records})
        async with self._sessionmaker() as session, session.begin():
            # Make sure every partition has a row, then lock them: a second consumer that
            # briefly owns the same partition during a rebalance waits here, then sees the
            # offsets this one stored and skips what was already applied.
            await self._ensure(session, topic, partitions)
            stored = {
                int(row.partition): int(row.next_offset)
                for row in await session.scalars(
                    select(IngestOffset)
                    .where(
                        IngestOffset.consumer_group == self.group,
                        IngestOffset.topic == topic,
                        IngestOffset.partition.in_(partitions),
                    )
                    .with_for_update()
                )
            }
            batch: list[Pending] = []
            poison = duplicates = 0
            nxt: dict[int, int] = dict(stored)
            for record in records:
                if record.offset < stored.get(record.partition, 0):
                    duplicates += 1
                    continue
                nxt[record.partition] = max(nxt.get(record.partition, 0), record.offset + 1)
                try:
                    batch.append(decode(record.value))
                except MessageError as exc:
                    poison += 1
                    log.warning(
                        "skipping message %s/%d@%d: %s",
                        topic,
                        record.partition,
                        record.offset,
                        exc,
                    )
            result = await write_batch(session, batch, max_groups=self.max_groups)
            await self._store(session, topic, {p: o for p, o in nxt.items() if p in partitions})
        self.stats.batches += 1
        self.stats.messages += len(records)
        self.stats.duplicates += duplicates
        self.stats.poison += poison
        self.stats.written += result.accepted
        if result.over_limit:
            self.stats.dropped["group_limit"] += result.over_limit
        if result.site_gone:
            self.stats.dropped["site_gone"] += result.site_gone
        try:
            await self._subscriber.commit({p: nxt[p] for p in partitions if p in nxt})
        except Exception as exc:
            self.stats.commit_failures += 1
            log.warning("broker commit failed (the database has the offsets): %s", exc)
        return len(records)

    async def _ensure(self, session: AsyncSession, topic: str, partitions: list[int]) -> None:
        now = utcnow()
        stmt = _insert(session.get_bind().dialect.name)(IngestOffset.__table__).values(
            [
                {
                    "consumer_group": self.group,
                    "topic": topic,
                    "partition": partition,
                    "next_offset": 0,
                    "updated_at": now,
                }
                for partition in partitions
            ]
        )
        await session.execute(stmt.on_conflict_do_nothing())

    async def _store(self, session: AsyncSession, topic: str, offsets: dict[int, int]) -> None:
        now = utcnow()
        for partition, offset in sorted(offsets.items()):
            await session.execute(
                update(IngestOffset)
                .where(
                    IngestOffset.consumer_group == self.group,
                    IngestOffset.topic == topic,
                    IngestOffset.partition == partition,
                )
                .values(next_offset=offset, updated_at=now)
            )

    async def run(
        self,
        *,
        idle_exit: float | None = None,
        timeout: float = 1.0,
        stop: asyncio.Event | None = None,
    ) -> ConsumeStats:
        """Consume until ``stop`` is set, or until nothing arrived for ``idle_exit`` seconds.

        A batch that fails to apply is retried with backoff; its offsets weren't stored, so
        nothing is lost or counted twice.
        """
        loop = asyncio.get_running_loop()
        idle_since = loop.time()
        failures = 0
        while stop is None or not stop.is_set():
            try:
                read = await self.run_once(timeout)
            except Exception:
                failures += 1
                delay = min(30.0, 0.5 * 2 ** min(failures, 8))
                log.exception("applying a batch failed; retrying in %.1fs", delay)
                await self._rewind()
                await asyncio.sleep(delay)
                continue
            failures = 0
            if read:
                idle_since = loop.time()
            elif idle_exit is not None and loop.time() - idle_since >= idle_exit:
                break
        return self.stats

    async def _rewind(self) -> None:
        """After a failed batch, read again from what the database says was applied."""
        try:
            await self._subscriber.rewind(self.positions)
        except Exception:
            log.exception("could not rewind the subscriber")


# --- An in-memory broker --------------------------------------------------------------------------


class MemoryBroker:
    """A partitioned, in-memory log with committed offsets per consumer group: enough to
    test the consumer's offset handling (redelivery, failed commits, several partitions)
    without Kafka. Every subscriber reads every partition (no rebalancing)."""

    def __init__(self, topic: str = "sentinel.csp-reports", partitions: int = 3) -> None:
        if partitions < 1:
            raise ValueError("partitions must be at least 1")
        self.topic = topic
        self.logs: list[list[bytes]] = [[] for _ in range(partitions)]
        self.committed: dict[str, dict[int, int]] = {}  # group -> partition -> offset
        self.fail_publish: Exception | None = None
        self.fail_commit: Exception | None = None

    def partition_for(self, key: bytes) -> int:
        return zlib.crc32(key) % len(self.logs)

    def append(self, partition: int, value: bytes) -> int:
        self.logs[partition].append(value)
        return len(self.logs[partition]) - 1

    def publisher(self) -> MemoryPublisher:
        return MemoryPublisher(self)

    def subscriber(self, group: str = "script-sentinel") -> MemorySubscriber:
        return MemorySubscriber(self, group)


class MemoryPublisher:
    def __init__(self, broker: MemoryBroker) -> None:
        self.broker = broker

    async def start(self) -> None:
        pass

    async def publish(self, key: bytes, value: bytes) -> None:
        if self.broker.fail_publish is not None:
            raise self.broker.fail_publish
        self.broker.append(self.broker.partition_for(key), value)

    async def close(self) -> None:
        pass


class MemorySubscriber:
    def __init__(self, broker: MemoryBroker, group: str) -> None:
        self.broker = broker
        self.group = group
        self.topic = broker.topic
        self.position: dict[int, int] = {}

    async def start(self, positions: PositionLoader) -> None:
        await self.rewind(positions)

    async def rewind(self, positions: PositionLoader) -> None:
        partitions = list(range(len(self.broker.logs)))
        stored = await positions(self.topic, partitions)
        committed = self.broker.committed.get(self.group, {})
        self.position = {p: stored.get(p, committed.get(p, 0)) for p in partitions}

    async def fetch(self, max_records: int, timeout: float) -> list[Record]:
        records: list[Record] = []
        for partition, log_ in enumerate(self.broker.logs):
            start = self.position.get(partition, 0)
            for offset in range(start, len(log_)):
                if len(records) >= max_records:
                    return records
                records.append(Record(partition, offset, log_[offset]))
                self.position[partition] = offset + 1
        if not records and timeout > 0:
            await asyncio.sleep(min(timeout, 0.01))
        return records

    async def commit(self, positions: dict[int, int]) -> None:
        if self.broker.fail_commit is not None:
            raise self.broker.fail_commit
        self.broker.committed.setdefault(self.group, {}).update(positions)

    async def close(self) -> None:
        pass
