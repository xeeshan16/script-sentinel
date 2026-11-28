"""Kafka adapters for the report queue, built on aiokafka (``pip install
'script-sentinel[kafka]'``).

The producer waits for every in-sync replica (``acks="all"``) with idempotence on, so a
``202`` from the collector in kafka mode means the reports are on the broker. The
consumer never lets the broker decide where to start: on every partition assignment it
seeks to the offsets the database says were applied (see ``ingest.ReportConsumer``), and
falls back to the earliest offset for a partition the database has never seen.
"""

from __future__ import annotations

import asyncio
import importlib
from collections.abc import Sequence
from typing import Any

from script_sentinel.ingest import PositionLoader, Record


class KafkaUnavailableError(RuntimeError):
    """aiokafka isn't installed."""


def _aiokafka() -> Any:
    try:
        return importlib.import_module("aiokafka")
    except ImportError as exc:  # pragma: no cover - the dev environment has it
        raise KafkaUnavailableError(
            "kafka mode needs aiokafka: pip install 'script-sentinel[kafka]'"
        ) from exc


class AioKafkaPublisher:
    def __init__(
        self,
        bootstrap_servers: str,
        topic: str,
        *,
        client_id: str = "script-sentinel",
        send_timeout: float = 5.0,
        linger_ms: int = 5,
    ) -> None:
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.client_id = client_id
        self.send_timeout = send_timeout
        self.linger_ms = linger_ms
        self._producer: Any = None

    async def start(self) -> None:
        lib = _aiokafka()
        self._producer = lib.AIOKafkaProducer(
            bootstrap_servers=self.bootstrap_servers,
            client_id=self.client_id,
            acks="all",
            enable_idempotence=True,
            linger_ms=self.linger_ms,
            request_timeout_ms=max(1000, int(self.send_timeout * 1000)),
        )
        await self._producer.start()

    async def publish(self, key: bytes, value: bytes) -> None:
        if self._producer is None:
            raise RuntimeError("the publisher isn't started")
        await asyncio.wait_for(
            self._producer.send_and_wait(self.topic, value, key=key), self.send_timeout
        )

    async def close(self) -> None:
        if self._producer is not None:
            await self._producer.stop()
            self._producer = None


class AioKafkaSubscriber:
    def __init__(
        self,
        bootstrap_servers: str,
        topic: str,
        *,
        group_id: str,
        client_id: str = "script-sentinel",
    ) -> None:
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.group_id = group_id
        self.client_id = client_id
        self._consumer: Any = None
        self._lib: Any = None

    async def start(self, positions: PositionLoader) -> None:
        lib = self._lib = _aiokafka()
        self._consumer = lib.AIOKafkaConsumer(
            bootstrap_servers=self.bootstrap_servers,
            group_id=self.group_id,
            client_id=self.client_id,
            enable_auto_commit=False,
            auto_offset_reset="earliest",
            isolation_level="read_committed",
        )
        subscriber = self
        base: Any = lib.ConsumerRebalanceListener

        class Listener(base):  # type: ignore[misc]
            async def on_partitions_revoked(self, revoked: Any) -> None:
                pass

            async def on_partitions_assigned(self, assigned: Any) -> None:
                await subscriber._seek([tp.partition for tp in assigned], positions)

        self._consumer.subscribe([self.topic], listener=Listener())
        await self._consumer.start()

    async def _seek(self, partitions: Sequence[int], positions: PositionLoader) -> None:
        stored = await positions(self.topic, partitions)
        for partition, offset in stored.items():
            self._consumer.seek(self._lib.TopicPartition(self.topic, partition), offset)

    async def fetch(self, max_records: int, timeout: float) -> list[Record]:
        data = await self._consumer.getmany(timeout_ms=int(timeout * 1000), max_records=max_records)
        records = [
            Record(tp.partition, message.offset, message.value or b"")
            for tp, messages in data.items()
            for message in messages
        ]
        records.sort(key=lambda r: (r.partition, r.offset))
        return records

    async def commit(self, positions: dict[int, int]) -> None:
        await self._consumer.commit(
            {self._lib.TopicPartition(self.topic, p): o for p, o in positions.items()}
        )

    async def rewind(self, positions: PositionLoader) -> None:
        assigned = [tp.partition for tp in self._consumer.assignment()]
        if assigned:
            await self._seek(assigned, positions)

    async def close(self) -> None:
        if self._consumer is not None:
            await self._consumer.stop()
            self._consumer = None
