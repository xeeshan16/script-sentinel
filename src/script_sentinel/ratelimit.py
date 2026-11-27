"""A keyed token bucket for the CSP report collector.

Each key (a site) gets a bucket holding up to ``burst`` tokens that refills at ``rate``
tokens per second. A request costs one token per report it carries, so a browser's
batched Reporting API delivery is charged for what it actually sends.

The buckets live in the process: with several API replicas each one enforces the limit
on its own share of the traffic. That bounds what one replica stores and is enough to
stop a single noisy page from drowning the collector; a shared limit needs a shared
store and is not worth one yet.
"""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(slots=True)
class _Bucket:
    tokens: float
    updated: float


class RateLimiter:
    def __init__(
        self, rate: float, burst: int, *, clock: Callable[[], float] = time.monotonic
    ) -> None:
        if rate <= 0 or burst < 1:
            raise ValueError("rate must be positive and burst at least 1")
        self.rate = rate
        self.burst = burst
        self._clock = clock
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def acquire(self, key: str, cost: int = 1) -> float:
        """Take ``cost`` tokens from ``key``'s bucket.

        Returns 0.0 when they were taken, otherwise the seconds until the bucket will hold
        enough (and takes nothing). A cost above ``burst`` is charged as ``burst``, so a
        request is never refused forever.
        """
        cost = max(1, min(cost, self.burst))
        with self._lock:
            now = self._clock()
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = self._buckets[key] = _Bucket(float(self.burst), now)
            else:
                elapsed = max(0.0, now - bucket.updated)
                bucket.tokens = min(float(self.burst), bucket.tokens + elapsed * self.rate)
                bucket.updated = now
            if bucket.tokens >= cost:
                bucket.tokens -= cost
                return 0.0
            return (cost - bucket.tokens) / self.rate


def retry_after(seconds: float) -> str:
    """A ``Retry-After`` header value: whole seconds, at least 1."""
    return str(max(1, math.ceil(seconds)))
