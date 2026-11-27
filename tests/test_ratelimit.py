from __future__ import annotations

import pytest

from script_sentinel.ratelimit import RateLimiter, retry_after


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_a_bucket_starts_full_and_refills_at_the_rate() -> None:
    clock = Clock()
    limiter = RateLimiter(rate=2.0, burst=4, clock=clock)
    assert [limiter.acquire("shop") for _ in range(4)] == [0.0] * 4
    assert limiter.acquire("shop") == pytest.approx(0.5)
    clock.now += 0.5
    assert limiter.acquire("shop") == 0.0
    assert limiter.acquire("shop") == pytest.approx(0.5)


def test_refills_never_exceed_the_burst() -> None:
    clock = Clock()
    limiter = RateLimiter(rate=10.0, burst=3, clock=clock)
    limiter.acquire("shop", 3)
    clock.now += 3600
    assert limiter.acquire("shop", 3) == 0.0
    assert limiter.acquire("shop") == pytest.approx(0.1)


def test_a_refused_request_takes_nothing() -> None:
    clock = Clock()
    limiter = RateLimiter(rate=1.0, burst=5, clock=clock)
    limiter.acquire("shop", 3)
    assert limiter.acquire("shop", 3) == pytest.approx(1.0)
    assert limiter.acquire("shop", 2) == 0.0


def test_costs_are_clamped_and_keys_are_independent() -> None:
    clock = Clock()
    limiter = RateLimiter(rate=1.0, burst=5, clock=clock)
    assert limiter.acquire("shop", 50) == 0.0  # charged as the whole burst
    assert limiter.acquire("shop", 0) == pytest.approx(1.0)  # charged as one
    assert limiter.acquire("blog", 5) == 0.0


def test_a_clock_going_backwards_refills_nothing() -> None:
    clock = Clock()
    limiter = RateLimiter(rate=1.0, burst=1, clock=clock)
    limiter.acquire("shop")
    clock.now -= 100
    assert limiter.acquire("shop") == pytest.approx(1.0)


@pytest.mark.parametrize(("rate", "burst"), [(0.0, 1), (-1.0, 1), (1.0, 0)])
def test_invalid_limits(rate: float, burst: int) -> None:
    with pytest.raises(ValueError, match="rate"):
        RateLimiter(rate=rate, burst=burst)


@pytest.mark.parametrize(("seconds", "header"), [(0.01, "1"), (1.0, "1"), (1.2, "2"), (30, "30")])
def test_retry_after(seconds: float, header: str) -> None:
    assert retry_after(seconds) == header
