"""Send synthetic CSP violation reports to a running collector and time it.

    python examples/csp_load.py --url http://127.0.0.1:8080 --site shop \\
        --origin https://shop.example.com --requests 2000 --batch 20 --concurrency 32

Each request is a Reporting API batch of ``--batch`` reports about the site's own pages,
spread over ``--hosts`` blocked hosts on ``.test`` and a few directives, so the collector
folds them into a bounded number of groups. Prints one JSON line: how many requests and
reports were sent, the wall-clock time, and the responses by status code. Start the server
with a rate limit that won't get in the way, e.g. ``SENTINEL_CSP_REPORTS_PER_MINUTE=1000000
SENTINEL_CSP_BURST=1000000``, or the 429s are what you measure.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import time
from collections import Counter
from typing import Any

import httpx

DIRECTIVES = ("img-src", "connect-src", "script-src-elem")


def _batch(rng: random.Random, origin: str, size: int, hosts: int) -> list[dict[str, Any]]:
    return [
        {
            "type": "csp-violation",
            "age": rng.randrange(1000),
            "url": f"{origin}/p{rng.randrange(20)}",
            "body": {
                "documentURL": f"{origin}/p{rng.randrange(20)}?session={rng.randrange(10**6)}",
                "effectiveDirective": rng.choice(DIRECTIVES),
                "blockedURL": f"https://px{rng.randrange(hosts)}.load.test/c?id={rng.random()}",
                "disposition": rng.choice(("enforce", "report")),
                "statusCode": 200,
            },
        }
        for _ in range(size)
    ]


async def run(
    url: str,
    site: str,
    origin: str,
    *,
    requests: int,
    batch: int,
    concurrency: int,
    hosts: int,
    seed: int = 7,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    rng = random.Random(seed)
    bodies = [json.dumps(_batch(rng, origin, batch, hosts)).encode() for _ in range(requests)]
    statuses: Counter[int] = Counter()
    queue: asyncio.Queue[bytes] = asyncio.Queue()
    for body in bodies:
        queue.put_nowait(body)
    endpoint = f"{url.rstrip('/')}/v1/reports/csp/{site}"
    headers = {"content-type": "application/reports+json"}

    async with httpx.AsyncClient(timeout=30, transport=transport) as client:

        async def worker() -> None:
            while not queue.empty():
                body = queue.get_nowait()
                response = await client.post(endpoint, content=body, headers=headers)
                statuses[response.status_code] += 1

        started = time.perf_counter()
        await asyncio.gather(*(worker() for _ in range(concurrency)))
        elapsed = time.perf_counter() - started
    return {
        "requests": requests,
        "reports": requests * batch,
        "seconds": round(elapsed, 3),
        "reports_per_second": round(requests * batch / elapsed),
        "status": {str(code): n for code, n in sorted(statuses.items())},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument("--site", default="shop")
    parser.add_argument("--origin", default="https://shop.example.com")
    parser.add_argument("--requests", type=int, default=1000)
    parser.add_argument("--batch", type=int, default=20)
    parser.add_argument("--concurrency", type=int, default=32)
    parser.add_argument("--hosts", type=int, default=50)
    args = parser.parse_args()
    result = asyncio.run(
        run(
            args.url,
            args.site,
            args.origin,
            requests=args.requests,
            batch=args.batch,
            concurrency=args.concurrency,
            hosts=args.hosts,
        )
    )
    print(json.dumps(result))


if __name__ == "__main__":
    main()
