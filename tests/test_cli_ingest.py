from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from script_sentinel import cli, sites
from script_sentinel.cli import _sparkline, app
from script_sentinel.config import Settings
from script_sentinel.db import make_engine, make_sessionmaker
from script_sentinel.db.models import utcnow
from script_sentinel.ingest import MemoryBroker, encode
from script_sentinel.violations import Pending
from tests.test_rollups import INLINE, _v

runner = CliRunner()
EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "csp-reports"
LEGACY = str(EXAMPLES / "report-uri.json")
BATCH = str(EXAMPLES / "reporting-api.json")


def _invoke(*args: str, env: dict[str, str] | None = None) -> tuple[int, str]:
    result = runner.invoke(app, list(args), env=env)
    return result.exit_code, result.output


@pytest.fixture
def url(sqlite_url: str) -> list[str]:
    url = ["--url", sqlite_url]
    assert _invoke("sites", "add", "shop", "-o", "https://shop.example.com", *url)[0] == 0
    return url


def test_sparkline() -> None:
    assert _sparkline([]) == ""
    assert _sparkline([0, 0]) == "··"
    assert _sparkline([0, 1, 4, 8]) == "·▁▄█"


def test_rollups_text_and_json(url: list[str]) -> None:
    code, out = _invoke("csp", "rollups", "shop", *url)
    assert code == 0, out
    assert out.startswith("shop: 0 reports in the last 24h (the 24h before: 0)\n")
    assert "count" not in out  # no table without rows
    _invoke("csp", "ingest", "shop", LEGACY, *url)
    _invoke("csp", "ingest", "shop", BATCH, *url)
    code, out = _invoke("csp", "rollups", "shop", *url)
    assert code == 0, out
    lines = out.splitlines()
    assert lines[0] == "shop: 4 reports in the last 24h (the 24h before: 0)"
    assert lines[1].startswith("  " + "·" * 23 + "█  ")
    assert lines[2].split() == ["count", "before", "directive", "blocked"]
    assert lines[3].split() == ["2", "0", "connect-src", "collect.skim.test", "NEW"]
    assert lines[5].split() == ["1", "0", "script-src-elem", "inline", "NEW"]
    code, out = _invoke("csp", "rollups", "shop", "--by", "blocked", "--hours", "2", *url)
    assert out.splitlines()[2].split() == ["count", "before", "blocked"]
    assert out.splitlines()[3].split() == ["3", "0", "collect.skim.test", "NEW"]
    code, out = _invoke("csp", "rollups", "shop", "--by", "directive", "--limit", "1", *url)
    assert out.splitlines()[3].split() == ["2", "0", "connect-src", "NEW"]
    code, out = _invoke(
        "csp", "rollups", "shop", "--disposition", "report", "--directive", "script-src-elem",
        "--json", *url,
    )  # fmt: skip
    data = json.loads(out)
    assert (data["total"], len(data["buckets"]), data["rows"][0]["blocked"]) == (
        1,
        24,
        "collect.skim.test",
    )


def test_rollups_unknown_site(url: list[str]) -> None:
    assert _invoke("csp", "rollups", "nope", *url)[0] == 1


def test_prune(url: list[str]) -> None:
    _invoke("csp", "ingest", "shop", LEGACY, *url)
    assert _invoke("csp", "prune", *url) == (
        0,
        "deleted 0 rollup buckets older than 62 days\n",
    )
    # Keeping one day still keeps this hour.
    assert _invoke("csp", "prune", "--days", "1", *url)[1].startswith("deleted 0 ")
    assert _invoke("csp", "rollups", "shop", "--json", *url)[1].count('"count": 1') >= 1


def test_consume_needs_a_broker(url: list[str]) -> None:
    code, out = _invoke("csp", "consume", "--idle-exit", "0", *url)
    assert code == 2
    assert "SENTINEL_KAFKA_BOOTSTRAP_SERVERS" in out


async def _site_id(database_url: str) -> uuid.UUID:
    engine = make_engine(database_url)
    try:
        async with make_sessionmaker(engine)() as session:
            return (await sites.get_site(session, "shop")).id
    finally:
        await engine.dispose()


def test_consume_applies_what_is_on_the_topic(
    url: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    site_id = asyncio.run(_site_id(url[1]))
    broker = MemoryBroker(partitions=2)
    key = site_id
    for pending in (
        Pending(key, utcnow(), [_v(), _v(), INLINE]),
        Pending(uuid.uuid4(), utcnow(), [_v()]),
    ):
        broker.append(broker.partition_for(pending.site_id.bytes), encode(pending))
    broker.append(0, b"junk")
    seen: list[Settings] = []

    def subscriber(settings: Settings) -> Any:
        seen.append(settings)
        return broker.subscriber(settings.kafka_consumer_group)

    monkeypatch.setattr(cli, "_subscriber", subscriber)
    env = {"SENTINEL_KAFKA_BOOTSTRAP_SERVERS": "localhost:9092"}
    code, out = _invoke("csp", "consume", "--idle-exit", "0.05", *url, env=env)
    assert code == 0, out
    assert out == (
        "3 messages in 1 batches: 3 reports written, 0 duplicates skipped, 1 unreadable, "
        "dropped: site_gone 1\n"
    )
    assert seen[0].kafka_bootstrap_servers == "localhost:9092"
    # Running again reads nothing new: the offsets are in the database.
    code, out = _invoke("csp", "consume", "--idle-exit", "0.05", "--json", *url, env=env)
    assert json.loads(out)["messages"] == 0
    code, out = _invoke("csp", "violations", "shop", "--json", *url)
    assert json.loads(out)["total_reports"] == 3
