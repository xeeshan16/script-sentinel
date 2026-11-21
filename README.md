# script-sentinel

[![CI](https://github.com/xeeshan16/script-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/xeeshan16/script-sentinel/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.12%20%7C%203.13-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**Self-hosted integrity monitoring for the third-party scripts your pages load.**

A tag manager, an A/B testing snippet or a chat widget can change on the vendor's CDN with no
deploy on your side, and nothing tells you. When that vendor is compromised, the attacker's
code runs on your checkout page with your users' trust. script-sentinel keeps an inventory of
every script your pages load, pins what each one should look like, and tells you when one
changes and whether the change looks like a skimmer.

> **Status: in active development (day 1 of 14).** The data model, site and page registry,
> scan allowlist, API, CLI and CI are in place. The scanner lands on day 2. See
> [docs/PLAN.md](docs/PLAN.md) for the roadmap and [docs/PROGRESS.md](docs/PROGRESS.md) for
> the daily log.

## Why

- **Supply-chain attacks through scripts are routine.** Magecart-style skimmers, crypto
  wallet-address swaps and injected tag-manager code all arrive from a CDN you already trust.
  Only monitoring the scripts themselves, or a strict Content Security Policy, catches them.
- **PCI DSS 4.0 made it mandatory.** Requirement 6.4.3 asks for an inventory of every script
  on payment pages, each authorized with a written justification and integrity-checked.
  Requirement 11.6.1 asks for tamper detection on those pages at least once every 7 days.
  The tools that cover this are mostly commercial SaaS.
- **CSP reports are noisy.** Violation reports arrive in two formats, in bursts, mostly as
  duplicates. They are useful only once deduplicated and aggregated.

## Features

| Area | What it does | Status |
| --- | --- | --- |
| Registry | Sites with an explicit origin allowlist and a scan interval (≤ 7 days); pages marked as payment pages are in PCI scope | ✅ day 1 |
| Allowlist | Browser-style origin normalization (case, IDNA, default ports, IPv6), exact matching, credentials in URLs refused | ✅ day 1 |
| Inventory | Every inline and external script per page, with `integrity`, `nonce` and `type` | day 2 |
| Pinning | SHA-384 version history per script, SRI hash generation, security-header snapshots | day 3 |
| Authorization (6.4.3) | Approve or justify each script; pinned hashes, allowlisted origins, "expected to change" vendors; audit trail | day 4 |
| Change review | JS-aware tokenized diff, size and entropy deltas, newly referenced domains | day 5 |
| Skimmer heuristics | New exfiltration sinks, card-field listeners, wallet-address swaps, obfuscation, script injection | day 6 |
| CSP reports | `report-uri` and Reporting API collector with dedupe, rate limits, batch ingest and optional Kafka | days 7–8 |
| CSP builder | Policy suggestions from the approved inventory and observed reports | day 9 |
| Worker and alerts | Scheduled scans, advisory locks, transactional outbox, HMAC-signed webhooks | day 10 |
| Dynamic scripts | Optional headless-browser renderer for runtime-injected scripts | day 11 |
| Evidence | 6.4.3 / 11.6.1-style exports in JSON and Markdown; optional LLM diff explainer with a deterministic fake | day 12 |

## Architecture

```mermaid
flowchart LR
    subgraph API["FastAPI service"]
        sites["/v1/sites<br/>registry + allowlist"]
        csp["CSP report collector<br/>(day 7)"]
    end
    worker["Scan worker<br/>(day 10)"] --> scanner["Scanner<br/>fetch → parse → hash"]
    scanner --> store[("PostgreSQL<br/>sites · pages · scripts<br/>versions · findings")]
    scanner --> policy["Policy engine<br/>approved · pinned · changed"]
    policy --> diff["Diff + heuristics"]
    diff --> findings["Findings"] --> outbox["Outbox"] --> hooks["Signed webhooks"]
    sites --> store
    csp --> ingest["Buffered ingest<br/>(memory or Kafka)"] --> store
```

The data model today:

```mermaid
erDiagram
    SITE ||--o{ PAGE : has
    SITE ||--o{ SCRIPT : inventories
    SCRIPT ||--o{ SCRIPT_VERSION : "served bodies"
    SITE ||--o{ FINDING : raises
    SCRIPT |o--o{ FINDING : about
    SITE {
        uuid id
        string name
        json allowed_origins
        int scan_interval_hours "1..168"
    }
    PAGE {
        string url "on an allowed origin"
        bool payment_page
    }
    SCRIPT {
        enum kind "external | inline"
        string locator "src URL, or page + position"
        enum status "pending | approved | rejected"
        text justification
    }
    SCRIPT_VERSION {
        string sha384 "unique per script"
        string normalized_sha384
        int size_bytes
    }
    FINDING {
        string kind
        enum severity
        enum status "open | acknowledged | resolved"
        json detail
    }
```

Design notes:

- **Only listed origins are scanned.** A page can't be registered unless its origin is on the
  site's allowlist, and an origin can't be removed while pages use it.
- **A changed script is a new version, not a new script.** Scripts are identified by a locator
  within their site, so history and approvals follow the script across body changes.
- **Findings outlive the scripts they're about.** Deleting a script sets the reference on its
  findings to `NULL` instead of deleting them; they are audit evidence.
- **Portable schema.** Enums are `VARCHAR` + `CHECK`, JSON is `JSONB` on PostgreSQL, and
  timestamps are timezone-aware UTC on both PostgreSQL and SQLite. A test asserts the ORM
  models and the hand-written migrations match.

## Quick start

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/). PostgreSQL 16 for real use;
SQLite works for trying it out.

```bash
git clone https://github.com/xeeshan16/script-sentinel.git
cd script-sentinel
uv sync

# PostgreSQL (or: export SENTINEL_DATABASE_URL=sqlite+aiosqlite:///sentinel.db)
export SENTINEL_DATABASE_URL=postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel
uv run sentinel db upgrade      # prints: database upgraded to head
```

Register a site, the origins its pages may be fetched from, and the pages to scan:

```console
$ uv run sentinel sites add shop --origin https://shop.example.com --origin http://localhost:8000
added site shop: http://localhost:8000, https://shop.example.com (scan every 168h)
$ uv run sentinel pages add shop https://shop.example.com/checkout --payment --label checkout
added page https://shop.example.com/checkout (payment page)
$ uv run sentinel pages add shop https://cdn.vendor.test/
error: https://cdn.vendor.test/ is not on an allowed origin of site 'shop' (http://localhost:8000, https://shop.example.com)
$ uv run sentinel sites list
shop                 pages=1    payment=1    every 168h  http://localhost:8000, https://shop.example.com
```

Or run the API (interactive docs at `http://127.0.0.1:8080/docs`):

```console
$ uv run sentinel serve --port 8080
$ curl -s -X POST localhost:8080/v1/sites -H 'content-type: application/json' \
    -d '{"name":"blog","allowed_origins":["https://Blog.Example.com:443/"],"scan_interval_hours":24}'
{
    "id": "98244174-12d9-4262-a0f9-2611ff60a33f",
    "name": "blog",
    "allowed_origins": [
        "https://blog.example.com"
    ],
    "scan_interval_hours": 24,
    "page_count": 0,
    "payment_page_count": 0,
    "created_at": "2026-11-21T09:59:34.947249Z",
    "updated_at": "2026-11-21T09:59:34.947257Z"
}
$ curl -s -X POST localhost:8080/v1/sites/blog/pages -H 'content-type: application/json' \
    -d '{"url":"https://evil.test/"}'
{"detail":"https://evil.test/ is not on an allowed origin of site 'blog' (https://blog.example.com)"}
```

(Output above is from a real run against PostgreSQL 16; the JSON was pretty-printed.)

## API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/healthz` | Liveness |
| `GET` | `/readyz` | Readiness (database ping); `503` when the database is unreachable |
| `POST` | `/v1/sites` | Register a site (`name`, `allowed_origins`, optional `scan_interval_hours`) |
| `GET` | `/v1/sites` | List sites with page counts |
| `GET` | `/v1/sites/{name}` | One site |
| `PATCH` | `/v1/sites/{name}` | Change origins or interval (`409` if a page would fall off the allowlist) |
| `DELETE` | `/v1/sites/{name}` | Delete a site and everything recorded for it |
| `POST` | `/v1/sites/{name}/pages` | Register a page (`422` if it's off the allowlist) |
| `GET` | `/v1/sites/{name}/pages` | List pages |
| `DELETE` | `/v1/sites/{name}/pages?url=…` | Stop scanning a page |

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `SENTINEL_DATABASE_URL` | `postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel` | SQLAlchemy async URL (`postgresql+asyncpg://…` or `sqlite+aiosqlite:///…`) |
| `SENTINEL_DEFAULT_SCAN_INTERVAL_HOURS` | `168` | Interval for sites that don't set one (1–168) |
| `SENTINEL_LOG_LEVEL` | `info` | `debug`, `info`, `warning` or `error` |

The default URL's credentials are local-development placeholders; set your own in production.

## Development

```bash
uv sync
uv run ruff check . && uv run ruff format --check .
uv run mypy
uv run pytest --cov

# Also run the suite against PostgreSQL:
export SENTINEL_TEST_DATABASE_URL=postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel
uv run pytest
```

CI runs the same checks on Python 3.12 and 3.13 against SQLite and PostgreSQL 16, builds the
package, and smoke-tests the CLI and API against PostgreSQL.

## Project layout

```
src/script_sentinel/
  app.py            FastAPI app factory, health checks, error mapping
  api/              REST routers and schemas
  cli.py            `sentinel` command line
  config.py         SENTINEL_* settings
  db/               engine, models, migration runner
  migrations/       Alembic environment and versions
  origins.py        origin parsing, normalization and allowlist matching
  sites.py          site and page registry with allowlist invariants
tests/              pytest suite (SQLite always, PostgreSQL when configured)
docs/               PLAN.md and PROGRESS.md
```

## License

[MIT](LICENSE) © 2026 Zeeshan Imdad
