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

> **Status: in active development (day 3 of 14).** Scans fetch your pages, inventory every
> script they load, download and hash every script body, keep a version history per script,
> check `integrity` attributes the way a browser does, and snapshot each page's security
> headers. The approve-and-justify workflow (PCI DSS 6.4.3) lands on day 4. See
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
| Scanner | Fetches registered pages with timeouts, size caps, allowlist-checked redirects and RFC 9309 `robots.txt` handling; keeps a snapshot of every scan | ✅ day 2 |
| Inventory | Every script a browser would run, per page and in order: inline, external, module, import map, SVG and `data:` scripts, with `integrity`, `nonce`, `crossorigin` and `type` | ✅ day 2 |
| Versions | Every body (inline or external) hashed with SHA-384 over the exact bytes and over a comment- and whitespace-insensitive JS token stream; a version history per script, so a vendor change is a new version of the same script | ✅ day 3 |
| Integrity | `integrity` attributes checked the way browsers do (strongest algorithm wins); SRI values to pin each body; CSP hash sources for inline code; a warning for SRI on a cross-origin script without `crossorigin` | ✅ day 3 |
| Headers (11.6.1) | CSP, CSP-Report-Only, Integrity-Policy, HSTS, `X-Content-Type-Options` and other security headers, plus `<meta>` CSPs, snapshotted per page per scan | ✅ day 3 |
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
    scans["/v1/sites/{name}/scans"] --> scanner
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
    SITE ||--o{ SCAN : "is scanned"
    SCAN ||--o{ PAGE_SNAPSHOT : records
    PAGE |o--o{ PAGE_SNAPSHOT : "snapshots of"
    PAGE_SNAPSHOT ||--o{ SCRIPT_OBSERVATION : saw
    SCRIPT ||--o{ SCRIPT_OBSERVATION : "observed as"
    SCRIPT_VERSION |o--o{ SCRIPT_OBSERVATION : "body seen"
    SCAN ||--o{ SCRIPT_FETCH : downloads
    SCRIPT ||--o{ SCRIPT_FETCH : "fetched as"
    SCRIPT_VERSION |o--o{ SCRIPT_FETCH : got
    SITE {
        uuid id
        string name
        json allowed_origins
        int scan_interval_hours "1..168"
        bool respect_robots
    }
    SCAN {
        enum status "running | completed | partial | failed"
        enum trigger "cli | api | schedule"
        int pages_ok
        int pages_skipped
        int pages_failed
        int scripts_new
        int scripts_changed
    }
    PAGE_SNAPSHOT {
        enum outcome "ok | robots_disallowed | http_error | ..."
        string final_url
        string body_sha384
        json warnings
        json security_headers
        json meta_csp
    }
    SCRIPT_OBSERVATION {
        int position
        enum script_type "classic | module | importmap"
        string integrity
        string nonce_digest "never the nonce itself"
        string inline_sha384
        enum sri_status "match | mismatch | no_supported_hash | unverified"
    }
    SCRIPT_FETCH {
        enum outcome "ok | http_error | too_large | ..."
        int http_status
        string final_url
        bool new_version
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
        text content
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
- **The scanner stays on the allowlist.** Redirects are followed by hand and every hop must
  be on an allowed origin; a page that redirects elsewhere is reported as `redirect_blocked`.
  Third-party script URLs are fetched only as scripts, never as pages.
- **No half-parsed pages.** A page over `SENTINEL_MAX_PAGE_BYTES` is reported as `too_large`
  instead of being parsed up to the cut, which would silently hide the scripts after it.
- **robots.txt per RFC 9309,** including wildcards and longest-match precedence (which
  Python's `urllib.robotparser` lacks): 4xx means no rules, 5xx or unreachable means
  disallow everything. Checkout pages are often disallowed for crawlers, so a site can opt
  out for its own pages with `--ignore-robots`; a robots refusal counts as skipped, not
  failed, and the CLI warns when it kept a payment page out of a scan.
- **What a browser would run, not every `<script>` tag.** Script types follow the HTML
  standard (`application/ld+json` and other data blocks never run; import maps are kept
  because they control where modules load from), `<base href>` changes resolution, scripts in
  `<template>` and `<noscript>` are skipped, SVG scripts are read from `href`, and `data:`
  URLs are treated as inline code. Anything that can't be inventoried becomes a warning on
  the snapshot instead of disappearing.
- **No database transaction is held across the network.** A scan fetches first, then writes
  the scan, its snapshots and the inventory in one go.
- **Two hashes per body.** `sha384` covers the exact bytes (what Subresource Integrity
  checks). `normalized_sha384` covers the body's JavaScript tokens with comments dropped and
  whitespace collapsed (line breaks kept, because automatic semicolon insertion makes them
  meaningful), so a rebuild that only changed a banner comment or `sourceMappingURL` can be
  told apart from a change in the code. The tokenizer handles strings, template literals
  with nested substitutions, regex-versus-division and unterminated input, and is the base
  for day 5's token diff.
- **Integrity checked like a browser.** Only the strongest algorithm in an `integrity`
  attribute counts (`sha256-<good> sha384-<bad>` fails), unusable values mean the script
  runs unchecked (reported as `no_supported_hash`), and digests are compared exactly. SRI
  on a cross-origin script without `crossorigin` is flagged, because browsers refuse to run
  it.
- **Script bodies are fetched once per scan, off the event loop.** Every external script
  the pages reference is downloaded once (redirects to any http(s) URL are followed, as a
  browser would; robots.txt doesn't apply to subresources), capped at
  `SENTINEL_MAX_SCRIPT_BYTES`, and hashed in a worker thread.
- **Stored third-party code never runs on the sentinel's origin.** Version bodies are served
  as `text/plain` with `nosniff` and a sandboxing CSP.
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

### Scan a site

[`examples/`](examples) holds a small synthetic shop and the "third-party" CDN it loads
scripts from, on two local origins. The shop's `robots.txt` disallows `/checkout`, as many
real shops do. Serve both and register the shop:

```bash
python examples/serve.py &    # shop on 127.0.0.1:8000, CDN on 127.0.0.1:8001
uv run sentinel sites add demo --origin http://127.0.0.1:8000
uv run sentinel pages add demo http://127.0.0.1:8000/index.html --label home
uv run sentinel pages add demo http://127.0.0.1:8000/checkout.html --payment --label checkout
```

```console
$ uv run sentinel scan run demo
scan 8d81462d-7f10-4b4e-bd33-9a1654a374bf of demo: completed in 0.04s (2 pages: 1 ok, 1 skipped)
  robots   http://127.0.0.1:8000/checkout.html [payment]  disallowed by robots.txt (parsed)
  ok       http://127.0.0.1:8000/index.html  200  3 scripts (3 new)
      headers: nosniff, Referrer-Policy
      + http://127.0.0.1:8000/js/app.js  (classic)  sha384-oaeGFW/oKjuWczG…
      + http://127.0.0.1:8001/analytics/v2/tag.js  (classic)  sha384-raygKpbLnYdKgM3…
      + http://127.0.0.1:8000/index.html#inline-1  (classic)  sha384-uSDeh2gpqss7OOr…
inventory: 3 scripts seen, 3 new (pending approval)
bodies: 2 external fetched, 0 failed; 3 new versions, 0 scripts changed
warning: robots.txt kept payment pages out of this scan; if they are your own pages, run: sentinel sites update demo --ignore-robots
$ uv run sentinel sites update demo --ignore-robots
updated site demo: scan every 168h, robots.txt ignored
$ uv run sentinel scan run demo
scan 2167fba1-1378-4aa3-aa2c-0cd23cdf758a of demo: completed in 0.04s (2 pages: 2 ok)
  ok       http://127.0.0.1:8000/checkout.html [payment]  200  6 scripts (4 new)
      headers: CSP report-only, nosniff, Referrer-Policy
      + http://127.0.0.1:8000/checkout.html#inline-1  (classic, nonce)  sha384-lXDOInm1aF5PqqU…
      + http://127.0.0.1:8000/checkout.html#inline-2  (importmap)  sha384-RK3hVJoVsFjKTgJ…
        http://127.0.0.1:8000/js/app.js  (classic)  sha384-oaeGFW/oKjuWczG…
        http://127.0.0.1:8001/analytics/v2/tag.js  (classic)  sha384-raygKpbLnYdKgM3…
      + http://127.0.0.1:8001/payments/v3/elements.js  (classic, integrity ok)  sha384-i+C8D+bUmsEtpaC…
      + http://127.0.0.1:8000/js/checkout.mjs  (module)  sha384-V9XBxb1rMJcHI5I…
  ok       http://127.0.0.1:8000/index.html  200  3 scripts
      headers: nosniff, Referrer-Policy
        http://127.0.0.1:8000/js/app.js  (classic)  sha384-oaeGFW/oKjuWczG…
        http://127.0.0.1:8001/analytics/v2/tag.js  (classic)  sha384-raygKpbLnYdKgM3…
        http://127.0.0.1:8000/index.html#inline-1  (classic)  sha384-uSDeh2gpqss7OOr…
inventory: 7 scripts seen, 4 new (pending approval)
bodies: 4 external fetched, 0 failed; 4 new versions, 0 scripts changed
$ uv run sentinel scripts list demo
pending   external  v1   sha384-oaeGFW/oKjuWczG…   http://127.0.0.1:8000/js/app.js
pending   external  v1   sha384-V9XBxb1rMJcHI5I…   http://127.0.0.1:8000/js/checkout.mjs
pending   external  v1   sha384-raygKpbLnYdKgM3…   http://127.0.0.1:8001/analytics/v2/tag.js
pending   external  v1   sha384-i+C8D+bUmsEtpaC…   http://127.0.0.1:8001/payments/v3/elements.js
pending   inline    v1   sha384-lXDOInm1aF5PqqU…   http://127.0.0.1:8000/checkout.html#inline-1
pending   inline    v1   sha384-RK3hVJoVsFjKTgJ…   http://127.0.0.1:8000/checkout.html#inline-2
pending   inline    v1   sha384-uSDeh2gpqss7OOr…   http://127.0.0.1:8000/index.html#inline-1
```

`+` marks a script seen for the first time. Every new script starts as `pending`: under PCI
DSS 6.4.3 it needs an authorization and a written justification (day 4). The checkout page
pins the payments library with SRI, and the scan confirms a browser would accept the body
it got (`integrity ok`). The JSON `application/ld+json` block on the checkout page is
counted but not inventoried, because it never runs.

Now play the vendor: the analytics tag on the CDN changes, with no deploy on the shop's side.

```console
$ echo 'queue.push(["ping"]);' >> examples/fixture-cdn/analytics/v2/tag.js
$ uv run sentinel scan run demo
scan 869bc596-a6ee-421e-9c18-7d7978d7c132 of demo: completed in 0.04s (2 pages: 2 ok)
  ok       http://127.0.0.1:8000/checkout.html [payment]  200  6 scripts
      headers: CSP report-only, nosniff, Referrer-Policy
        http://127.0.0.1:8000/checkout.html#inline-1  (classic, nonce)  sha384-lXDOInm1aF5PqqU…
        http://127.0.0.1:8000/checkout.html#inline-2  (importmap)  sha384-RK3hVJoVsFjKTgJ…
        http://127.0.0.1:8000/js/app.js  (classic)  sha384-oaeGFW/oKjuWczG…
      ~ http://127.0.0.1:8001/analytics/v2/tag.js  (classic)  sha384-5R5tM2xxeboPVK+…
        http://127.0.0.1:8001/payments/v3/elements.js  (classic, integrity ok)  sha384-i+C8D+bUmsEtpaC…
        http://127.0.0.1:8000/js/checkout.mjs  (module)  sha384-V9XBxb1rMJcHI5I…
  ok       http://127.0.0.1:8000/index.html  200  3 scripts
      headers: nosniff, Referrer-Policy
        http://127.0.0.1:8000/js/app.js  (classic)  sha384-oaeGFW/oKjuWczG…
      ~ http://127.0.0.1:8001/analytics/v2/tag.js  (classic)  sha384-5R5tM2xxeboPVK+…
        http://127.0.0.1:8000/index.html#inline-1  (classic)  sha384-uSDeh2gpqss7OOr…
inventory: 7 scripts seen, 0 new (pending approval)
bodies: 4 external fetched, 0 failed; 1 new versions, 1 scripts changed
$ uv run sentinel scripts show demo http://127.0.0.1:8001/analytics/v2/tag.js
http://127.0.0.1:8001/analytics/v2/tag.js
  kind: external   status: pending
  seen: 2026-11-23 10:11:18Z .. 2026-11-23 10:11:21Z
  versions (2, most recently seen first):
    2026-11-23 10:11:21Z       231 bytes  sha384-5R5tM2xxeboPVK+WaFsUzTA2YwHEgRK/wn7ptQQByydFrdEChhOQ1FYewCG6Zj52
    2026-11-23 10:11:19Z       209 bytes  sha384-raygKpbLnYdKgM3/yZTB+rNJEmEUx75tgDCpLy3OMpv6OlnikQK3g4yXoPd2vFCD
  pin the current body with:
    <script src="http://127.0.0.1:8001/analytics/v2/tag.js" integrity="sha384-5R5tM2xxeboPVK+WaFsUzTA2YwHEgRK/wn7ptQQByydFrdEChhOQ1FYewCG6Zj52" crossorigin="anonymous"></script>
$ uv run sentinel scripts show demo 'http://127.0.0.1:8000/checkout.html#inline-1' | tail -1
  CSP hash source for the current body: 'sha384-lXDOInm1aF5PqqUrDg5CaId7/zhFcRp49CafOH2uDqHBYq9Cjkh80E/lvWCymFNd'
$ git checkout -- examples/fixture-cdn    # put the fixture back
```

`~` marks a script whose body changed: same script, new version. Judging whether that
change is acceptable is the job of the authorization policies (day 4) and the diff and
skimmer heuristics (days 5 and 6). `sentinel scan run` exits 3 when any page could not be
inventoried, so it can gate a cron job or a pipeline; `--json` prints the whole scan,
including each page's security headers and every script fetch.

(Output from a real run against PostgreSQL 16.)

### The API

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
| `POST` | `/v1/sites/{name}/scans` | Scan every page now; returns the scan with each page's snapshot and scripts (`422` if the site has no pages) |
| `GET` | `/v1/sites/{name}/scans?limit=20` | Recent scans, newest first |
| `GET` | `/v1/scans/{id}` | One scan with its snapshots and script observations |
| `GET` | `/v1/sites/{name}/scripts` | The site's script inventory with authorization status, version count and current SRI value |
| `GET` | `/v1/sites/{name}/scripts/{id}` | One script with its version history (hashes, SRI, size, first and last seen) |
| `GET` | `/v1/sites/{name}/scripts/{id}/versions/{version_id}/content` | One version's body, as `text/plain` with `nosniff` and a sandboxing CSP |

`PATCH /v1/sites/{name}` also accepts `respect_robots`. A scan through the API runs inside
the request for now; scheduled background scans arrive with the worker on day 10.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `SENTINEL_DATABASE_URL` | `postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel` | SQLAlchemy async URL (`postgresql+asyncpg://…` or `sqlite+aiosqlite:///…`) |
| `SENTINEL_DEFAULT_SCAN_INTERVAL_HOURS` | `168` | Interval for sites that don't set one (1–168) |
| `SENTINEL_LOG_LEVEL` | `info` | `debug`, `info`, `warning` or `error` |
| `SENTINEL_USER_AGENT` | `script-sentinel/<version> (+https://github.com/xeeshan16/script-sentinel)` | User-Agent for fetches; the part before the first `/` is the robots.txt product token |
| `SENTINEL_FETCH_TIMEOUT_SECONDS` | `10` | Deadline for one page, including redirects and robots.txt |
| `SENTINEL_MAX_PAGE_BYTES` | `2097152` | Larger pages are reported as `too_large` instead of parsed |
| `SENTINEL_MAX_SCRIPT_BYTES` | `5242880` | Larger external scripts are reported as `too_large` instead of hashed |
| `SENTINEL_MAX_REDIRECTS` | `5` | Redirect hops per page or script |
| `SENTINEL_SCAN_CONCURRENCY` | `4` | Pages fetched at once during a scan |

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
package, smoke-tests the CLI and API against PostgreSQL, and scans the fixture site.

Scanner tests run against two real HTTP servers on `127.0.0.1` (the shop and a vendor CDN on
another origin) whose pages and scripts the tests change mid-run, plus `httpx.MockTransport`
for timeouts, oversized bodies, odd redirects and broken servers. No test touches the
internet. CI also changes a vendor script in the fixture CDN between two scans and checks
that it is recorded as a new version of the same script.

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
  fetch.py          page fetcher: timeouts, size caps, redirects, robots.txt
  robots.py         RFC 9309 robots.txt parsing and matching
  inventory.py      finds the scripts a browser would run on a page
  headers.py        captures a page's security-relevant response headers
  jstokens.py       JavaScript tokenizer and the normalized form used for hashing
  sri.py            Subresource Integrity values and browser-style checks
  versions.py       body hashing and per-script version history
  scanner.py        runs a scan and records snapshots, fetches, versions and the inventory
examples/
  serve.py          serves the fixture shop and its CDN on two local origins
  fixture-site/     synthetic shop for the quick start and CI
  fixture-cdn/      the "third-party" scripts it loads
tests/              pytest suite (SQLite always, PostgreSQL when configured)
docs/               PLAN.md and PROGRESS.md
```

## License

[MIT](LICENSE) © 2026 Zeeshan Imdad
