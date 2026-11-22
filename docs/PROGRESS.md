# Progress log

One entry per day. The plan is in [PLAN.md](PLAN.md).

## Day 1 — 2026-11-21: scaffold

**Done**

- Project layout: `src/script_sentinel`, Python 3.12+, `uv` with a lock file, hatchling build,
  `sentinel` console script.
- Settings from `SENTINEL_*` environment variables (`config.py`). The scan interval is capped
  at 168 hours, because PCI DSS 11.6.1 asks for tamper detection at least every 7 days.
- Domain model (`db/models.py`) for sites, pages, scripts, script versions and findings, with
  one hand-written Alembic migration (`0001`). Design choices:
  - enums are `VARCHAR` plus a `CHECK` constraint, not native Postgres enums, so later
    values are a constraint change rather than `ALTER TYPE`;
  - JSON columns are `JSONB` on PostgreSQL and `JSON` on SQLite;
  - timestamps are timezone-aware UTC on both backends (a `TypeDecorator` refuses naive
    datetimes and re-attaches UTC on SQLite);
  - a script is identified within its site by a `locator` (its absolute `src`, or page URL
    plus position for inline blocks), so a changed body becomes a new version of the same
    script, unique per `(script, sha384)`;
  - deleting a site cascades to everything; deleting a script keeps its findings
    (`SET NULL`), because findings are audit evidence.
- Origin allowlist (`origins.py`): parses and normalizes origins the way browsers compare
  them (lowercase, IDNA, default port dropped, IPv6 literals), rejects URLs with embedded
  credentials without echoing them, rejects anything that isn't a bare origin, and matches
  exactly (a subdomain is a different origin).
- Site and page service (`sites.py`) with two invariants: every page is on an allowed origin
  of its site, and an origin can't be removed while pages still use it.
- REST API: `/healthz`, `/readyz` (pings the database, never echoes the URL),
  `/v1/sites` CRUD and `/v1/sites/{name}/pages`. Domain errors map to 404/409/422; request
  bodies reject unknown fields.
- CLI: `sentinel db upgrade|downgrade|current`, `sentinel sites add|list|remove`,
  `sentinel pages add|list|remove`, `sentinel serve`, `sentinel version`. Validation errors
  exit 2, other domain errors exit 1.
- CI (GitHub Actions): ruff lint and format check, mypy strict, pytest with coverage gate
  (95%) on SQLite and PostgreSQL 16, `uv build`, then a smoke test of the CLI and the API
  against PostgreSQL. Python 3.12 and 3.13.

**Tests**

- 129 tests locally on Python 3.13 against SQLite and PostgreSQL 16, 100% line and branch
  coverage. The suite also passes on Python 3.12 (SQLite only locally).
- `test_migrations.py` checks that the ORM models and the hand-written migration describe the
  same schema (Alembic `compare_metadata` returns no differences) on both backends, and that
  upgrade → downgrade → upgrade round-trips.
- The CI smoke script was run locally against PostgreSQL 16 before pushing.

**Next (day 2):** scanner v1. Fetch allowlisted pages with timeouts, size caps and
`robots.txt` handling, parse `<script>` tags (src, inline, integrity, nonce, type) and store
inventory snapshots, tested against a local fixture site.

## Day 2 — 2026-11-22: scanner v1

**Done**

- `fetch.py`: the page fetcher.
  - Redirects are followed by hand and every hop must stay on one of the site's allowed
    origins; a redirect elsewhere is recorded as `redirect_blocked` and never followed.
  - Connect/read timeouts plus an overall deadline per page, at most `max_redirects` hops.
  - Bodies are streamed and abandoned past `SENTINEL_MAX_PAGE_BYTES` (a declared
    `Content-Length` over the cap is refused before reading). An oversized page is recorded
    as `too_large` rather than parsed up to the cut, because a truncated page would hide the
    scripts after it.
  - Non-HTML responses are `not_html`; a missing content type is parsed as HTML. Decoding
    follows the browser order: BOM, then the `Content-Type` charset, then `<meta charset>`.
- `robots.py`: RFC 9309 parsing and matching, written from the RFC because
  `urllib.robotparser` has no `*`/`$` wildcards and applies the first matching rule instead
  of the longest. Groups for our product token are combined, and the `*` groups are used only
  when none match. Allow wins ties, `/robots.txt` is always allowed, and only the first
  500 KiB are parsed. The fetcher maps HTTP status per the RFC: 2xx parsed, 4xx means no
  rules, 5xx or unreachable means disallow everything. robots.txt is fetched once per origin
  per scan.
- `sites.respect_robots` (default on), with `sentinel sites add --ignore-robots`,
  `sentinel sites update --respect-robots/--ignore-robots` and `respect_robots` in the API.
  Checkout pages are often disallowed for crawlers, and the site owner may still want them
  monitored. A robots refusal counts as *skipped*, not *failed*, and the CLI warns when one
  kept a payment page out of a scan.
- `inventory.py`: finds the scripts a browser would run, following the HTML standard where it
  changes the answer:
  - `type` decides whether a block is code. Missing, empty or a JavaScript MIME type is
    classic, `module` is a module, and `importmap` is kept because it controls where modules
    load from. Other types (`application/ld+json`, templates, `speculationrules`) are data
    blocks, counted but not inventoried. The legacy `language` attribute applies when `type`
    is absent.
  - The first `<base href>` changes resolution. Scripts in `<template>` and `<noscript>` are
    skipped. SVG scripts are read from `href`/`xlink:href`. `data:` URLs are decoded and
    treated as inline code. An unterminated `<script>` at the end of a document is kept.
  - Unfetchable sources (`javascript:`, `blob:`, empty `src`, invalid `data:` URLs,
    external import maps, overlong URLs) become warnings on the snapshot instead of
    disappearing.
- Migration `0002`: `scans`, `page_snapshots` and `script_observations`, plus
  `sites.respect_robots`. Snapshots keep the URL and payment flag and survive page removal
  (`page_id` is set to NULL), because they are the evidence that a check ran. Observations
  record the position, type, `integrity`, `crossorigin`, `referrerpolicy`, `async`/`defer`/
  `nomodule`, and the inline body's SHA-384. Nonces are stored only as a 16-hex-character
  SHA-256 digest: enough to notice a nonce that never changes, without keeping the value.
  `ALTER TABLE` is used directly instead of Alembic batch mode, so SQLite never rebuilds
  `sites` (a rebuild would cascade deletes into every table that references it).
- `scanner.py`: fetches all pages concurrently (`SENTINEL_SCAN_CONCURRENCY`) with no
  transaction open, then writes the scan, snapshots and observations and upserts the
  inventory by locator in one go. New scripts start as `pending`. The scan status is
  `completed`, `partial` or `failed` depending on how many pages failed.
- API: `POST`/`GET /v1/sites/{name}/scans`, `GET /v1/scans/{id}`,
  `GET /v1/sites/{name}/scripts`. CLI: `sentinel scan run|list|show`, `sentinel scripts
  list`. `scan run` exits 3 when any page could not be inventoried.
- `examples/fixture-site`: a synthetic shop for the quick start and the CI smoke test. Its
  robots.txt disallows `/checkout`, which exercises the opt-out path.
- CI: a new step serves the fixture site and checks a full scan, the robots skip, the opt-out
  and the exit code for a failing page, against PostgreSQL.

**Tests**

- 235 tests locally on Python 3.13 against SQLite and PostgreSQL 16 (106 new), 100% line and
  branch coverage. Ruff and mypy (strict) are clean.
- The scanner and CLI tests run against a real HTTP server on `127.0.0.1` whose routes the
  tests change mid-run (a page's inline config changes, a vendor script disappears, a page
  starts returning 500). `httpx.MockTransport` covers timeouts, the overall deadline,
  oversized streamed bodies, redirect loops and robots.txt status handling.
- `test_examples.py` runs the README quick start against `examples/fixture-site`.
- The README output comes from a real run against PostgreSQL 16, and the new CI smoke step
  was run locally before pushing.

**Known limitations (deliberate for now)**

- Inline scripts are identified by their position among a page's inline blocks. Inserting a
  block in front of others shifts the ones after it, so they will look changed. Day 5's diff
  should match inline blocks by content similarity before falling back to position.
- An external script with a cache-busting query (`app.js?v=123`) gets a new locator whenever
  the query changes. Day 4's policies (pinned vs. "expected to change") are the place to
  normalize this per vendor.
- Only scripts present in the HTML are seen. Scripts injected at runtime are day 11.
- `<script src="..." />` outside SVG is treated as a complete element. Browsers ignore the
  slash and keep the element open, so the following markup becomes script text.
- A scan through the API runs inside the request. Background scans come with the worker on
  day 10.

**Next (day 3):** hashing and versions. Fetch each external script (same limits, never as a
page), hash it with SHA-384 raw and normalized, keep a version history per script, generate
SRI values, and snapshot the security headers (CSP, HSTS and others) for 11.6.1.
