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

## Day 3 — 2026-11-23: hashing and versions

**Done**

- `fetch.py`: `PageFetcher.fetch_script`. Every external script the scanned pages reference
  is downloaded once per scan, concurrently. Redirects are followed to any http(s) URL (a
  browser would), a redirect to another scheme is `bad_redirect`, robots.txt is not consulted
  (loading a subresource isn't crawling), and bodies over `SENTINEL_MAX_SCRIPT_BYTES`
  (default 5 MiB, measured after content decoding) are `too_large` instead of hashed.
- Fixed a crash found while testing redirects: httpx parses a redirect's `Location` eagerly
  and raises `InvalidURL` (not an `HTTPError`) for some values, which escaped the page and
  robots.txt fetchers too. It is now a failed fetch.
- `jstokens.py`: a forgiving JavaScript tokenizer (strings, template literals with nested
  `${}`, regex-versus-division from the previous token, numeric separators and BigInt,
  private names, hashbang, Unicode line terminators). It never raises; unterminated input
  marks the result incomplete. `normalize` drops comments and collapses whitespace but keeps
  line breaks, because automatic semicolon insertion makes them meaningful.
- `versions.py`: each body gets `sha384` over the exact bytes and `normalized_sha384` over
  the normalized tokens, so a rebuild that only changed a banner comment is visibly not a
  code change. Bodies are decoded like browsers do (BOM, then the header charset, then
  UTF-8); NUL characters become U+FFFD in the stored text only (PostgreSQL text can't hold
  them; the hashes use the raw bytes). Hashing runs in a worker thread so a large script
  doesn't stall the API's event loop. `VersionRecorder` upserts versions per
  `(script, sha384)` for a scan: a body seen again moves `last_seen_at`, a new body is a new
  version, and a new body for a script that already had one counts as a change.
- `sri.py`: integrity values, and checks that follow the SRI spec: unknown algorithms and
  malformed tokens are ignored, only the strongest algorithm present counts, nothing usable
  means the browser runs the script unchecked (`no_supported_hash`), and digests are compared
  exactly. Each observation of an external script with `integrity` gets `match`, `mismatch`,
  `no_supported_hash` or `unverified` (body not fetched); the same script can match on one
  page and not on another. Integrity on inline scripts is ignored, as browsers do.
- `inventory.py`: records `<meta http-equiv="Content-Security-Policy">` policies, and warns
  about `integrity` on a cross-origin script without `crossorigin` (the request is no-cors,
  the response opaque, and browsers refuse to run it).
- `headers.py`: each page snapshot keeps the security headers as served (every value, since
  CSP can be sent more than once): CSP and CSP-Report-Only, Integrity-Policy (and
  report-only), HSTS, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`,
  `Permissions-Policy`, COOP/COEP/CORP, `Reporting-Endpoints` and `Report-To`, capped in
  count and length.
- Migration `0003`: `script_fetches` (one row per external script per scan: outcome,
  status, final URL, content type, size, error, version, whether the body was new), plus
  `script_observations.version_id`/`sri_status`, `page_snapshots.security_headers`/
  `meta_csp` and four scan counters (`scripts_fetched`, `scripts_fetch_failed`,
  `versions_new`, `scripts_changed`). Only `script_observations` is rebuilt on SQLite (nothing
  references it); `page_snapshots` gets plain `ADD COLUMN`s so no cascade fires.
- API: scan responses carry the new counters, each page's headers, each script's version,
  SRI value and status, and the script fetches. New: `GET /v1/sites/{name}/scripts/{id}`
  (version history) and `.../versions/{version_id}/content`, served as `text/plain` with
  `nosniff`, a sandboxing CSP and `no-store`, so stored third-party code never runs on the
  sentinel's origin. The inventory listing includes the version count and current SRI.
- CLI: `scan run` shows each page's security headers and each script's SRI value and
  integrity status, marks changed scripts with `~` and unfetchable ones with `!`, and warns
  about integrity mismatches and failed fetches. New `sentinel scripts show SITE LOCATOR`
  prints the version history and a ready-to-paste `<script integrity=…>` tag (or the CSP hash
  source for inline code). `scripts list` shows version counts and the current SRI.
- Examples: `examples/serve.py` serves the fixture shop and a "third-party" CDN on two local
  origins (`examples/fixture-cdn`), adds security headers to the shop's pages, and the
  checkout page pins the payments library with its real SRI hash. The `.test` vendor URLs
  are gone from the quick start, so every script in it is really fetched.
- CI: the fixture smoke test now also checks fetch counts, the SRI match on the checkout
  page and the captured CSP-Report-Only header, then appends a line to the fixture vendor
  script and checks that the next scan records one new version of the same script.

**Tests**

- 304 tests locally on Python 3.13 against SQLite and PostgreSQL 16 (69 new), 100% line
  and branch coverage; the suite also passes on Python 3.12 (SQLite). Ruff and mypy (strict)
  are clean, and `examples/` is now type-checked too.
- Scanner tests use a second local server as the vendor CDN (a different origin), change
  its script mid-test, and check versions, changes, comment-only rebuilds (same normalized
  hash), reverting to an earlier body (its version is reused), per-page integrity status
  and cascade deletes.
- Both CI smoke scripts were run locally against PostgreSQL 16 before pushing, and the
  README output comes from a real run.

**Known limitations (deliberate for now)**

- "Changed" means a body this script has never served before. Going back to an earlier body
  reuses that version and isn't counted; day 5 compares each scan with the previous one.
- The regex-or-division guess treats `/` after `)` as division, so `if (x) /re/.test(y)`
  tokenizes the regex as operators. It still hashes deterministically; it only matters for
  the token diff, where the effect is a coarser diff.
- External scripts are fetched without cookies or a page referrer, so a CDN that serves
  different bodies per user or per referring page is only seen from one point of view.
  The dynamic renderer (day 11) will see what a browser sees.
- A page's `<script>` may point anywhere, including private addresses, and the scanner
  fetches it. Pages are the operator's own, so this is an accepted risk for now; it goes in
  the threat model on day 14 with an option to refuse private ranges.

**Next (day 4):** the authorization workflow for 6.4.3. Approve, reject or justify each
script with an audit trail, and policies: allowlisted origins, pinned hashes, and vendors
that are expected to change (with cache-busting query normalization).

## Day 4 — 2026-11-24: authorization workflow (6.4.3)

**Done**

- `authorization.py`: each script's `status` is now derived, never set by hand, from three
  inputs, in this order:
  - a person's **decision**: approve with a written justification, either `pinned` to the
    bodies served now or for `any_version`, or reject;
  - the site's **policies**: `origin`, `prefix` (a vendor's SDK path) and `hash` (one exact
    body, inline code included). Origin and prefix policies are `expected_to_change` or
    `pinned`; a pinning policy approves the first body it sees (trust on first use) and
    records which one;
  - the **bodies the script serves now** (`scripts.current_version_ids`) and which of them
    were approved (`script_versions.approved_at`/`approved_by`).

  A rejection always wins. A pinned approval holds while every current body was approved or
  matches a hash policy; otherwise the script is `pending` again. A per-script pin is
  deliberate, so a broad "expected to change" origin policy doesn't override it. Without a
  decision, hash policies come first, then the most specific origin or prefix policy (the
  longest prefix, then the origin). `evaluate()` is a pure function, unit-tested on its own.
- Statuses are recomputed after every scan, decision and policy change. A failed fetch
  never flips a status: the script keeps the bodies it last served successfully. Going back
  to an approved body makes a pinned script `approved` again.
- **Cache busters:** origin and prefix policies can drop query parameters
  (`ignore_query: ["v"]` or `["*"]`) before a URL becomes a locator, so `tag.js?v=1` and
  `tag.js?v=2` are versions of one script. The other parameters keep their order and
  encoding. Several URLs can now map to one script within a scan, so `script_fetches` is
  unique per `(scan, url)` instead of `(scan, script)`. Prefixes always end in a path, so
  `https://cdn.vendor.com/` can't match `https://cdn.vendor.com.evil.test/`.
- `audit.py`: an append-only audit trail per site. Every decision, policy change and status
  change (including a script's first evaluation, so the trail shows when each script entered
  the inventory) is an `authorization_events` row numbered per site, carrying the SHA-256 of
  the previous event and of its own canonical JSON. Appends lock the site row
  (`SELECT … FOR UPDATE`) so concurrent writers can't fork the chain. Event ids for scripts
  and policies are plain columns, not foreign keys: the hash covers them, so a cascading
  `SET NULL` would break the chain, and events have to outlive what they mention.
  `verify_chain` walks the trail in keyset pages and reports the first missing, edited or
  relinked event.
- Scans record each observation's authorization status as of the end of the scan, plus
  `scripts_approved`/`pending`/`rejected` counters, so old scans stay accurate evidence.
- Migration `0004`: `policies`, `authorization_events`, decision and status columns on
  `scripts`, approval columns on `script_versions`, the scan counters, the observation
  status, and the new `script_fetches` constraint. The downgrade keeps one fetch per script
  per scan where a query rule had mapped several URLs to one script.
- **SQLite migrations now run with foreign keys off** and finish with
  `PRAGMA foreign_key_check`. Adding a foreign key to `scripts` needs a table rebuild on
  SQLite, and with foreign keys on, dropping the old table would have cascade-deleted every
  observation, version and fetch. A new test scans, downgrades to 0003 and upgrades again,
  and checks the rows survive; it fails if the pragma is switched back on.
- API: `POST /v1/sites/{name}/scripts/{id}/approve|reject|reset`,
  `GET|POST /v1/sites/{name}/policies`, `DELETE /v1/sites/{name}/policies/{id}`,
  `GET /v1/sites/{name}/audit` and `/audit/verify`. Script responses carry the decision,
  scope, justification, status reason and authorizing policy; versions carry who approved
  them. Policy changes return the scripts whose status changed.
- CLI: `sentinel scripts approve|reject|reset`, `sentinel policies add|list|remove`,
  `sentinel audit list|verify` (exits 1 on a broken chain). The actor comes from `--actor`,
  `SENTINEL_ACTOR` or the login name. `scan run` shows each script's status, prints an
  authorization summary, warns when a payment page runs unapproved scripts, and with
  `--fail-on-unauthorized` exits 4 in that case (it wins over exit 3).
- CI: the fixture smoke test authorizes the demo inventory with two policies and four
  approvals, checks the gate passes, changes the analytics tag, and checks the script goes
  back to `pending`, the gate fails with exit 4, and the audit trail verifies with 17
  events.

**Tests**

- 358 tests locally on Python 3.13 against SQLite and PostgreSQL 16 (54 new): pure rule
  tests (`test_policy_rules.py`), real scans against the two local servers
  (`test_authorization.py`: pinned approvals lapsing and coming back, rejection over
  policies, reset, trust on first use, hash policies on inline code, policy removal, query
  folding with two URLs in one scan, a failed fetch, tampering by edit, delete and
  re-hashing), API and CLI tests, and the migration data test. Line and branch coverage is
  100% with PostgreSQL configured; the suite also passes on Python 3.12 (SQLite). Ruff and
  mypy (strict) are clean.
- Both CI smoke scripts were run locally against PostgreSQL 16 before pushing, and the
  README output comes from real runs.

**Plan changes**

- Day 13 now also adds API keys. Until then the API records the `actor` given in the
  request body, which is only trustworthy on a trusted network; the README says so.
- Day 12's evidence export will include the audit trail's verified head hash, which is what
  makes the chain useful against someone who can rewrite the whole table.

**Known limitations (deliberate for now)**

- A new `ignore_query` rule applies from the next scan on. Scripts already recorded under a
  URL with the cache buster stay in the inventory under their old locators (and stop being
  seen).
- Deciding about many scripts at once (for example, approving every inline block of a page)
  is one call per script. A bulk endpoint can come with the evidence work if it's needed.
- Changes still don't raise findings or alerts; that's days 5, 6 and 10.

**Next (day 5):** change detection and diff. A JS-aware token diff between a script's
versions, size and entropy deltas, newly referenced domains and URLs, and findings with a
severity. Also match inline blocks by content before position, so inserting one doesn't
make the ones after it look changed.

## Day 5 — 2026-11-25: change detection and diff

**Done**

- `diff.py`: a token diff between two script bodies, on the tokens from `jstokens`, so
  comments and whitespace never count and an edit inside a minified one-line bundle comes
  out as the few tokens that changed, with context and line numbers.
  - The common prefix and suffix are trimmed first; small middles go to
    `difflib.SequenceMatcher` (autojunk off: in JavaScript the most frequent tokens are the
    ones it would ignore).
  - Large middles get a patience diff: tokens that occur once on each side anchor the
    alignment (longest increasing run), recursively, and ranges without unique tokens use
    `SequenceMatcher` while a total work budget lasts. Past the budget a range is reported
    whole and the diff is marked `coarse` (only if the two sides share tokens; a
    replacement with nothing in common is exact).
  - Found while measuring: the first version compared statement-sized chunks instead, and
    a shuffled 1.4 MB synthetic bundle (90,000 chunks, "}" in a third of them) didn't
    finish within 100 s. With the patience diff the same input takes about 2.4 s here, and
    a realistic two-edit change to that bundle about 2 s for the whole analysis. Each body
    is tokenized once for both the diff and the URL extraction.
- `changes.py`: what a change means.
  - Size and Shannon entropy (bits per character) before and after; the entropy rule only
    counts for bodies of at least 1 KiB, because a few hundred characters swing with any
    edit.
  - URLs and hosts referenced in string and template literals, with `\/`, `\xNN` and
    `\uNNNN`/`\u{…}` escapes undone, protocol-relative `//host` included, and template
    substitutions cut out. Hosts are kept in full, URLs capped at 200 per body.
  - Severity rules as pure functions: reformatting only is `info`; a code change is
    `low`; sharp growth (> 50% and ≥ 1 KiB) or an entropy jump (> 0.3 bits) is `medium`;
    a newly referenced host is `high`; a payment page raises one level. Going back to an
    earlier body is `low`. A new script is `low` inline, `medium` external, `high` from a
    host no other script of the site uses, one level up on a payment page.
  - Inline block matching: exact body, then normalized body, then token similarity
    (≥ 0.6, best pairs first), then position, then a fresh index. Similarity is skipped
    past 50 × 50 candidate pairs.
- `findings.py` and the scanner:
  - After each scan, every script is compared with the bodies it served on its last
    successful fetch (`current_version_ids` before the scan). Any body outside that set
    raises `script.changed` (or `script.reformatted`), diffed against the closest previous
    body; this also fixes day 3's gap where going back to an earlier body wasn't counted.
    A failed fetch raises nothing and keeps the old bodies as the reference.
  - A script new to the inventory raises `script.added` only if it shows up on a page an
    earlier scan already inventoried. First version: "after the site's first scan". The
    CI smoke test showed why that's wrong: the checkout page had been skipped by robots.txt
    until then, so all of its scripts became findings the first time it was scanned. Now
    each page's first successful scan is its baseline.
  - Inline locators come from the matching above instead of the raw position, fixing day
    2's known limitation: a snippet inserted in front makes one new script, not N changes.
    Inventories from before day 4 have inline scripts without current bodies; those fall
    back to positions (tested).
  - Findings can be acknowledged, resolved (a note is required) and reopened; each step
    records who, when and why on the finding and appends `finding.*` events to the site's
    hash-chained audit trail.
- Migration `0005`: `findings.scan_id`, `previous_version_id`, `locator` (so a finding stays
  readable after its script is deleted), `status_changed_at/by`, `status_note`, an index on
  `scan_id`, and `scans.findings_new`. `findings` is rebuilt on SQLite (nothing references
  it); `scans` only gets an `ADD COLUMN`.
- API: scan responses carry `findings_new` and the findings; `GET /v1/sites/{name}/findings`
  (filters: status, minimum severity, scan, script), `GET /v1/findings/{id}`,
  `POST /v1/findings/{id}/acknowledge|resolve|reopen`, and
  `GET /v1/sites/{name}/scripts/{id}/diff?from=&to=` (version id, hex SHA-384 prefix or the
  SRI prefix that `scripts show` prints).
- CLI: `scan run` and `scan show` list the findings (and `~` now marks the scripts a change
  finding is about); `scan run --fail-on SEVERITY` exits 5 (it wins over 4 and 3);
  `sentinel findings list|show|ack|resolve|reopen`; `sentinel scripts diff SITE LOCATOR
  [--from] [--to]`.
- CI: the fixture smoke test now also checks the analytics change is a `medium` finding,
  plants a synthetic skimmer (a `sendBeacon` to a new host) and checks for a `critical`
  finding with the host and the added tokens, exit 5 from `--fail-on high`, the scripts
  diff, the audited ack/resolve flow (resolve without a note exits 2), and that inserting
  an inline block in front raises exactly one `script.added` for `#inline-3`.

**Tests**

- 430 tests locally on Python 3.13 against SQLite and PostgreSQL 16 (72 new), 100% line
  and branch coverage; the suite also passes on Python 3.12 (SQLite). Ruff and mypy (strict)
  are clean.
- New: `test_diff.py` (hunks, lines across every line terminator, truncation, the patience
  path against the exact result, the budget and `coarse`), `test_changes.py` (references,
  entropy, every severity rule, inline matching cases), `test_findings.py` (real scans
  against the two local servers: vendor change with a new host, reformatting, reverting,
  failed fetches, added scripts and hosts, per-page baselines, inline insertion and
  in-place edits, a script serving two bodies, the handling workflow and its audit events,
  findings outliving their script, version diffs), API and CLI tests, and a migration test
  that `0005` keeps findings in both directions.
- Both CI smoke scripts were run locally against PostgreSQL 16 before pushing, and the
  README output comes from a real run.

**Known limitations (deliberate for now)**

- Line breaks don't count in the token diff (they do in the normalized hash), so a change
  that only matters through automatic semicolon insertion shows up as a hash change with
  an empty diff.
- URLs assembled at runtime (`"https://" + host`, `atob(...)`) aren't extracted; that is
  day 6's skimmer heuristics.
- A finding's diff keeps the first 50 hunks; `scripts diff` recomputes the full diff on
  demand.

**Next (day 6):** skimmer heuristics. New exfiltration sinks (fetch, XHR, sendBeacon, image
or WebSocket to a new host), listeners on card or form fields, wallet-address regexes and
swaps, eval/atob/obfuscation and scripts that inject other scripts, against a corpus of
synthetic malicious fixtures, feeding the finding's severity.

## Day 6 — 2026-11-26: skimmer heuristics

**Done**

- `heuristics.py`: reads what a body *does*, in two steps.
  - `inspect()` partly evaluates the token stream first, the way a reviewer reads
    obfuscated code: `atob("…")`, `String.fromCharCode(…)` and
    `"…".split("").reverse().join("")` on literals are replaced by their result (three
    layers deep), adjacent literals joined with `+` are folded, `obj["name"]` becomes
    `obj.name`, escaped identifiers (`e\u0076al`) are read as what they spell, and
    `name = <URL>` assignments are remembered so `fetch(name)` knows its destination.
  - The rules then emit counted signals with evidence (the code where each first occurs):
    exfiltration sinks (`sendBeacon`, `fetch`, XHR via `.open`, image pixels via `.src` or
    `setAttribute`, WebSockets, `$.ajax`/`$.post`/`$.get`) with their destination
    (literal, hidden, relative or computed at runtime); card fields in strings, selectors
    and property names; form listeners (`addEventListener`, jQuery `.on`, `onX =`) and
    serialization; cookies and storage; wallet addresses (ETH, bech32, base58, TRON),
    address-matching regexes and `RegExp` strings, clipboard access; `eval`/`Function`
    (separately on decoded text), string timers, the packer, `_0x` names, sensitive text
    hidden by encoding or joining, sensitive APIs reached by hidden names; scripts injected
    with `createElement("script")`, `<script>` markup or `import()`, with their source.
  - `assess()` combines signals into verdicts with a severity: card fields plus a send to a
    host that is neither the script's nor the site's (or a hidden one) is `high`, `medium`
    when the destination is computed at runtime; form input plus such a send is `high`; a
    send to a hidden host is `high`; wallet addresses with the clipboard, or an address with
    a matcher, is `high`; `eval` on decoded text is `high`; dynamic code, packing, hidden
    URLs and injected scripts from other hosts are `medium`; a send to another host with
    nothing else is `low`. With the previous body's report, a verdict needs at least one
    signal that is new or occurs more often.
- Wired into change review:
  - `analyze_change` runs both bodies through the heuristics. Hosts the code hides count
    as referenced hosts, which closes day 5's limitation on URLs built with `atob` or
    joined from pieces. The analysis carries the signals the new body added and the
    verdicts on them, and each verdict raises the severity (before the payment-page step).
    Going back to an earlier body skips the new-host rule but not the heuristics: the old
    body may be the skimmer coming back.
  - New scripts get every signal and verdict in their finding and the severity of the worst
    verdict.
  - New `script.suspicious` finding kind: a script on a page's first scan with a `high`
    verdict or worse is reported instead of becoming part of the baseline. Medium verdicts
    stay in the baseline. No migration: `findings.kind` is a free `VARCHAR(64)`.
  - "Its own" destinations are the script's host and the site's origin hosts (ports
    ignored), passed by the scanner.
- `sentinel inspect FILE [--script-host] [--site-host ...] [--fail-on] [--json]` runs the
  heuristics on a local file with no database (exit 5 under `--fail-on`).
  `sentinel scripts inspect SITE LOCATOR [--version]` and
  `GET /v1/sites/{name}/scripts/{id}/inspect?version=` run them on a stored version,
  read-only. `scripts diff`, the diff endpoint and `findings show` print or return the
  verdicts and new signals. `scan run` no longer marks a script `~` for a finding that
  isn't a change.
- `jstokens.py` now owns the literal helpers (`unescape`, `string_value`, `urls_in`),
  shared by `changes.references` and the heuristics.
- `tests/fixtures/heuristics/`: a corpus of 13 inert, skimmer-shaped samples and 7 benign
  look-alikes, each declaring its context and the exact verdicts it must get.
- CI: a step runs `sentinel inspect` on the corpus (a skimmer fails `--fail-on high`, the
  PSP library given its own host passes, a hidden loader host is reported); the fixture
  smoke test checks the planted beacon's verdict and adds a page that already runs a
  base64-hidden pixel skimmer, expecting a `critical` `script.suspicious` with the hidden
  host and a matching `scripts inspect`.
- README: a skimmer heuristics walkthrough, the "Review a change" walkthrough re-recorded
  from a fresh real run (the finding now carries the verdicts), new commands and endpoint,
  design notes.

**Tests**

- 542 tests locally on Python 3.13 against SQLite and PostgreSQL 16 (112 new), 100% line
  and branch coverage. Ruff and mypy (strict) are clean.
- New: `test_heuristics.py` (the corpus with exact verdicts, decoding and its failure
  cases, folding and its cap, computed members, escaped strings and identifiers,
  templates, every sink and destination kind, look-alikes that aren't sinks, bindings,
  every collection, wallet, obfuscation and injection rule, truncation, serialization,
  verdict combinations and the "needs a new signal" rule); `test_changes.py` (suspicious
  severity, verdicts raising added and changed scripts, hidden hosts as referenced hosts);
  `test_findings.py` (a skimmer on the first scan, a medium one staying in the baseline,
  new scripts carrying verdicts, first-party destinations staying quiet, inspecting stored
  versions); API and CLI tests for `inspect`, `scripts inspect`, the diff and finding
  output, and findings stored before today.
- Rough cost, measured locally once: `inspect()` on a 1.25 MB concatenation of the benign
  corpus took about 0.8 s.
- Both CI smoke scripts and the new corpus step were run locally against PostgreSQL 16
  before pushing, and the README output comes from a real run.

**Known limitations (deliberate for now)**

- Static analysis only: data flow is followed through literal assignments, not through
  functions, objects or arrays, so `fetch(cfg.endpoint)` is "computed at runtime". Day 11's
  renderer will see what actually runs.
- The rules can be evaded by anyone who reads them, and some legitimate code trips
  `medium` verdicts (old `'<scr' + 'ipt>'` snippets read as hidden text, for example). A
  verdict says where to look; it never approves anything.
- Scripts already in the inventory are not re-inspected until they change;
  `sentinel scripts inspect` covers them on demand.

**Next (day 7):** the CSP report collector. `report-uri` and Reporting API formats, schema
validation, size limits, per-site rate limits, dedupe and fingerprinting.

## Day 7 — 2026-11-27: CSP report collector

**Done**

- `csp_reports.py`: pure parsing for both browser formats.
  - `report-uri` (`application/csp-report`, `{"csp-report": {…}}`, CSP Level 2 names) and
    the Reporting API (`application/reports+json`, a batch in which only `csp-violation`
    entries count). `application/json` is accepted for either, by shape; a shape that
    contradicts the content type is refused rather than guessed at.
  - Pydantic schemas per report with lax types (`"12"` is a line number), length caps and
    `extra="ignore"`. One bad report in a batch is counted, not fatal.
  - Normalization: document, blocked and source URLs keep only origin and path (no query,
    fragment or credentials; lowercased host, IDNA, default port dropped, IPv6 bracketed);
    `data:`/`blob:` and other opaque or authority-less schemes keep only the scheme, and
    old browsers' bare `data` becomes `data:`; keywords (`inline`, `eval`, `wasm-eval`,
    `trusted-types-*`, `self`) are kept as such; the directive comes from
    `effective-directive`, falling back to the first token of `violated-directive`; a
    missing disposition is `unknown`; samples are cut to 40 characters and stripped of
    control characters; the policy is kept up to 4096 characters and hashed in full. The
    referrer and user agent are never kept.
  - Drop reasons: `invalid`, `not_csp`, `foreign_document` (the page isn't on the site's
    allowed origins), `extension` (blocked or source URL in a browser extension),
    `batch_limit` and `group_limit`.
  - `Violation.fingerprint()`: SHA-256 over page, directive, blocked kind and value,
    source file, line and disposition. Column, sample and policy text are left out on
    purpose (minified builds move columns; samples are attacker-controlled).
- `violations.py` and migration `0006`: a `csp_violations` table with one row per
  (site, fingerprint), `count`, `first_seen_at`/`last_seen_at`, the format of the latest
  report, and `blocked_host` ready for day 8's aggregates. A request's reports are folded
  in memory, then written with one `INSERT … ON CONFLICT DO UPDATE` per request (the same
  statement on PostgreSQL and SQLite). A per-site cap on groups (default 10,000) drops
  reports that would open a new group while known groups keep counting. Listing with
  filters (directive, disposition, blocked host, since), two orders and totals.
- `ratelimit.py`: a keyed token bucket (injectable clock), charged per report; a refused
  request takes nothing and gets the wait time.
- API (`api/csp.py`):
  - `POST /v1/reports/csp/{site}` answers `202` with received/accepted/new/updated and
    drop counts. `413` from `Content-Length` and again while streaming (a missing or
    understated length doesn't help), `415` for other content types or a compressed body,
    `400` for a body that isn't a report payload, `429` with `Retry-After` when over the
    limit. The bucket is charged before any write, and a rejected request still costs one
    token. `404` for an unknown site.
  - `OPTIONS` on the same path answers CORS preflights (Reporting API deliveries need
    them) with `Access-Control-Allow-Origin` only for the site's own origins.
  - `GET /v1/sites/{site}/csp/violations` and `…/violations/{id}` (with the policy).
- Settings: `SENTINEL_CSP_MAX_BODY_BYTES` (64 KiB), `…_MAX_REPORTS_PER_REQUEST` (100),
  `…_REPORTS_PER_MINUTE` (600), `…_BURST` (300, must cover a full batch),
  `…_MAX_GROUPS_PER_SITE` (10,000).
- CLI: `sentinel csp ingest SITE FILE|- [--format] [--json]` replays a saved payload
  through the same pipeline (no rate limit), `sentinel csp violations` and
  `sentinel csp show`.
- `examples/csp-reports/`: a synthetic `report-uri` payload and a Reporting API batch (two
  reports of one beacon differing only in query strings, an inline violation, extension
  noise, another site's page, a deprecation report). All hosts are on `.test` or
  `example.com`.
- CI: the API smoke test posts both payloads and checks the grouping, the drop reasons,
  that no query string was stored, preflights for an allowed and a foreign origin, `413`
  and `415`, and a CLI replay.
- README: a "Collect CSP reports" walkthrough recorded from a real run against
  PostgreSQL 16, the new endpoints, settings, data model and design notes.

**Tests**

- 709 tests locally on Python 3.13 against SQLite and PostgreSQL 16 (167 new), 100% line
  and branch coverage. Ruff and mypy (strict) are clean; the package builds.
- New: `test_csp_reports.py` (URL stripping and what it refuses, blocked values, directives,
  extensions, content types and shapes, every drop reason, truncation and full-policy
  hashing, what a fingerprint ignores and what it tells apart, the example payloads, batch
  limits); `test_violations.py` (upserts and counters, timestamps on conflict, format of the
  latest report, the group cap, site isolation, filters and ordering, cascade on site
  delete); `test_ratelimit.py`; `test_api_csp.py` (both payloads end to end, filters, 404s,
  413 by length and by stream, 415, 400, rate limiting per report, batch caps, the token a
  refused request costs, CORS for allowed and foreign origins); `test_cli_csp.py`.
- The CI smoke step was run locally against PostgreSQL 16 before pushing.

**Known limitations (deliberate for now)**

- The rate limit lives in each API process. With several replicas each enforces it on
  its own share; a shared limit belongs with day 8's ingest path.
- Reports are written inside the request. Day 8 adds the buffered batch path with
  backpressure and optional Kafka.
- The group cap is checked per request, so concurrent requests can overshoot it by a few
  groups.
- Report endpoints are unauthenticated by nature; anyone can post plausible reports about
  a site's own pages. The limits bound the cost, and counts are signals, not evidence.

**Next (day 8):** high-volume ingest. A buffered batch-insert path with backpressure and
optional Kafka (aiokafka) behind an interface, and rolling aggregates per directive and
blocked host.
