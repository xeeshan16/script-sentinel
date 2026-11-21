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
