# script-sentinel: 14-day plan

One milestone per day, starting 2026-11-21. Progress is logged in [PROGRESS.md](PROGRESS.md).

| Day | Milestone | Status |
| --- | --- | --- |
| 1 | **Scaffold:** FastAPI app, settings, SQLAlchemy + Alembic (Postgres and SQLite), a domain model (sites, pages, scripts, versions, findings), README, MIT license, CI (ruff, mypy, pytest, build), PLAN and PROGRESS. | done |
| 2 | **Scanner v1:** fetches allowlisted pages (with timeouts, size caps and robots handling) and parses `<script>` tags (src, inline, integrity, nonce, type). Stores inventory snapshots. Tested against a local fixture site. | done |
| 3 | **Hashing and versions:** fetches each script, hashes it with SHA-384 (raw and normalized), keeps a version history and generates SRI hashes. Captures the security headers (CSP, HSTS and others) as a snapshot for 11.6.1. | done |
| 4 | **Authorization workflow (6.4.3):** approve or justify each script, with policies: allowlisted origins, pinned hashes, and "expected to change" vendors. REST API and audit trail. | done |
| 5 | **Change detection and diff:** a JS-aware tokenized diff, size and entropy deltas, and new domains or URLs referenced. Findings get a severity. | done |
| 6 | **Skimmer heuristics:** new exfiltration sinks (fetch, XHR, sendBeacon, image or WebSocket to a new host), listeners on card or form fields, wallet-address regexes and swaps, eval/atob/obfuscation, and scripts that inject other scripts. Uses a corpus of synthetic malicious fixtures. | done |
| 7 | **CSP report collector:** `report-uri` and Reporting API formats, schema validation, size limits, per-site rate limits, dedupe and fingerprinting. | done |
| 8 | **High-volume ingest:** a buffered batch-insert path with backpressure and optional Kafka (aiokafka) behind an interface. Rolling aggregates per directive and blocked host. | |
| 9 | **CSP builder:** suggests a policy from the approved inventory plus the reports seen, compares report-only with the enforced policy, and gives a rollout checklist. | |
| 10 | **Worker and alerts:** per-site scan schedules (at most every 7 days by default), Postgres advisory locks, retries with backoff, and a transactional outbox with HMAC-signed webhooks (Slack-compatible payload). | |
| 11 | **Dynamic scripts:** an optional Playwright renderer behind an interface catches scripts injected at runtime, with a fake renderer for tests. The scanner merges static and rendered inventories. | |
| 12 | **Evidence and explainer:** exports for 6.4.3/11.6.1 evidence (inventory with justifications, scan history, alerts, and the audit trail's verified head hash) in JSON and Markdown, plus an optional LLM diff explainer with a deterministic fake. | |
| 13 | **Observability, auth and deploy:** API keys for the REST API (the audit trail's actor comes from the key instead of the request body), Prometheus metrics, OTel traces, Docker Compose (API, worker, Postgres, optional Kafka), and an e2e test in CI where the fixture vendor script is compromised mid-run and an alert has to fire. | |
| 14 | **Finish:** README polish with real output, Mermaid diagrams, a clean-clone check, threat model and limitations, and a "What I'd do next" list. | |

## Ground rules

- Only origins a site lists are ever fetched as pages; third-party script URLs are fetched
  only because an allowlisted page references them.
- No paid API keys or secrets are needed to build, test or run the demo. Anything external
  (an LLM, Kafka, a headless browser) is optional and sits behind an interface with a
  deterministic fake.
- Synthetic fixtures only: the test suite "compromises" a local fixture vendor script; it
  never scans third-party sites.
