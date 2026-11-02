# Progress

Status of each phase. A phase is marked Done only after every acceptance check in
`Docs/IMPLEMENTATION_PLAN.md` has been verified (see the phase-completion rule).

## Phase 0 — Environment, repository and skeleton

**Status:** Done (verified 2026-11-02)

**What was built:**
- Root: `.gitignore`, `.gitattributes` (LF line endings), `.env.example`,
  `docker-compose.yml` (postgres, redis, api), `Makefile`, `README.md`, `PROGRESS.md`.
- `backend/`: MVC package `phishguard` (`core/`, `models/`, `schemas/`, `views/`,
  `controllers/`, `services/{features,ml,intel,simulation}/`, `db/`, `workers/`),
  `GET /health`, `Dockerfile` (non-root user), `README.md`, tests.
- `frontend/dashboard/`: React + Vite + TypeScript + Tailwind, feature folders (`overview`,
  `detections`, `campaigns`, `models`, `experiments`, `threat-intel`, `settings`, `auth`),
  `shared/` (layout, sidebar, page header, API client, types), tests.
- `frontend/extension/`, `ml/`, `gateway/`: folders and READMEs (code comes in later phases).
- `Docs/`: `features.md` (generated from Appendix A), `decisions.md`, `data_card.md`
  template, `devlog/`.

**How to run:** see `README.md` (quick start) and each module README.

**Acceptance checks (verified 2026-11-02):**
- [x] `make lint` and `make test` pass on a clean clone — fresh `git clone` of commit
  `dacbc75`, `make install`, then `make test`: backend 6 passed, dashboard 8 passed;
  `make lint`: ruff "All checks passed!", "23 files already formatted", `tsc` clean. Exit 0.
- [x] `docker compose up` starts Postgres and Redis healthy — `make up`: postgres (healthy),
  redis (healthy), api up; `pg_isready` "accepting connections"; `redis-cli ping` "PONG".
- [x] `Docs/features.md` has exactly 140 rows, F1…F140, names as in Appendix A —
  `test_feature_catalogue.py` (4 tests) passed.
- [x] `GET /health` returns 200 through view → controller → schema — HTTP 200 from the
  container: `{"status":"ok","app_name":"PhishGuard API","version":"0.1.0","environment":"development"}`;
  API runs as `appuser` (non-root).
- [x] Dashboard feature import rule enforced — `structure.test.ts` passed, and was shown to
  fail on a deliberate cross-feature import.

**Carried forward (your action, not a code check):**
- [ ] Send the university ethics-approval request. Needed before Phase 6 (simulations).

**Known issues:**
- pytest prints a Starlette deprecation warning recommending `httpx2` for the TestClient;
  harmless for now, to be checked before switching.
- npm did not run esbuild's install script (npm `allowScripts`); build and tests still work.
- Local `.env` was created from `.env.example` with a random Postgres password (gitignored).

**Decisions made:** D0 layout, backend MVC, `models/` = DB tables only, installable
`phishguard` package, feature-based dashboard, LF line endings (see `Docs/decisions.md`).

**Next phase needs to know:** decisions D1 (category labelling), D3 (URL/email split) and
D4 (grouping key, the Enron problem) must be settled before Phase 1 starts. The `snapshot`
collector service is added to `docker-compose.yml` in Phase 1.

## Phase 1 — Data and split

**Status:** In progress — all code built and tested (2026-11-02); the real split is not made yet.
**Decided 2026-11-02 (you accepted the recommendations):** D3 = largest balanced set at split
time (≈120k, report the gap to 175k); D9 = option (a); D10 = (a) one same-site page per Tranco
home page, built into the snapshot collector, + (c) path-free URL results in Phase 3;
snapshots of the real URLs approved and **started 2026-11-02** (phishing first).

**Remaining, in this order** (the snapshot run rewrites `records.parquet` when it ends, so
`build` must not run while it is running):
1. ~~Snapshot runs~~ **done 2026-11-02** (both passes exit 0, 10:05): 101,313 URL records
   have snapshots (all 51,592 phishing), and 16,213 same-site legitimate link pages (D10a)
   were added.
2. RDAP run finishes (`python -m phishguard_ml rdap`, registries only; re-run once to retry
   HTTP 429s). Missing data (no RDAP server / HTTP 403) is kept as missing — see decisions.
3. ~~Enron download~~ **done 2026-11-02**: 443 MB (the page says "about 1.7Gb"; the file is complete: gzip check OK,
   520,743 files from 150 mailboxes, as the page describes); 10% received-mail sample = 20,346 emails. `build` re-run with
   Enron: 183,931 records after de-duplication.
4. `build` (now with Enron) → both snapshot passes again (fetch nothing old, restore the D10
   pages) → `label` → `count` → `datacard`.
5. `split --n-url <2 × phishing URLs> --n-email <2 × phishing emails>` (D3) → `verify-split`.
6. Start the daily collector: `docker compose --profile collect up -d collector`.
7. Re-check every acceptance check below on the real data, then mark Phase 1 Done.

**Steps:**
- [x] 1. `ml/` package, paths, `SampleRecord` (UUID v5 ids), Parquet read/write
- [x] 2. Downloaders + manifests (`download.py`); formats verified on the source pages and on
  the real files. Downloaded 2026-11-02: PhishTank, OpenPhish, Tranco (list V354N), Nazario,
  SpamAssassin, Enron (443 MB, complete).
- [x] 3. Parsing (`parse.py`) and cleaning (`clean.py`): URL normalisation, registered domain,
  email parsing, D4 group keys, de-duplication (phishing copy wins a label conflict)
- [x] 4. Email time-clue normaliser (`email_normalise.py`)
- [x] 5. Snapshot collector (`snapshot.py`, `ml/Dockerfile`, compose `snapshot` service).
  Checked in the container on 5 legitimate Tranco sites: 3 full snapshots, 1 does not resolve,
  1 connect timeout — all recorded. **Not yet run on phishing URLs** (your go needed).
- [x] 6. Category labeller (`label.py`, D1), shared word lists in
  `backend/phishguard/services/features/lexicons.py`
- [x] 7. Counting (`pipeline.count`): see the data card. **Stop: you choose n_url / n_email.**
- [x] 8. Sampling, grouped split, 5 folds, hashes, never-overwrite (`split.py`) — tested on
  synthetic data; **real split not made** (waits for D3, D9, D10, Enron, snapshots)
- [x] 9. Daily collector (`collect.py`, compose `collector` service), own-mailbox loader
- [x] 10. `Docs/data_card.md` generated from pipeline outputs (`datacard.py`)

**Real numbers (build 2026-11-02, without Enron):** 165,123 records after de-duplication —
URLs 51,592 phishing / 99,994 legitimate; emails 9,429 phishing / 4,108 legitimate. Largest
balanced set today: 103,184 URLs + 8,216 emails = 111,400 (< 175,000; Enron will add
legitimate emails, so emails can reach about 18,858).

**Acceptance checks:**
- [ ] Final counts match 175,000 and 50/50, per-category counts in the data card — *not yet*:
  only 111,400 balanced samples are possible today (see D3 below); categories are in the card
- [x] No group_key on both sides of the split; no content_hash twice — `test_split.py`,
  `test_clean.py` (synthetic data; to re-check on the real split)
- [x] Test ≈ 15%, folds stratified, reproducible from seed 42 — `test_split.py`
- [ ] Monthly collector runs as a scheduled job and writes a dated batch — code and test pass
  (`test_pipeline.py`); **not yet started live** in the container
- [x] Tests run offline against small fixture files — 101 ml tests, network mocked

**Test results (2026-11-02):** `make test` backend 25, ml 101, dashboard 8 passed;
`make test-db` 1 passed; `make lint` clean; `docker compose config` valid.

**Known issues:**
- The first two snapshot passes stopped on single malformed URLs (`httpx.InvalidURL` from a
  redirect; `Invalid IPv6 URL` from a page link). Fixed: both are recorded per URL, and any
  unexpected error for one URL is written to its `meta.json` instead of stopping the run.
  Regression tests added; finished snapshots were kept (resume).
- After snapshots, URL categories are still mostly `unknown` (46,731 of 51,592): most live
  phishing pages show no form without JavaScript, or were already taken down (see
  `Docs/decisions.md`, 2026-11-02 finding). **You decided:** PhishTank's `target` field now also
  marks brand impersonation (D1 extended, tests added).
- One snapshot had an empty `meta.json` from a stopped run; writes are now atomic and the
  URL was re-fetched (regression tests added).
- Legitimate URLs with snapshots: 49,721 (incl. 16,213 link pages), slightly fewer than the
  51,592 phishing URLs. **You decided:** add 3,000 more Tranco sites — **done 2026-11-02**:
  +3,000 home pages and 1,379 link pages; legitimate URLs with snapshots now 54,100.
- 1 of 5 Tranco check sites timed out (facebook.com) from the container.
- `data/snapshot_check/` (5 test snapshots) can be deleted by hand; my delete was blocked.

**Approved choices:** Parquet; httpx, tldextract (offline PSL), dnspython, ssl, RDAP,
StratifiedGroupKFold; `ml/` as its own package; collector as a compose service.

## Phase 2 — Feature extractor F1–F140

**Status:** In progress (started 2026-11-02, built alongside the end of Phase 1; uses no real
split data, only hand-made test examples).
**Decided 2026-11-02:** P2-a…P2-f (missing = NaN, modality columns, Tranco leakage reported,
external dated lists, RDAP/Authentication-Results sources, NLP libraries) — `Docs/decisions.md`.

**Steps:**
- [x] Shared pieces: `missing.py` (NaN), `hosts.py` (offline host splitting, same as ml/)
- [x] F1–F45 `url_lexical.py`; lists for F26 (Interisle 2026 Table 2) and F27 (CC BY-SA
  shortener list, pinned commit) — 16 tests, every value hand-counted
- [ ] F46–F65 `domain_ssl.py` (stored RDAP / DNS / TLS; F65 always missing — you decided)
- [ ] F66–F95 `html_js.py`
- [ ] F96–F115 `email_headers.py`
- [ ] F116–F140 `nlp_text.py` (pyspellchecker, vaderSentiment after licence check)
- [ ] `extractor.py` (140 values in catalogue order), feature-matrix builder in `ml/`
- [ ] Missing-value rate per feature in the data card

**Decided 2026-11-02:** URLhaus only in the D2 blocklist baseline (removed from labelling and
`ti_score`); F65 always missing.

## Phase 5 — Backend API and database

**Status:** In progress (database part built early, 2026-11-02)

**What was built:**
- `backend/phishguard/models/`: 13 tables in `access.py`, `detection.py`, `simulation.py`,
  `experiments.py`; shared types and mixins in `base.py`; allowed values in `enums.py`.
- `backend/phishguard/core/crypto.py`: Fernet encryption and HMAC blind index for emails.
- `backend/phishguard/db/session.py` (engine, sessions, `get_db`), Alembic setup
  (`alembic.ini`, `phishguard/db/migrations/`), initial migration `b56beefdb0fc`.
- `Docs/database.md` (schema reference); new decisions in `Docs/decisions.md`.
- `make migrate`, `make test-db`; two new keys in `.env.example`.

**How to run:** `make migrate` (needs `docker compose up -d postgres`), `make test`,
`make test-db`.

**Test results (2026-11-02):**
- `make test`: backend 25 passed (crypto 5, models 14, plus earlier tests), dashboard 8 passed.
- `make test-db`: 1 passed — upgrade to head, models and database identical
  (`compare_metadata` empty), downgrade removes every table.
- `make lint`: clean. API container rebuilt; `/health` 200. Dev database at `b56beefdb0fc`.

**Known issues:**
- On this PC `localhost` tries IPv6 `::1` first and Docker does not answer it, so connections
  hang. `.env.example` and `.env` now use `127.0.0.1`.
- Cross-table rule "holdout template → usage sim_holdout" is left for the Phase 6 controller.

**Still open in Phase 5:** endpoints, inference service, Celery worker, feature-parity test,
latency measurement.
