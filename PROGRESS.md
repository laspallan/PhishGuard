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

**Status:** Not started. Decisions D1 (category labelling), D3 (URL/email split) and D4
(grouping key) were deferred on 2026-11-02 and must be settled before this phase starts.

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
