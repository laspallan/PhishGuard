# Progress

Status of each phase. A phase is marked Done only after every acceptance check in
`Docs/IMPLEMENTATION_PLAN.md` has been verified (see the phase-completion rule).

## Phase 0 — Environment, repository and skeleton

**Status:** In progress

**What was built:**
- Root: `.gitignore`, `.env.example`, `docker-compose.yml` (postgres, redis, api), `Makefile`,
  `README.md`, `PROGRESS.md`.
- `backend/`: MVC package `phishguard` (`core/`, `models/`, `schemas/`, `views/`,
  `controllers/`, `services/{features,ml,intel,simulation}/`, `db/`, `workers/`),
  `GET /health`, `Dockerfile`, `README.md`, tests.
- `frontend/dashboard/`: React + Vite + TypeScript + Tailwind, feature folders (`overview`,
  `detections`, `campaigns`, `models`, `experiments`, `threat-intel`, `settings`, `auth`),
  `shared/` (layout, sidebar, page header, API client, types), tests.
- `frontend/extension/`, `ml/`, `gateway/`: folders and READMEs (code comes in later phases).
- `Docs/`: `features.md` (generated from Appendix A), `decisions.md`, `data_card.md`
  template, `devlog/`.

**How to run:** see `README.md` (quick start) and each module README.

**Test results (2026-11-01, run by Claude in a scratch environment):**
- backend: `pytest` 6 passed (health controller, health view, 4 feature-catalogue checks);
  `ruff check` and `ruff format --check` passed.
- dashboard: `npm run typecheck` passed; `npm test` 8 passed; `npm run build` succeeded.
  The import-rule test was checked to fail on a deliberate cross-feature import.

**Acceptance checks still open:**
- [ ] `make lint` and `make test` pass on a clean clone (make not installed yet)
- [ ] `docker compose up` starts Postgres and Redis healthy (Docker not installed yet)
- [ ] Feature-catalogue test passes in the user's environment
- [ ] `GET /health` returns 200 in the user's environment
- [ ] Ethics-approval request sent

**Known issues:**
- pytest prints a Starlette deprecation warning recommending `httpx2` for the TestClient;
  harmless for now, to be checked before switching.
- npm did not run esbuild's install script (npm `allowScripts`); the build still works.

**Decisions made:** D0 layout, backend MVC, `models/` = DB tables only, installable
`phishguard` package, feature-based dashboard (see `Docs/decisions.md`).

**Next phase needs to know:** decisions D1, D3 and D4 must be settled before Phase 1 starts.
