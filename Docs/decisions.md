# Design decisions

Each entry: the decision, why, the main alternative and why it was not chosen.

## 2026-11-01 — D0: Repository layout

**Decision:** top-level folders `backend/` (API), `ml/` (offline training and evaluation),
`gateway/` (IMAP gateway), `frontend/` (`dashboard/`, `extension/`) and `Docs/`, with
`docker-compose.yml`, `Makefile` and `.env.example` at the repo root.

**Why:** each top-level folder is one deployable or runnable part of the system, so the
research pipeline (`ml/`) is kept apart from the live service while still sharing code with
it. Compose sits at the root because it starts services from several folders.

**Alternative:** putting `ml/` and `gateway/` inside `backend/`. Not chosen because training
code and its heavy dependencies would then be part of the API package and image.

## 2026-11-01 — MVC structure for the backend

**Decision:** `backend/phishguard/` uses models (SQLAlchemy tables), views (FastAPI routers)
and controllers (logic per resource), plus `schemas/` (Pydantic) and `services/` (feature
extractor, ML, threat intelligence, simulation).

**Why:** views only translate HTTP to function calls, so every controller can be unit-tested
without starting a web server, and the detection logic does not depend on FastAPI.

**Alternative:** putting logic directly in the route functions (the common FastAPI style).
Not chosen because it mixes HTTP handling with detection logic and makes the logic harder to
test and to reuse from `ml/` and `gateway/`.

## 2026-11-01 — `models/` means database tables only

**Decision:** ML models live in `phishguard/services/ml/`; trained model files live under
`data/` (gitignored); `phishguard/models/` holds only database tables.

**Why:** in MVC "model" is the data layer; using the same folder for ML models would give one
word two meanings in the code and in the thesis.

**Alternative:** a single `models/` folder for both. Not chosen because of that ambiguity.

## 2026-11-01 — Feature-based dashboard structure

**Decision:** `frontend/dashboard/src/features/` has one folder per menu item (overview,
detections, campaigns, models, experiments, threat-intel, settings, plus auth), and one
`shared/` folder for anything used by more than one feature. A feature may import only from
`shared/`; `shared/` never imports a feature. A test enforces this. TypeScript is used.

**Why:** each menu item can be built, changed or removed on its own, and the import rule
stops hidden dependencies between pages. TypeScript lets the API response types be checked
against the backend schemas at compile time.

**Alternative:** grouping by file type (`components/`, `pages/`, `hooks/` at the top).
Not chosen because the code for one screen would be spread over many folders.

## 2026-11-01 — Backend is an installable package named `phishguard`

**Decision:** `backend/` is installed with `pip install -e backend[dev]`; `ml/` and `gateway/`
import from `phishguard` (e.g. the feature extractor).

**Why:** CLAUDE.md requires one feature extractor shared by training and the live API;
importing one package guarantees both use the same code.

**Alternative:** copying the extractor into `ml/`. Not chosen because the two copies could
drift apart, which would silently make training features differ from live features.
