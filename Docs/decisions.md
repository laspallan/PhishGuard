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

## 2026-11-02 — LF line endings (`.gitattributes`)

**Decision:** `* text=auto eol=lf` for all text files.

**Why:** scripts and Makefiles run inside Linux containers, where Windows CRLF line endings
break them.

**Alternative:** git's Windows default (`core.autocrlf=true`). Not chosen because files
would differ between Windows checkouts and the containers.

## 2026-11-02 — Research dataset stays in files, not in the database

**Decision:** the 175,000 samples, snapshots, splits and feature matrices live under `/data/`
as hashed files. The database holds only what the running system produces (scans, model
versions, simulations, experiment results).

**Why:** a frozen, hashed split file makes it provable that the locked test set never
changes, and the database stays small.

**Alternative:** a `samples` table. Not chosen because it makes accidental queries on the
locked test set easy and would store large raw HTML in PostgreSQL.

## 2026-11-02 — UUID primary keys for every table

**Decision:** every `id` is a random UUID (version 4), generated in Python.

**Why:** ids can be created before the row is saved (useful for the gateway and Celery
tasks), and they cannot be guessed or counted from the outside, unlike 1, 2, 3...

**Alternative:** auto-increment integers. Not chosen because they leak volumes (e.g. how
many scans exist) and allow guessing other records' ids in API URLs.

## 2026-11-02 — Email addresses encrypted, with a blind index

**Decision:** admin and participant email addresses are encrypted with Fernet (from the
`cryptography` library) using `PHISHGUARD_ENCRYPTION_KEY`. Each also gets an HMAC-SHA256
"blind index" (`email_hash`) under a separate key, used for lookups and uniqueness.

**Why:** the proposal promises that personal data is encrypted. Fernet encryption is
randomised, so an encrypted column cannot be searched; the blind index makes login and
duplicate checks possible without decrypting every row.

**Alternative:** PostgreSQL `pgcrypto`. Not chosen because the key would be sent to the
database in every query and appear in its logs; encrypting in the application keeps the key
out of the database entirely.

## 2026-11-02 — Scans store a hash, not email content; verdict is part of the scan

**Decision:** for email scans only `input_hash`, `sender_domain` and the verdict are kept,
never the body or subject. Score, decision and explanation are columns of `scans`.

**Why:** emails are personal data even in a test mailbox, and the hash is enough to match a
scan to its message. Each scan has exactly one verdict, so a separate table adds only joins.

**Alternative:** storing full messages for later retraining. Not chosen for privacy; the
research dataset comes from the public corpora instead.

## 2026-11-02 — Enums stored as VARCHAR + CHECK constraint

**Decision:** enum columns use SQLAlchemy `Enum(native_enum=False, create_constraint=True)`.

**Why:** adding a new allowed value is a simple constraint change in a migration, and the
same schema works on SQLite for fast unit tests.

**Alternative:** native PostgreSQL `ENUM` types. Not chosen because changing them needs
special migration steps and they do not exist in SQLite.
