# PhishGuard backend

FastAPI service that scans URLs and emails and returns block / warn / allow.
It is also the `phishguard` Python package, so `ml/` and `gateway/` can import shared
code such as the feature extractor.

## Structure (MVC)

```
phishguard/
  main.py        builds the FastAPI app and registers the views
  core/          configuration (env vars), logging, security
  models/        M - SQLAlchemy database tables (only; ML code is in services/ml/)
  schemas/       Pydantic request/response shapes
  views/         V - FastAPI routers: HTTP only, delegate to controllers
  controllers/   C - logic per resource; use services and models
  services/      features/ ml/ intel/ simulation/ engines
  db/            engine, sessions, migrations
  workers/       Celery tasks
tests/
  unit/          controllers and services, no HTTP
  integration/   views through FastAPI's TestClient
```

A request flows: **view** → **controller** → services / models → **schema** → response.

## Run locally (PowerShell, from `backend/`)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check .
python -m ruff format --check .
uvicorn phishguard.main:app --reload
```

Then open http://127.0.0.1:8000/health or http://127.0.0.1:8000/docs.

## Run with Docker (from the repo root)

```powershell
Copy-Item .env.example .env   # then edit the values
docker compose up -d --build
```

## Database

Schema reference: [`Docs/database.md`](../Docs/database.md). Tables are SQLAlchemy models in
`phishguard/models/`; changes go only through Alembic migrations in
`phishguard/db/migrations/versions/`.

```powershell
docker compose up -d postgres                              # from the repo root
python -m alembic upgrade head                             # apply migrations (or: make migrate)
python -m alembic revision --autogenerate -m "describe"    # after changing a model; review it!
python -m pytest -m postgres                               # migration test (or: make test-db)
```

`make test` runs the model tests on in-memory SQLite (no Docker needed). `make test-db`
checks the migrations against real PostgreSQL in a throwaway database.

Use `127.0.0.1`, not `localhost`, in `PHISHGUARD_DATABASE_URL` on Windows: `localhost` tries
IPv6 `::1` first, which Docker Desktop does not answer, and the connection hangs.

## Configuration

All settings come from environment variables with the `PHISHGUARD_` prefix; see
`../.env.example`. No secrets are stored in code. `PHISHGUARD_ENCRYPTION_KEY` and
`PHISHGUARD_EMAIL_HASH_KEY` are required to read or write email addresses; losing the
encryption key makes stored emails unreadable, so keep a safe backup of it.

## Features F1–F140 (Phase 2)

`phishguard/services/features/` computes the 140 features of `Docs/features.md`, in that order.
Training (`ml/`) and the live API call the same function:

```python
from phishguard.services.features.extractor import UrlEvidence, email_features, url_features
url_features(UrlEvidence(url=..., captured_at=..., html=..., dns=..., tls=..., rdap=...), ranks)
email_features(raw_email, ranks)    # ranks: Tranco registered domain -> rank
```

| Module | Features | Reads |
|---|---|---|
| `url_lexical.py` | F1–F45 | the URL string |
| `domain_ssl.py` | F46–F65 | stored RDAP / DNS / TLS (F65 always missing) |
| `html_js.py` | F66–F95 | stored page HTML (read as text, never run) |
| `email_headers.py` | F96–F115 | the raw email |
| `nlp_text.py` | F116–F140 | the time-normalised email (`email_normalise.py`) |

Missing value = NaN (`missing.py`); URL records have F96–F140 missing, emails F1–F95. Word
lists are in `lexicons.py`; external lists and their licences in `data/README.md`. Every
definition choice is written at the top of its module. `extractor.feature_code_hash()` changes
whenever any feature code or list changes; it is stored with the feature matrix.
