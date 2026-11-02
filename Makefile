# Run from the repo root. On Windows, install make first (e.g. `winget install ezwinports.make`).
.PHONY: install test test-db migrate lint format up down

install:
	cd backend && python -m pip install -e ".[dev]"
	cd ml && python -m pip install -e ".[dev]"
	cd frontend/dashboard && npm install

test:
	cd backend && python -m pytest
	cd ml && python -m pytest
	cd frontend/dashboard && npm test

test-db:
	cd backend && python -m pytest -m postgres

migrate:
	cd backend && python -m alembic upgrade head

lint:
	cd backend && python -m ruff check . && python -m ruff format --check .
	cd ml && python -m ruff check . && python -m ruff format --check .
	cd frontend/dashboard && npm run typecheck

format:
	cd backend && python -m ruff check --fix . && python -m ruff format .
	cd ml && python -m ruff check --fix . && python -m ruff format .

up:
	docker compose up -d --build

down:
	docker compose down
