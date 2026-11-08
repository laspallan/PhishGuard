# Run from the repo root. On Windows, install make first (e.g. `winget install ezwinports.make`).
.PHONY: install test test-db test-text migrate lint format results up down gophish-cert

install:
	cd backend && python -m pip install -e ".[dev]"
	cd ml && python -m pip install -e ".[dev,train]"
	cd gateway && python -m pip install -r requirements.txt
	cd frontend/dashboard && npm install
	cd frontend/extension && npm install

test:
	cd backend && python -m pytest
	cd ml && python -m pytest
	cd gateway && python -m pytest
	cd frontend/dashboard && npm test
	cd frontend/extension && npm test

test-db:
	cd backend && python -m pytest -m postgres

# LSTM, CNN and DistilBERT code: needs PyTorch, so it runs in ml/.venv-text (see ml/README.md).
test-text:
	cd ml && env -u PYTHONHOME .venv-text/Scripts/python.exe -m pytest tests/test_text_models.py

migrate:
	cd backend && python -m alembic upgrade head

lint:
	cd backend && python -m ruff check . && python -m ruff format --check .
	cd ml && python -m ruff check . && python -m ruff format --check .
	cd gateway && python -m ruff check . && python -m ruff format --check .
	cd frontend/dashboard && npm run typecheck
	cd frontend/extension && npm run typecheck

format:
	cd backend && python -m ruff check --fix . && python -m ruff format .
	cd ml && python -m ruff check --fix . && python -m ruff format .
	cd gateway && python -m ruff check --fix . && python -m ruff format .

results:
	cd ml && python -m phishguard_ml results

up:
	docker compose up -d --build

down:
	docker compose down

# GoPhish admin certificate that names its hosts, so the API can check it (decisions.md, Phase 6).
# Needs openssl (ships with Git for Windows). Makes data/gophish/, which is gitignored.
gophish-cert:
	mkdir -p data/gophish/cert data/gophish/key
	MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/O=PhishGuard GoPhish" -addext "subjectAltName=DNS:gophish,DNS:localhost,IP:127.0.0.1" -keyout data/gophish/key/gophish_admin.key -out data/gophish/cert/gophish_admin.crt
