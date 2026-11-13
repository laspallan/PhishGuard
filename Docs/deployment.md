# Deploying PhishGuard on one machine

From a clean Windows machine to a running system: API, database, live URL scans, dashboard,
browser extension, email gateway and, only after ethics approval, simulations. Commands are
PowerShell from the repo root unless a step says otherwise. Everything listens on 127.0.0.1 only.

## 0. What you need

| Tool | Used for |
|---|---|
| Docker Desktop | Postgres, Redis, API, collectors, GoPhish, SpamAssassin |
| Python 3.11 | backend, ml pipeline, gateway (outside Docker) |
| Node.js 20+ and npm | dashboard and extension |
| Git for Windows | `openssl` (GoPhish certificate) and `make` (optional) |
| Chrome or Edge | the extension |

## 1. Settings

```powershell
Copy-Item .env.example .env
```

Fill in `.env` (never commit it):

- `PHISHGUARD_API_KEY`: `python -c "import secrets; print(secrets.token_urlsafe(32))"`
- `POSTGRES_PASSWORD`, and the same password in `PHISHGUARD_DATABASE_URL`
- `PHISHGUARD_ENCRYPTION_KEY` and `PHISHGUARD_EMAIL_HASH_KEY` (commands in `.env.example`; the
  Fernet one needs the `cryptography` package, so run it after step 2 installs it).
  **Back up the encryption key**: without it, stored participant addresses cannot be read.
- Optional: VirusTotal and AlienVault OTX keys (threat intelligence; without them `ti_score` is
  missing, never invented).

## 2. Install and test

```powershell
python -m venv backend\.venv
.\backend\.venv\Scripts\Activate.ps1
make install        # or the commands in Makefile, one by one
make test           # offline; nothing is contacted
```

PyTorch (text models) has its own environment; see `ml/README.md`. It is not needed to run the
system.

## 3. Database

```powershell
docker compose up -d postgres redis
cd backend; python -m alembic upgrade head; cd ..     # or: make migrate
```

Migrations run from the host because the API image does not contain Alembic's files.

## 4. Models

The API answers **503** to scans until trained models are in `data/models/` (it never guesses).
Either train them (`ml/README.md`, Phase 3: build the dataset, `features`, `train`, `report`), or
copy a `data/models/` folder made by that pipeline. `data/` is gitignored and never published.

## 5. API

```powershell
docker compose up -d --build api
curl.exe http://127.0.0.1:8000/health
curl.exe -H "X-API-Key: <your key>" http://127.0.0.1:8000/admin/status
```

The API container sees only `data/models` (read-only) and GoPhish's certificate, never the
stored phishing pages. API documentation: http://127.0.0.1:8000/docs.

**While the RQ2 lookups are being recorded** (`ti-record --daily`, section 10), do not let the API
use the same VirusTotal key: each process counts the 4-a-minute and 500-a-day limits on its own, so
together they can exceed them and RQ2 lookups would be refused. Set `PHISHGUARD_TI_OFFLINE=true` for
the API during those days, or give it a second key.

## 6. Live URL scans (decision D11)

```powershell
docker compose --profile live up -d --build evidence-collector
```

The evidence collector is the only part that contacts a scanned site (DNS, TLS, one page GET). It
has its own network with only Redis and the API, no secrets, no volume and a read-only file system.
Without it, URL scans use the URL features only.

## 7. Dashboard

```powershell
cd frontend\dashboard
Copy-Item .env.example .env.local      # VITE_API_BASE_URL=http://127.0.0.1:8000
npm run dev                            # http://localhost:5173
```

Sign in with `PHISHGUARD_API_KEY`; it stays in that browser tab only. If you open the dashboard
from another address, add it to `PHISHGUARD_DASHBOARD_ORIGINS` (the API allows only those origins).

## 8. Browser extension

```powershell
cd frontend\extension
npm run build
```

`chrome://extensions` (or `edge://extensions`), Developer mode, **Load unpacked**, choose
`frontend/extension/dist/`. In the toolbar popup enter `http://127.0.0.1:8000` and the API key.
Every visited http(s) URL is sent to this API, so point it only at your own PhishGuard.

## 9. Email gateway

Only a mailbox you control, or whose owner consented. The gateway reads its own `gateway/.env` (not
the root `.env`), with the `PHISHGUARD_GATEWAY_*` settings listed in `gateway/README.md`: IMAP
server, user, password, API address (`http://127.0.0.1:8000`) and the API key.

```powershell
cd gateway
python imap_gateway.py
```

Mail is read without marking it read; block moves it to the quarantine folder, warn flags it.

## 10. Research data collection (optional)

```powershell
docker compose --profile collect up -d collector            # daily fresh phishing URLs (RQ3)
cd ml; python -m phishguard_ml ti-record --daily            # RQ2 lookups (needs both TI keys)
```

Phishing pages are fetched only inside the collector container, with plain GET: no JavaScript,
no form submission, no downloads.

## 11. Simulations: only after university ethics approval

Nothing can be sent until `PHISHGUARD_ETHICS_APPROVAL_REF` is set, and only consenting
participants can be targeted. Landing pages are always PhishGuard's explanation page (no form).

1. Make GoPhish's admin certificate (its own has no host name, so it could not be checked):
   ```powershell
   make gophish-cert      # -> data/gophish/cert/ and data/gophish/key/ (gitignored)
   ```
2. Start GoPhish and read the first admin password from its log:
   ```powershell
   docker compose --profile simulate up -d gophish
   docker compose --profile simulate logs gophish | Select-String password
   ```
3. Sign in at https://127.0.0.1:3333 (the browser warns about the certificate; it is ours), change
   the password, then copy the API key from **Settings** into `PHISHGUARD_GOPHISH_API_KEY`.
4. In GoPhish, create a **Sending Profile** for the study's mail account. Its name is what the
   dashboard asks for as "GoPhish sending profile".
5. In `.env`: `PHISHGUARD_SIMULATION_CONTACT_EMAIL`, and, once the university has approved,
   `PHISHGUARD_ETHICS_APPROVAL_REF`. Restart the API: `docker compose up -d api`.
6. In the dashboard, **Simulation**: templates (fictional organisation only), participants (signed
   consent), a draft campaign, then Launch, Fetch events, Complete. The **Campaigns** page shows
   totals only.

> **⚠️ GoPhish state is not persisted.** Only the cert and key files are mounted; `gophish.db`
> (the admin password, the API key, and every sending profile / template / campaign created inside
> GoPhish) lives in the container's writable layer. Do **not** run `docker compose down`, or remove
> or recreate the `gophish` container, while a round is live — it resets the first-boot password and
> API key, and steps 2–4 above (and `PHISHGUARD_GOPHISH_API_KEY` in `.env`) must be redone. To make
> this safe long-term, add a named volume for `/opt/gophish/gophish.db` at a planned moment (it
> starts empty, so the key is regenerated once after the switch). See `Docs/simulation_runbook.md`.

Checked on 2026-11-08 against real GoPhish 0.12.1 in a local container with a closed SMTP port and
a `.test` address (no email could leave): launch, the explanation page (no form, capture off),
fetching events and completing all worked through the real API code, with the certificate checked.

## 12. Ports

| Port (127.0.0.1) | Service |
|---|---|
| 8000 | API |
| 5173 | dashboard (dev server) |
| 5432 | Postgres |
| 6379 | Redis: not published; only with `docker-compose.dev.yml`, for running the API on the host |
| 3333 / 8088 | GoPhish admin / landing pages (`--profile simulate` only) |

## 13. Stopping and backups

```powershell
docker compose --profile live --profile collect --profile simulate --profile baseline down
```

`down` keeps the Postgres database volume (`pgdata`); `down -v` deletes it with every stored scan
and participant, so do not use `-v` during the study. **It does not preserve GoPhish's `gophish.db`**
(see the warning in section 11): bringing the `gophish` container down and up again during a round
resets its admin password, API key, profiles and templates. Back up `.env` (above all the encryption
key) and `data/` outside the repository.
