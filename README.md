# PhishGuard

A machine learning-based phishing detection and simulation platform (MSc Cybersecurity &
Forensics research artifact). It detects phishing in emails (IMAP gateway) and URLs
(browser extension) with an ensemble of six ML models plus live threat intelligence, and
runs consenting-user phishing simulations whose results feed a retraining loop.

## Repository layout

```
backend/     FastAPI API (MVC), Python package "phishguard"
ml/          offline data, training and evaluation pipeline
gateway/     IMAP email gateway
frontend/    dashboard/ (React, feature-based)  extension/ (MV3)
Docs/        proposal, CLAUDE.md, implementation plan, features, decisions, data card, devlog
data/        local datasets and artefacts (gitignored; rebuilt by scripts)
```

## Quick start (PowerShell)

```powershell
Copy-Item .env.example .env          # then edit the values

# Backend
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m pytest
cd ..

# Dashboard
cd frontend\dashboard
npm install
npm test
cd ..\..

# All services (needs Docker Desktop)
docker compose up -d --build
```

Module details: [backend](backend/README.md), [dashboard](frontend/dashboard/README.md),
[ml](ml/README.md), [gateway](gateway/README.md), [extension](frontend/extension/README.md).

Full deployment walkthrough (API, live scans, dashboard, extension, gateway, simulations):
[Docs/deployment.md](Docs/deployment.md).

Build plan and status: [Docs/IMPLEMENTATION_PLAN.md](Docs/IMPLEMENTATION_PLAN.md).
Progress log: [PROGRESS.md](PROGRESS.md).

## Data and ethics

Raw datasets are not included; the scripts in `ml/data/` rebuild them. Simulations only
target consenting participants and mailboxes I control, with university approval, and
submitted credential values are never stored.
