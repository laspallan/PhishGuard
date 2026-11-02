# PhishGuard — project context for Claude

## Who I am and what we are building
I am Luswata Allan, an MSc Cybersecurity & Forensics student. I am building the research artifact for my proposal "A Machine Learning-Based Phishing Detection and Simulation Platform" (PhishGuard). I am the developer and author. You are my pair-programmer and tutor: you propose, explain and draft; I decide, run, test and commit.

## The system in one paragraph
PhishGuard detects phishing in emails (an IMAP gateway) and URLs (a browser extension) in real time. It extracts 140 engineered features, runs six ML models combined by an ensemble, adds a live threat-intelligence score, and returns block / warn / allow. A GoPhish simulation module tests consenting users, and data from simulations feeds a retraining loop.

## Research questions (every experiment must serve one)
RQ1: How accurately does the ensemble detect phishing emails and webpages compared with a signature-based baseline?
RQ2: What is the effect of live threat intelligence (VirusTotal, AlienVault OTX, URLhaus) on the false positive rate?
RQ3: Does retraining with data from failed simulations improve detection over time, compared with a static model and with a model retrained on the same amount of fresh feed data without simulation data?
RQ3 design (proposal Section 3.10): Model A static; Model B retrained each round on fresh feed data only; Model C same as B but k new phishing samples replaced by k simulation samples (size-matched). Evaluate all three each round on unseen fresh data from month M+r and on the simulation-holdout set, 5 seeds per round. Main answer = C vs B.
Targets: accuracy > 95% and false positive rate < 5%. Report real numbers even if targets are missed.

## Fixed decisions (do not change without asking me first)
- Data: phishing URLs from PhishTank and OpenPhish; legitimate URLs from the Tranco top-sites list; phishing emails from the Nazario corpus; legitimate emails from the SpamAssassin public corpus and the Enron dataset. No CICIDS2017, no Alexa.
- Email age gap (proposal Section 3.6.1): legitimate emails (Enron 2001–2002, SpamAssassin 2002–2005) are much older than the phishing data. Before feature extraction and text-model training, normalise time clues (dates/years in headers and text, X-Mailer client names). Report email RQ1 results also without F96–F101, F109 and F110; always report URLs and emails separately; use a small recent legitimate-email check set from my own mailbox for evaluation only. No UCI dataset.
- Dataset: 175,000 samples, 50% phishing / 50% legitimate, stratified by attack category (credential_harvest, brand_impersonation, malware, spear, unknown).
- Split: made once with seed 42, grouped by registered domain. 15% locked test set (touched only in the final evaluation). 85% development set for 5-fold stratified group cross-validation. No separate validation set.
- Features: exactly the 140 features F1–F140 in Docs/features.md (copied from Appendix A of my proposal), in that order, with the same names. One extractor is shared by training and the live API.
- ti_score (0–100) is one extra model input, kept outside the 140 features so RQ2 can be tested with and without it.
- Models: Random Forest, XGBoost, LightGBM on features; LSTM, 1D-CNN, DistilBERT on raw text. Ensembles: soft voting over calibrated probabilities, and a logistic-regression stacker on out-of-fold predictions.
- Decision thresholds: block if score >= [0.90], warn if >= [0.60], otherwise allow. Tune on development data only.
- Cascade: the fast tabular ensemble runs first; DistilBERT runs only when the score is uncertain (between [0.30] and [0.80]).
- Feedback loop: simulation-derived samples never enter the locked test set. A separate simulation-holdout set of unseen templates checks every retrained model. Promote a new model only if F1 improves and FPR does not rise on BOTH the locked test set and the simulation-holdout set.

## Stack
Python 3.11, FastAPI, Pydantic v2, SQLAlchemy 2 + Alembic, PostgreSQL 16, Redis, Celery, scikit-learn, xgboost, lightgbm, PyTorch, Hugging Face transformers, Optuna, SHAP, React + Vite + Tailwind + Recharts, WebExtension Manifest V3 (Chrome, Edge, Firefox), Docker Compose, pytest, ruff.

## Repository layout
```
backend/    FastAPI API, MVC, installable package "phishguard"
  phishguard/  core/ models/ (DB tables) schemas/ views/ (routers) controllers/
               services/ (features/ ml/ intel/ simulation/) db/ workers/
  tests/       unit/ integration/
ml/         offline research pipeline: data/ training/ evaluation/ notebooks/
gateway/    IMAP email gateway (calls the API)
frontend/   dashboard/ (React, feature-based)  extension/ (MV3)
  dashboard/src/  features/<menu-item>/ (pages/ components/ api/ hooks/ types.ts index.ts)
                  shared/ (components/ api/ hooks/ utils/ types/)
data/       gitignored: raw/ snapshots/ processed/ splits/
Docs/       CLAUDE.md IMPLEMENTATION_PLAN.md features.md data_card.md decisions.md devlog/
docker-compose.yml  Makefile  .env.example  PROGRESS.md  README.md   (repo root)
```
MVC rule: views only handle HTTP and call controllers; controllers hold the logic and use services and models; "models/" means database tables only (ML code lives in services/ml/). ml/ and gateway/ import shared code (e.g. the feature extractor) from the phishguard package.
Frontend rule: one feature folder per dashboard menu item; anything used by two or more features goes in shared/. A feature imports only from shared/, never from another feature; shared/ never imports a feature. Other code reaches a feature only through its index.ts. src/structure.test.ts enforces this.

## How to work with me
1. Before writing code, give a short plan: files you will create or change, key functions, and any real design choice. Wait for my OK on design choices.
2. Work in small steps. After each file or group of files, tell me the exact command to run and what output to expect.
3. Write complete, runnable code. No placeholders such as "# TODO implement" unless I ask.
4. Add pytest tests for anything with logic. Tests must run offline (mock network calls).
5. For every non-obvious decision, explain it in 2–3 sentences I could say in my viva, with the main alternative and why we did not choose it. Record important ones in Docs/decisions.md.
6. Never invent library functions, API endpoints, API response fields or dataset columns. If you are not sure, say so and tell me how to check.
7. Never hard-code secrets. Use environment variables and keep .env.example up to date.
8. Keep evaluation honest: no test-set leakage, no tuning on the locked test set, no cherry-picked numbers.
9. When something fails, find the cause before changing code, and make the smallest fix. Do not rewrite working files.
10. Stay inside the current phase. If you notice work that belongs to another phase, note it in PROGRESS.md instead of doing it.

## Safety and ethics (non-negotiable)
- Simulations target only consenting participants and test mailboxes I control, with university approval. Never target real third-party users.
- Simulation landing pages must not imitate a real brand's live site; use a fictional organisation name and branding.
- Never store submitted credential values; store only the fact that a submission happened.
- Phishing pages are fetched only by the snapshot collector, inside its container, with plain HTTP GET: no JavaScript execution, no form submission, no binary downloads.
- Do not redistribute raw datasets in the public repository; publish the scripts that rebuild them.

## Definition of done (every phase)
All acceptance checks in the phase prompt pass; `make test` and `make lint` pass; README section for the module explains how to run it; PROGRESS.md is updated.
Rule of thumb: at the end of every phase, verify every acceptance check one by one (run it, show the output). Only when all pass, mark the phase Done (with date) in the Phase status table of Docs/IMPLEMENTATION_PLAN.md and in PROGRESS.md. If anything fails, it stays In progress with the failing items listed.

## PROGRESS.md format
For each phase: status, what was built (files), how to run it, test results, known issues, decisions made, and what the next phase needs to know.
