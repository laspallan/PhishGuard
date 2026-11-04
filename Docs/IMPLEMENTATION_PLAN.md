# PhishGuard — Implementation Plan

This is the build guide for the PhishGuard research artifact. It turns the proposal
(`Proposal_PhishGuard_revised.docx`) and the working rules in `CLAUDE.md` into ten phases
that we follow in order. Each phase has a goal, the research question it serves, what gets
built, acceptance checks, and a prompt to start the phase with Claude.

**Order of authority:** proposal → `CLAUDE.md` → this plan. If they disagree, the proposal
wins and this plan is corrected. Decisions marked **OPEN** must be settled (and recorded in
`docs/decisions.md`) before the phase that needs them starts.

---

## 0. Phase status

A phase is marked **Done** only after every acceptance check in its section has been run
and verified (plus `make test`, `make lint`, README section and `PROGRESS.md`). Until then
it stays **In progress**, with the unchecked items listed.

| Phase | Status | Verified on | Notes |
|---|---|---|---|
| 0 Environment and skeleton | **Done** | 2026-11-02 | All acceptance checks verified (see PROGRESS.md). Carried forward: send the ethics-approval request (your action; needed before Phase 6) |
| 1 Data and split | In progress | | Code, Enron and snapshots done. Before Done: RDAP finish, label/count/datacard, real split, live collector. See PROGRESS.md |
| 2 Feature extractor | In progress | | F1–F140 built and tested (2026-11-02); extractor, matrix, data-card rates to do |
| 3 Models, ensembles, baseline | In progress | | Step 1 (dev loader, tabular models) built on synthetic data 2026-11-03 |
| 4 Threat intelligence, RQ2 | In progress | | Clients, rate limits, cache, recorder (2026-11-04). Open: ti_score formula, subset, RQ2 |
| 5 Backend API and DB | In progress | | DB schema, migration and model tests built early (2026-11-02, see `Docs/database.md`). Still open: endpoints, inference service, Celery worker, parity and latency checks |
| 6 Simulation, feedback loop, RQ3 | Not started | | |
| 7 Extension and gateway | In progress | | Extension and IMAP gateway built and tested (2026-11-04). Open: D6, end-to-end with a model |
| 8 Dashboard, final evaluation | Not started | | |
| 9 Write-up | Not started | | |

---

## 1. Summary of what we are building

| Part | What it does | Serves |
|---|---|---|
| Data pipeline | Collects, cleans, de-duplicates and splits 175,000 samples; collects fresh data monthly | RQ1–RQ3 |
| Feature extractor | Computes F1–F140 (Appendix A), one code path for training and the live API | RQ1 |
| ML engine | RF, XGBoost, LightGBM (features); LSTM, 1D-CNN, DistilBERT (raw text); soft-voting and stacking ensembles; cascade | RQ1 |
| Signature baseline | The comparison system for RQ1 | RQ1 |
| Threat-intelligence service | VirusTotal + AlienVault OTX → `ti_score` 0–100, cached (URLhaus only in the D2 baseline: its terms forbid AI training) | RQ2 |
| Backend API + DB | FastAPI, PostgreSQL, Redis, Celery; returns block / warn / allow | all |
| Simulation module | GoPhish campaigns to consenting users; records clicks and the *fact* of submissions | RQ3 |
| Feedback loop + RQ3 harness | Retrains Models A/B/C per round, promotion rule, statistics | RQ3 |
| Browser extension | MV3 for Chrome, Edge, Firefox; checks URLs in real time | delivery |
| Email gateway | IMAP gateway that scans incoming mail | delivery |
| Dashboard | React admin UI: detections, campaigns, model versions, metrics | delivery |

Targets: accuracy > 95%, FPR < 5%. Real numbers are reported even if targets are missed.

---

## 2. Open decisions (settle before the phase that needs them)

| ID | Decision | Needed by | Recommendation (not yet agreed) |
|---|---|---|---|
| D0 | Repository layout. | Phase 0 | **Decided 2026-11-01:** top-level `backend/` (MVC API), `ml/`, `gateway/`, `frontend/` (`dashboard/`, `extension/`), `Docs/`; `docker-compose.yml` at the repo root. See `Docs/decisions.md`. |
| D1 | Attack-category labelling rules. | Phase 1 | **Decided 2026-11-02:** ordered rules (malware → brand_impersonation → credential_harvest → spear → unknown), documented in `data_card.md`. See `Docs/decisions.md`. |
| D2 | What the RQ1 "signature-based baseline" is. Not defined in the proposal. | Phase 3 | **Decided 2026-11-02:** URLs: lookup against a blocklist snapshot (PhishTank/OpenPhish/URLhaus) taken *before* the sample's collection date. Emails: SpamAssassin rule score (rules only, Bayes off). |
| D3 | How the 175,000 samples split between URLs and emails. | Phase 1 | **Decided 2026-11-02:** largest balanced set available at split time (≈120k expected; 175k not reachable with the public email corpora), each modality 50/50. See `Docs/decisions.md`. |
| D4 | Grouping key for the split. | Phase 1 | **Decided 2026-11-02:** URLs by registered domain (eTLD+1); emails by sender address (Enron: mailbox owner). See `Docs/decisions.md`. |
| D5 | One set of six models for both modalities, or separate URL and email models. | Phase 3 | **Decided 2026-11-02:** separate per modality (the features and the text inputs are different), still six model *types*. |
| D6 | Visual-similarity check in the extension (promised in Gap 3 / Table 2.3, but no feature or model covers it). | Phase 7 | Perceptual-hash comparison of a page screenshot / favicon against a small set of fictional and protected brand references, used as a warning signal, outside the 140 features. Or drop it and state it as a limitation. |
| D7 | How `ti_score` is obtained for the training data. Free VirusTotal limits make 175k lookups impossible, and URLs taken *from* PhishTank are likely to be in TI feeds already (circular). | Phase 4 | **Decided 2026-11-02:** record TI responses at collection time only; compute `ti_score` for a stratified subset that fits the API limits; run RQ2 on that subset; discuss the circularity as a threat to validity. Check current API limits in each provider's docs. |
| D8 | Start date, so the 24-week timeline has real dates. | Phase 0 | Fill in Section 5. |
| D9 | **Decided 2026-11-02: option (a).** The proposal says phishing URLs cover 2021–2026, but the free feeds list only URLs online *now* — **confirmed 2026-11-02**: PhishTank's developer page says its files contain "only online phishes"; OpenPhish's free feed has no archive (its 30-day archive needs the Academic Use Program). Option (a): keep the sources and reword to "collected from <start date> onward"; (b): add an archived phishing-URL dataset (changes the fixed source list). | Before step 8 of Phase 1 (split) | (a). Finding 2026-11-02: PhishTank submission dates already span 2021–2026 (see `Docs/decisions.md`). |
| D10 | **Decided 2026-11-02: (a) + (c).** Legitimate URLs from Tranco are home pages only; phishing URLs have paths, so URL shape alone separates the classes. | Before step 8 of Phase 1 (split) | (a) add same-site links from Tranco pages during snapshotting, plus (c) report URL results with and without path features. See `Docs/decisions.md`. |
| D11 | Live URL scanning without the API fetching pages (evidence collector, two stages, deployed feature set, rebinding fix). | Phase 5 | Proposal in `Docs/live_url_scanning.md` (2026-11-05), section 8: D11a–D11f. **Not yet agreed.** |

---

## 3. Rules that apply to every phase

- Plan first: list files, key functions, and design choices; wait for approval on choices.
- Small steps; after each file group, give the command to run and the expected output.
- Complete, runnable code; pytest tests for all logic; tests run offline (network mocked).
- No secrets in code; `.env.example` kept current.
- Locked test set is touched **only** in Phase 8. No tuning on it. Simulation samples never enter it.
- Never invent library functions, API endpoints, response fields or dataset columns; check docs when unsure.
- Fix failures at the cause, smallest change, no rewrites of working files.
- Stay in the phase; note other-phase work in `PROGRESS.md`.
- Non-obvious decisions → 2–3 sentence viva explanation with the main alternative, recorded in `docs/decisions.md`.
- **Done** = acceptance checks pass, `make test` and `make lint` pass, module README section written, `PROGRESS.md` updated.
- **Phase-completion rule:** at the end of every phase, go through its acceptance checks one by one and verify each (run the command, show the output). Only when all pass is the phase marked Done in Section 0 with the date. If any fail, the phase stays In progress and the failing items are listed.

### Safety and ethics (non-negotiable)
- Simulations only for consenting participants and test mailboxes I control, after university approval.
- Landing pages use a fictional organisation; never imitate a real brand's live site.
- Never store submitted credential values; store only that a submission happened.
- Phishing pages are fetched only by the snapshot collector, in its container, plain HTTP GET: no JavaScript, no form submission, no binary downloads.
- Raw datasets are not published; only the scripts that rebuild them.

---

## 4. Phases

### Phase 0 — Environment, repository and skeleton (weeks 1–2)

**Goal:** a repository anyone can clone and run `make test` / `make lint` on.

**Build:**
- Repo layout (D0):
  ```
  backend/    pyproject.toml Dockerfile README.md
              phishguard/  core/ models/ schemas/ views/ controllers/
                           services/{features,ml,intel,simulation}/ db/ workers/
              tests/       unit/ integration/
  ml/         data/ training/ evaluation/ notebooks/
  gateway/
  frontend/   dashboard/ extension/
  data/       raw/ snapshots/ processed/ splits/      (gitignored)
  Docs/       CLAUDE.md IMPLEMENTATION_PLAN.md features.md data_card.md decisions.md devlog/
  docker-compose.yml  Makefile  .env.example  .gitignore  PROGRESS.md  README.md
  ```
- `backend/pyproject.toml` (Python 3.11, ruff, pytest config).
- `docker-compose.yml`: `api`, `postgres:16`, `redis`. The `snapshot` collector is added in Phase 1 and the Celery `worker` in Phase 5, when their code exists.
- `Makefile`: `test`, `lint`, `format`, `up`, `down`.
- `.gitignore` covering `data/`, `.env`, model artefacts, `node_modules/`.
- `Docs/features.md`: F1–F140 copied exactly from Appendix A (ID, name, group, description, same order).
- `Docs/decisions.md`, `Docs/data_card.md` (empty template), `Docs/devlog/` (AI-assistance log, required by the proposal's ethics section).
- `PROGRESS.md` with the format from `CLAUDE.md`.
- Start the university ethics-approval request now (simulations in Phase 6 depend on it).

**Acceptance checks:**
- `make lint` and `make test` pass on a clean clone (one smoke test).
- `docker compose up` starts Postgres and Redis healthy.
- `Docs/features.md` has exactly 140 rows, F1…F140, names identical to Appendix A (a test checks this).
- `GET /health` returns 200 through the view → controller → schema path (MVC smoke test).

**Prompt:**
> Phase 0. Read CLAUDE.md and docs/IMPLEMENTATION_PLAN.md. Propose the files for the repo skeleton (layout per decision D0), pyproject, Makefile, docker-compose, .env.example, and docs/features.md from Appendix A. Wait for my OK, then build it in small steps.

---

### Phase 1 — Data acquisition, cleaning and split (weeks 3–5)

**Goal:** a balanced, de-duplicated, stratified dataset and a fixed split. **Serves:** RQ1–RQ3.

**Build (`ml/data/`):**
- Downloaders: PhishTank, OpenPhish, Tranco, Nazario, SpamAssassin public corpus, Enron. Each stores raw files under `data/raw/<source>/<date>/` with a manifest (URL, date, checksum).
- Snapshot collector (container `snapshot`): for each URL fetches HTML, WHOIS, DNS and TLS details **at collection time** with plain GET and size/time limits, stored under `data/snapshots/`. Phishing pages die in hours, so later fetching is not possible.
- Common record format: `sample_id, sample_type (url|email), raw_content, label, attack_category, source, source_date, collected_at, group_key, content_hash, snapshot_ref`.
- Cleaning: normalise URLs, parse emails, drop broken entries, de-duplicate by hash of normalised URL / email body.
- Email age-gap handling (proposal §3.6.1): normaliser for dates/years in headers and body and X-Mailer names, applied before feature extraction and text-model training.
- Attack-category labeller (D1).
- Sampler: 175,000 samples, 50/50, stratified by category (D3 for the URL/email mix).
- Splitter: seed 42, grouped by `group_key` (D4), 15% locked test / 85% development; 5-fold stratified group CV fold IDs on development. Split files are written once and hashed; a test fails if they change.
- Monthly collector: new phishing + legitimate URLs with collection date, stored by month for RQ3. Never alters the locked test set.
- Recent legitimate-email check set: script to load my own exported mailbox samples (personal content removed) as an **evaluation-only** set.
- `docs/data_card.md`: sources, licences, counts per source/category/label, date ranges, missing-snapshot rates, known biases (email age gap).

**Acceptance checks:**
- Final counts match the target and the 50/50 balance; per-category counts in the data card.
- No `group_key` appears on both sides of the split; no `content_hash` appears twice.
- Test set ≈ 15%, CV folds stratified; split is reproducible from seed 42.
- Monthly collector runs as a scheduled job and writes a dated batch.
- Tests run offline against small fixture files.

**Prompt:**
> Phase 1. Decisions D1, D3, D4 are now: <...>. Propose the data pipeline modules, the record schema and the snapshot collector design. First tell me exactly which fields each source provides and how I can verify them.

---

### Phase 2 — Feature extractor F1–F140 (weeks 6–8)

**Goal:** one extractor, used by training and the live API, that produces exactly F1–F140 in order. **Serves:** RQ1.

**Build (`backend/features/`):**
- Group modules: `url_lexical.py` (F1–F45), `domain_ssl.py` (F46–F65, reads snapshot data, never live network during training), `html_js.py` (F66–F95), `email_headers.py` (F96–F115), `nlp_text.py` (F116–F140).
- `extractor.py`: takes a record (+ snapshot), returns a 140-length vector with names from `docs/features.md`; non-applicable features get one fixed missing value.
- Shared word lists (brands, urgency, threat, reward, credential, sensitive URL words, risky TLDs/extensions, shorteners) in versioned data files.
- Feature-matrix builder for the whole dataset, saved to `data/processed/`.
- Age-sensitive feature list (F96–F101, F109, F110) exposed so evaluation can drop them.

**Acceptance checks:**
- A test asserts the output names and order equal `docs/features.md`.
- Every feature has at least one unit test with a hand-checked example.
- Training path and API path call the same function (test imports both).
- Missing-value rate per feature reported in the data card.

**Prompt:**
> Phase 2. Propose the extractor structure and the missing-value convention. Build one feature group at a time with tests, starting with F1–F45.

---

### Phase 3 — Models, ensembles, baseline and development evaluation (weeks 9–12)

**Goal:** trained, tuned, calibrated models and ensembles, evaluated with CV on the development set only. **Serves:** RQ1.

**Build (`ml/training/`, `ml/evaluation/`, `backend/models/`):**
- Tabular models: RF, XGBoost, LightGBM on F1–F140 (± `ti_score` later in Phase 4). Optuna tuning inside 5-fold group CV.
- Text models: LSTM and 1D-CNN (PyTorch) and DistilBERT (Hugging Face) on raw URL / normalised email text (D5).
- Out-of-fold predictions saved for every model.
- Probability calibration on OOF predictions.
- Ensembles: soft voting over calibrated probabilities; logistic-regression stacker trained on OOF predictions.
- Cascade: tabular ensemble first; DistilBERT only if score is in [0.30, 0.80].
- Thresholds: block ≥ 0.90, warn ≥ 0.60, tuned on development OOF data only.
- Signature baseline (D2).
- Evaluation module: accuracy, precision, recall, F1, FPR; per modality; with and without F96–F101/F109/F110 for email; URL results also without the URL-path features (decision D10c); URL results also without the RDAP features F46–F52 (missing registration data differs by class); FPR on the recent legitimate-email check set; bootstrap 95% CIs; McNemar test; SHAP summaries for tabular models.
- Model registry: versioned artefacts with metadata (data hash, features hash, seed, metrics).

**Acceptance checks:**
- No code path reads the locked test set (test enforces this).
- CV results table for all six models, both ensembles, the cascade and the baseline, per modality.
- Cascade latency measured on CPU and reported.
- Models reproducible from seed.

**Prompt:**
> Phase 3. Decisions D2 and D5 are: <...>. Propose the training/evaluation modules and the OOF/stacking design. Start with the tabular models.

---

### Phase 4 — Threat-intelligence service and RQ2 (weeks 13–14)

**Goal:** `ti_score` 0–100 and the with/without comparison for false positives. **Serves:** RQ2.

**Build (`backend/intel/`):**
- Clients for VirusTotal and AlienVault OTX (URLhaus is used only in the D2 blocklist baseline, never as a model input; endpoints and fields checked against current official docs before coding), with timeouts, retries, rate limiting and Redis caching.
- Score combiner → `ti_score` 0–100, with the formula documented in `decisions.md`.
- Offline recording of TI responses for the dataset subset (D7) with timestamps.
- RQ2 experiment: same models trained with and without `ti_score`, compared on FPR (plus F1) with CIs and McNemar, on development CV.

**Acceptance checks:**
- All clients tested with mocked responses; no keys in code.
- Cache hit/miss and rate limits tested.
- RQ2 table produced; circularity threat documented.

**Prompt:**
> Phase 4. Decision D7 is: <...>. Tell me the exact API endpoints and response fields you plan to use for each provider and where in the docs I can verify them. Then propose the client and scoring design.

---

### Phase 5 — Backend API and database (weeks 15–16)

**Goal:** the live service that the gateway, extension and dashboard call.

**Build (`backend/api/`, `backend/db/`):**
- SQLAlchemy 2 models + Alembic migrations: scans, verdicts, model versions, campaigns, simulation events (no credential values), users/admins.
- FastAPI endpoints (Pydantic v2): scan URL, scan email, get verdict, model info, health; admin endpoints for the dashboard; API-key auth for extension/gateway.
- Inference service: extractor → models → ensemble/cascade → `ti_score` → block/warn/allow, with the explanation (top SHAP features) returned.
- Celery tasks for slow work (snapshots, TI lookups, DistilBERT).
- Logging and basic metrics (latency per stage).

**Acceptance checks:**
- API tests with a test database and mocked TI.
- Live API features equal training features for the same input (parity test).
- p95 latency for the tabular path measured and reported.

**Prompt:**
> Phase 5. Propose the DB schema, the endpoint list with request/response models, and the inference flow. Wait for my OK.

---

### Phase 6 — Simulation module, feedback loop and RQ3 harness (weeks 17–18)

**Goal:** consenting-user simulations and the controlled A/B/C retraining experiment. **Serves:** RQ3.

**Pre-condition:** university ethics approval received; participant consent recorded.

**Build (`backend/simulation/`, `ml/training/`):**
- GoPhish integration through its documented API (verified before coding): create campaigns, pull results.
- Fictional organisation branding and templates; templates split into training templates and **simulation-holdout** templates.
- Event store: delivered, opened, clicked, submitted (boolean only, never values).
- Converter: failed-simulation emails/URLs → training records tagged `source=simulation`, never written to the locked test set.
- RQ3 harness: per round r, train Model A (static, up to month M), Model B (dev + fresh feed up to M+r−1), Model C (same as B with k phishing samples replaced by k simulation samples, size-matched, same features/hyper-parameters/seed); evaluate all three on fresh feed data of month M+r and on the simulation-holdout set; 5 seeds per round; F1, recall, FPR, differences with bootstrap 95% CIs, McNemar.
- Promotion rule: promote only if F1 improves and FPR does not rise on both the locked test set and the simulation-holdout set (in rounds after the final evaluation).

**Acceptance checks:**
- Test proves no simulation sample can enter the locked test set.
- Test proves B and C receive the same number of new samples and the same label balance.
- No credential value is stored anywhere (test posts a form and inspects DB and logs).
- Harness runs end-to-end on replayed monthly data with fake simulation samples.

**Prompt:**
> Phase 6. Ethics approval: <yes/no>. Propose the GoPhish integration (tell me which API endpoints you will use and how I verify them), the template split, and the RQ3 harness design.

---

### Phase 7 — Browser extension and email gateway (weeks 19–20)

**Goal:** real-time protection at the two entry points.

**Build:**
- `extension/`: MV3 for Chrome, Edge, Firefox; checks navigations against the API; local cache; warning and block pages; allow-once; settings; no page content sent unless needed for features; visual-similarity signal per D6.
- `gateway/`: IMAP gateway that polls a test mailbox, scans each message through the API, and moves/flags messages (block → quarantine folder, warn → tag subject/header, allow → leave). Attachment handling limited to file type and hash.

**Acceptance checks:**
- Extension loads unpacked in all three browsers; warning/block flow works against the local API.
- Gateway tested against a local test IMAP server; never touches mailboxes I do not control.
- Both handle API downtime safely (documented fail-open/fail-closed choice in `decisions.md`).

**Prompt:**
> Phase 7. Decision D6 is: <...>. Propose the extension architecture (permissions list and why each is needed) and the gateway loop.

---

### Phase 8 — Dashboard, deployment, final evaluation and RQ3 rounds (weeks 21–22)

**Goal:** the deployed system and the final numbers.

**Build:**
- `dashboard/`: React + Vite + Tailwind + Recharts — detections, verdict breakdowns, campaigns and click/submission rates, model versions and metrics, RQ3 round charts.
- Full `docker compose` deployment with a README walkthrough.
- **Final evaluation (only time the locked test set is used):** RQ1 table (ensembles vs baseline, per modality, email with and without age-sensitive features, FPR on the recent check set); RQ2 table; all with CIs.
- RQ3: at least three monthly rounds with 5 seeds each; B vs A, C vs B (main), C vs A.

**Acceptance checks:**
- One script reproduces every reported number from saved artefacts.
- Locked-test-set access is logged and happens once per final model.
- Results reported as they are, including missed targets or inconclusive RQ3.

**Prompt:**
> Phase 8. All models are frozen. Propose the final-evaluation script and the dashboard pages. Do not touch the locked test set until I confirm.

---

### Phase 9 — Write-up (weeks 23–24)

**Goal:** results and discussion chapters, AI-use appendix, public repository.

**Build:**
- Results per RQ with tables and figures generated from the evaluation outputs.
- Threats to validity: email age gap, TI circularity, small simulation sample, template leakage.
- Development-log appendix from `docs/devlog/` (what AI tools contributed and what I changed).
- Public repo cleaned: no raw data, no secrets, rebuild scripts documented.

**Prompt:**
> Phase 9. Help me structure the results chapter from the evaluation outputs in ml/evaluation/results/. Do not invent or round numbers beyond what the files contain.

---

## 5. Timeline

Start date: **<fill in — D8>**

| Phase | Weeks | Dates |
|---|---|---|
| 0 Environment and skeleton | 1–2 | |
| 1 Data and split; start monthly collection | 3–5 | |
| 2 Feature extractor | 6–8 | |
| 3 Models, ensembles, baseline | 9–12 | |
| 4 Threat intelligence, RQ2 | 13–14 | |
| 5 Backend API and DB | 15–16 | |
| 6 Simulation, feedback loop, RQ3 harness | 17–18 | |
| 7 Extension and gateway | 19–20 | |
| 8 Dashboard, deployment, final evaluation, RQ3 rounds | 21–22 | |
| 9 Write-up and submission | 23–24 | |

**Schedule risk for RQ3:** the proposal needs at least three monthly rounds, but simulations start in week 17 and the final evaluation is in weeks 21–22. Monthly feed collection starts in Phase 1, so feed data can be replayed in time order. Simulation samples, however, only exist after campaigns run. To keep three rounds possible: get ethics approval in Phase 0, run the first small campaign as soon as Phase 6 starts, and if fewer than three rounds of simulation data exist by week 22, report the rounds that were completed and say so.

---

## 6. Risk register

| Risk | Effect | Mitigation |
|---|---|---|
| Phishing pages offline before snapshot | Missing F46–F95 | Snapshot at collection time; report missing rates; models handle missing values |
| Too few phishing emails | Imbalanced modality mix | D3; report modalities separately |
| Email age gap | Model learns "old vs new" | §3.6.1 normalisation, ablation without F96–F101/F109/F110, recent check set |
| TI API limits / circularity | RQ2 biased or incomplete | D7 subset design; caching; document threat |
| Template leakage in feedback loop | Inflated RQ3 | Simulation-holdout templates; C must beat B on fresh feed data |
| Small number of volunteers | Low power for RQ3 | Size-matched design, 5 seeds, CIs; report inconclusive results honestly |
| Ethics approval delay | No simulations | Request in Phase 0 |
| DistilBERT latency | Slow real-time path | Cascade; measure and report |
