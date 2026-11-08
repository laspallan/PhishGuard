# Progress

Status of each phase. A phase is marked Done only after every acceptance check in
`Docs/IMPLEMENTATION_PLAN.md` has been verified (see the phase-completion rule).

## Phase 0 — Environment, repository and skeleton

**Status:** Done (verified 2026-11-02; details in git history).

**Carried forward (your action):** send the university ethics-approval request. Needed before
Phase 6 is tested on people. Draft written 2026-11-07, **not sent**: `Docs/ethics_request.md`.

## Phase 1 — Data and split

**Status:** Done (verified 2026-11-05; build details in git history).

**Acceptance checks (re-checked on the real data 2026-11-05):**
- [x] Final counts and 50/50, per-category counts in the data card: 122,042 samples, the largest
  balanced set (D3 replaces the 175,000 target; the gap is reported) — URL 51,592 / 51,592,
  email 9,429 / 9,429; categories and the split are in `Docs/data_card.md`
- [x] No group_key on both sides of the split (0 of all groups in more than one part); no
  content_hash twice (0)
- [x] Test ≈ 15% (15.0%; URL 15.0%, email 14.8%, every category 14.2–16.7%), 5 stratified
  folds, reproducible from seed 42 (sampling and split rebuilt in memory: identical)
- [x] Collector runs as a scheduled job and writes a dated batch: `collector` container up
  (restart unless-stopped, every 24 h); first batch `monthly/2026-11/2026-11-05.parquet`,
  679 new samples, none in the split
- [x] Tests run offline against small fixture files — 158 ml tests, network mocked

**RDAP stopped 2026-11-05 (you decided):** 105,445 of 108,480 domains answered; the rest
(registry refusals, rate limits, .au / .pl / .ar not reached) stay missing.

## Phase 2 — Feature extractor F1–F140

**Status:** Done (verified 2026-11-06; all four acceptance checks below, plus `make test` and
`make lint` in all five modules).
**Decided 2026-11-02:** P2-a…P2-f (missing = NaN, modality columns, Tranco leakage reported,
external dated lists, RDAP/Authentication-Results sources, NLP libraries) — `Docs/decisions.md`.

**Steps:**
- [x] Shared pieces: `missing.py` (NaN), `hosts.py` (offline host splitting, same as ml/)
- [x] F1–F45 `url_lexical.py`; lists for F26 (Interisle 2026 Table 2) and F27 (CC BY-SA
  shortener list, pinned commit) — 16 tests, every value hand-counted
- [x] F46–F65 `domain_ssl.py` (stored RDAP / DNS / TLS; F65 always missing — you decided) —
  12 tests; ages measured at capture time, RDAP changes after capture = missing (leak guard);
  checked on 3,000 real snapshots: no crashes, plausible ranges
- [x] F66–F95 `html_js.py` (standard-library parser, no new dependency) — 8 tests, one
  hand-checked page covering every feature. Real-page check **stopped**: see Defender below
- [x] F96–F115 `email_headers.py` + `email_parts.py` (robust header reading) — 13 tests; run
  on all 32,345 real emails: no crashes. **Finding:** Enron headers identify the corpus
  (0% Received/Return-Path) — decision needed before Phase 3 (`Docs/decisions.md`)
- [x] F116–F140 `nlp_text.py` (pyspellchecker 0.9.1, vaderSentiment 3.3.2, both MIT) — 6 tests;
  run on all 32,345 real emails: no crashes, ~10 ms each
- [x] `extractor.py` (140 values in catalogue order, `feature_code_hash`), email normaliser moved
  into the backend (same function for training and API), matrix builder
  `ml/phishguard_ml/features/matrix.py` + `features` command — counts unreadable pages in its
  report. Parallel build checked on real emails (400 in 7 s). **Real run waits for:** RDAP end,
  `label`, and your Defender decision (it reads all 51,592 phishing pages)
- [x] Missing-value rate per feature in the data card (per class, own modality, split dataset;
  `datacard.missing_rates`, 1 test) — 2026-11-05
- [x] **Real feature table built 2026-11-05** (`features.parquet`, hash `50d7055b…`): 169,178
  URL + 32,345 email rows, pages ok 85,944 / none 83,234 / unreadable 0, ~50 min on 10 workers.

**Acceptance checks (2026-11-05):**
- [x] Output names and order equal `Docs/features.md` — `test_feature_catalogue.py`,
  `test_extractor.py` and one test per feature group
- [x] Every feature has a unit test with a hand-checked example — per group tests above
- [x] Training path and API path call the same function (closed 2026-11-06) — training:
  `test_uses_the_backend_extractor`; API: `test_scan_path_gives_the_training_features_and_thresholds`
  runs the API's own `url_values` on a collector answer. `services/evidence.py`
  (`build_url_evidence`) is the only way stored or collected evidence becomes `UrlEvidence`
  (3,000 real records recomputed: 0 differences; feature hash unchanged).
- [x] Missing-value rate per feature in the data card

**Findings from the missing-value rates (class gaps of 10+ points):** email header features
(Received chain, Return-Path, SPF / DKIM / DMARC) are missing for 83–100% of legitimate emails
(Enron has no delivery headers) — all 20 are outside the headline `no_header` set. URL page
features: most are missing for 16.9% of phishing and 20.3% of legitimate URLs (no page), but the
link-based ones (F84 external_link_ratio, F85 null_link_ratio) are missing for 64.6% of phishing vs
32.1% of legitimate URLs (no page with links: phishing pages are often takedown or redirect
pages), so missingness carries class information; Phase 3 should also report URL results on
samples with a page.

**Decided 2026-11-02:** URLhaus only in the D2 blocklist baseline (removed from labelling and
`ti_score`); F65 always missing.

## Phase 3 — Models, ensembles, baseline and development evaluation

**Status:** In progress (code first, on synthetic data; real training needs the split).
**Decided 2026-11-03:** single-level Optuna on 5-fold CV, cross-fitted calibration/stacking,
DistilBERT on Colab (development split only), D2, D5, Enron header handling (a)+(b).

**Steps:**
- [x] 1. `training/devdata.py` (development rows only, feature sets, stale-matrix guard),
  `training/tabular.py` (RF / XGBoost / LightGBM, Optuna on OOF log loss, OOF saved with
  metadata) — 9 tests, incl. the locked-test guard and a no-leak check on the folds
- [x] 2. `training/calibration.py` (isotonic, cross-fitted), `evaluation/metrics.py`
  (accuracy, precision, recall, F1, FPR, group-bootstrap CIs, exact McNemar, ECE,
  threshold for a target FPR) — 7 tests, values by hand
- [x] 3. `training/ensembles.py`: soft voting, cross-fitted LR stacker on raw OOF log-odds,
  0.60 / 0.90 decisions, cascade rule — 5 tests
- [x] 4. Text models built 2026-11-06, not yet trained on real data: `training/text_train.py` (LSTM,
  CNN), `ml/train_text_queue.ps1`, `services/text_input.py`, `ml/colab/train_distilbert.py`,
  `training/text_colab.py` (`text-export`, `text-import`). 18+ tests in `test_text_models.py`, run in
  `ml/.venv-text` (`make test-text`): they are skipped in `backend/.venv`, which cannot load PyTorch.
  The Colab script ran end to end with a tiny DistilBERT, not the real one and not on a GPU.
  `ml/.venv-text` (uv Python 3.11.18, torch 2.15.0+cpu; not in git): ZKBioTime sets `PYTHONHOME`
  machine-wide, so run it with that cleared. Dataset names are hidden from the email text
  (decisions.md).
  **Timing, 2026-11-06, measured with the tabular queue using the CPU** (small samples, scaled to 15
  trainings of about 6 epochs each, so rough upper estimates). CNN: email about 6 h, full URL about
  14 h: feasible, and `ml/train_text_queue.ps1` now runs the CNN only, chained after the tabular queue.
  LSTM, at 1, 2 and 4 threads: full URL 342–429 h, email 592–1,183 h; more threads did not help. Even
  several times faster on a free CPU that is too slow, so the LSTM runs on Colab (you decided,
  2026-11-06). `ml/colab/train_lstm.py` is built: on a CPU it gives exactly the same predictions as
  `text_train.py`, and it searches the same space (tests). It keeps every finished trial and fold, and
  `text-import` registers the result like any other text model. Checked on 300 real rows on CPU; **not
  yet run on a GPU or on all rows, so its GPU time is unknown.** The three exports are ready in
  `data/colab/`. The real exports found lone surrogates in some emails, now replaced in `email_text`.
  **LSTM email/text_body trained on a Colab GPU 2026-11-06:** 16,065 rows, about 26 min, OOF log loss
  0.0761 (fold 0 was used to choose the settings; the other four average about 0.080). URL text_host
  trained on Colab 2026-11-07, about 32 min. URL text_full stopped at 3 of 10 trials (Colab limit);
  resuming draws the remaining trials with a different seed.
- [ ] 5. Cascade: the rule, the report row and `evaluation/latency.py` are built and tested; the
  real row and the CPU latency need DistilBERT from Colab (your action)
- [x] 6. Signature baseline (D2): `evaluation/baseline.py` + `ml/spamassassin/` container
  (SpamAssassin 4.0.1, Bayes off, no network), rows in the results table; URL baseline only in
  RQ3 (you decided). 3 tests + end-to-end; smoke test on 300 real emails passed.
  **Full run 2026-11-08:** all 16,065 development emails scored (379 min), 4,311 detected;
  `results.md` rebuilt. Development: SpamAssassin accuracy 0.7637, recall 0.5321, FPR 0.0046
  [0.0021, 0.0084]; soft vote no_header accuracy 0.9501, recall 0.9365, FPR 0.0364 [0.0301, 0.0437];
  McNemar p < 0.0001. The baseline has the **lower** false-positive rate.
- [x] 7. `training/registry.py` (final model + calibrator on all development rows, version id,
  hashes, `registry.json`), `evaluation/shap_report.py` (TreeExplainer, mean |SHAP|),
  `evaluation/report.py` (CV table per modality / feature set, ensembles, CIs, ECE, FPR at
  0.60 / 0.90, FPR per legitimate source, McNemar vs soft vote); `train` and `report`
  commands — end-to-end test on synthetic data
- [ ] 8. Real runs (started 2026-11-05; you chose 50 trials for every run). Queue:
  `ml/train_queue.ps1`, safe to re-run: `train --resume` skips models already complete with the
  same feature code, split, trial count and seed (a crash costs at most the model in progress).
  Order: email/no_header, url/all, email/all, url/no_path, url/no_tranco, url/no_rdap, then
  url/live (M2), url/live_stage1 (M1) and email/no_age when the queue is re-run after the first
  pass; 3 models each (random forest, XGBoost, LightGBM). url/all and email/all are done too.
  **email/no_header done** in 2 h 49 min, OOF log loss:
  RF 0.1586, XGBoost 0.1316, LightGBM 0.1305. First url/all attempt lost to battery shutdowns.

## Phase 4 — Threat-intelligence service and RQ2

**Status:** In progress (clients built 2026-11-04 in commit bf4574d, fixed after review).
- [x] VirusTotal (read-only, never submits URLs) and AlienVault OTX clients; async rate limits
  (VirusTotal public: 4/min, 500/day); cache (Redis or bounded memory, errors not cached);
  offline recorder of raw responses with timestamps — tests offline (mocked HTTP)
- [x] `ti_score` formula and D7 subset agreed 2026-11-08 (`Docs/decisions.md`, RQ2) and built:
  `scoring.py`, `training/rq2.py`, commands `ti-record [--daily]` and `rq2`; tests offline
  (`test_intel.py` 13, `test_rq2.py` 6). Still to check on the first real answers: OTX
  `pulse_info.count`, and the VirusTotal engine names for PhishTank and OpenPhish.
- [ ] Record TI responses for the subset (8 days of `ti-record --daily`, needs the keys and the PC
  awake); then `rq2` (needs the `url/live` models)
- [ ] Your action: free VirusTotal and OTX keys in `.env`

## Phase 5 — Backend API and database

**Status:** In progress (database part built early, 2026-11-02)

**What was built:**
- `backend/phishguard/models/`: 13 tables in `access.py`, `detection.py`, `simulation.py`,
  `experiments.py`; shared types and mixins in `base.py`; allowed values in `enums.py`.
- `backend/phishguard/core/crypto.py`: Fernet encryption and HMAC blind index for emails.
- `backend/phishguard/db/session.py` (engine, sessions, `get_db`), Alembic setup
  (`alembic.ini`, `phishguard/db/migrations/`), initial migration `b56beefdb0fc`.
- `Docs/database.md` (schema reference); new decisions in `Docs/decisions.md`.
- `make migrate`, `make test-db`; two new keys in `.env.example`.

**How to run:** `make migrate` (needs `docker compose up -d postgres`), `make test`,
`make test-db`.

**Test results (2026-11-02):**
- `make test`: backend 25 passed (crypto 5, models 14, plus earlier tests), dashboard 8 passed.
- `make test-db`: 1 passed — upgrade to head, models and database identical
  (`compare_metadata` empty), downgrade removes every table.
- `make lint`: clean. API container rebuilt; `/health` 200. Dev database at `b56beefdb0fc`.

**Known issues:**
- On this PC `localhost` tries IPv6 `::1` first and Docker does not answer it, so connections
  hang. `.env.example` and `.env` now use `127.0.0.1`.
- Cross-table rule "holdout template → usage sim_holdout" is left for the Phase 6 controller.

**Added 2026-11-04 (commit bf4574d, fixed after review):** `/scan/url`, `/scan/email`,
`/models`, `/admin/status` behind the X-API-Key (fail closed outside development); scans
answer 503 until a trained model is wired in (no placeholder verdicts); model registry reader;
real feature-parity check (`feature_code_hash`); Celery app skeleton.

**D11 step 5 built 2026-11-06:** `services/inference/service.py` (two-stage URL flow, email scan,
D11d and D11e rules), `model_loader.py` (lowest OOF log loss with the current feature hash, checks
`model_sha256`, refuses paths outside the models folder), `scan_store.py` (verdict cache 1 h, partial
5 min; rate limit per API client; a Redis failure does not stop scans), `persist.py` (scan and model
version; emails as hash and sender domain only; secret-looking URLs without their query). API image
has the serving libraries at the training versions.
Tests: `test_scan_service.py` (fake models and collector, every decision path, 23 tests).
Real check, 201 development emails through `email-no_header-lightgbm-2b4912be3f97`: legitimate 100
allow; phishing 91 block, 10 warn. Latency median 569 ms, p95 995 ms with training using the CPU.
These emails are ones the final model was refit on, so this shows the serving path works, not how
good the model is.

**Added 2026-11-06:** explanations (SHAP values from XGBoost and LightGBM; random forests give none)
in the answer and in `scans.top_features`; `test_scan_persistence.py` on real Postgres; read-only
admin endpoints for the dashboard (`test_admin_api.py`); `choose-band` command.

**Still open in Phase 5 (D11):**
- Real URL scans: M1 and M2 are not trained yet, so URL scans answer 503. After they are: run
  `choose-band` and set the band (0.15–0.85 is provisional), rebuild the evidence-collector image
  (task signature changed), measure p95 latency.
- End-to-end test with the extension and the gateway (D11 step 6).
- `ti_score` is None (Phase 4).
- ~~Redis is still published on 127.0.0.1:6379~~ Closed 2026-11-08: not published in
  `docker-compose.yml`; `docker-compose.dev.yml` publishes it on 127.0.0.1 only for host runs.
  Checked: port closed on the host, `redis-cli ping` inside the container answers.

**D11 step 4 code done 2026-11-06:** feature sets `live` (M2, 84 features) and `live_stage1` (M1, 48
features) in `training/devdata.py`, without F55 too (decisions.md), with behaviour tests. Both are in
`ml/train_queue.ps1`.

**D11 step 3 done 2026-11-06:** evidence collector `ml/phishguard_ml/data/evidence_worker.py`
(Celery task on queue `evidence`; stage 1 DNS only, stage 2 + page and TLS; one 6 s deadline, late
parts listed in `late`; refuses stage 2 for secret-looking URLs and runs only in its container),
API side `services/inference/evidence_client.py` (late or failed = None, never an error), compose
service `evidence-collector` (`--profile live`: own network with Redis and API only, no volume,
read-only file system, no secrets). Test `test_no_target_contact.py` fails if a service outside
`intel/` can open a connection. Real check through Redis: example.com stage 1 2.7 s, stage 2 0.9 s
(page, verified TLS); 169.254.169.254 and 127.0.0.1 refused; token URL refused; unresolvable host
gets DNS only; in the container Postgres is unreachable, writes fail, uid 1000, no /data.
Redis is no longer published (closed 2026-11-08, see above).

**D11f done 2026-11-05:** the snapshot collector connects only to the address it has just
checked (`PinnedBackend` / `PinnedTransport` for HTTP, `_connect_checked` for TLS; SNI and
certificate checks still use the host name; `trust_env=False` so no proxy bypasses it). 6 new
offline tests (rebinding, pinned IP for HTTP and TLS, wiring guard); ml 153 passed, lint clean.
Stored snapshots are unchanged.

**Removed 2026-11-04 (you decided):** the duplicate / placeholder files from bf4574d —
`simulation/gophish.py`, `gophish_client.py`, `templates.py`, `events.py` (duplicated
`models.enums`), `inference/persist.py`, `workers/tasks.py`, `ml` `rq3.py`, `rq3_harness.py`,
`rq2.py`, `transformer.py`, and the extension's empty content script. Their work stays in the
plan (Phases 3, 4, 5, 6).

## Phase 6 — Simulation module, feedback loop and RQ3 harness

**Status:** In progress. Built and tested 2026-11-06 without anyone being contacted. **Cannot be used
on people until the university approves.**
- [x] `services/simulation/gophish.py` (endpoints checked against the docs and the source) and
  `campaigns.py` (launch rules, event store, failed-simulation samples); `training/rq3.py`
  (arms A, B, C, CIs, McNemar, promotion rule); `gophish` compose service (`--profile simulate`)

**Acceptance checks:**
- [x] No simulation sample can enter the locked test set — `test_a_simulation_sample_can_never_be_in_the_locked_test_set`,
  `test_there_is_no_way_to_mark_a_sample_for_the_locked_test_set`
- [x] B and C get the same number of new samples and the same label balance — `test_b_and_c_have_the_same_size_and_label_balance_and_a_is_static`
- [x] No credential value stored — `test_a_submitted_value_reaches_neither_database_nor_logs`, and a real
  form submitted to real GoPhish 0.12.1 in a local container (no email could leave): the password
  did not reach GoPhish, and "Submitted Data" was still recorded
- [x] Harness runs end to end on replayed months with fake samples — `test_a_round_runs_end_to_end_on_replayed_months`

**2026-11-07:** you approved going ahead with RQ3. This does not replace the university's approval:
`PHISHGUARD_ETHICS_APPROVAL_REF` stays empty and no campaign can launch.

**Added 2026-11-08:** the launch code creates the explanation page (`debrief.py`) for every campaign,
so no other landing page can be used, and refuses without `PHISHGUARD_SIMULATION_CONTACT_EMAIL`.
Campaign-management endpoints under `/admin/simulation` (templates, participants and withdrawal,
campaigns, launch, sync, complete), behind the API key; answers never name a participant.
Tests: `test_simulation.py`, `test_simulation_api.py` (GoPhish faked); backend 204 passed.

**Added 2026-11-08 (later):** read-only lists `GET /admin/simulation/templates`, `/participants` (by
code only, never the address), `/campaigns`; dashboard **Simulation** page (templates, participants
and withdrawal, draft campaigns, launch, fetch events, complete; launch disabled and explained
without approval; asks before withdraw, launch and complete; shows the API's reason for a refusal).
**Real GoPhish 0.12.1 check** (local container, sending profile on a closed port, a `.test` address,
a test-only approval reference in memory; no email could leave): launch 200; the landing page was the
explanation page (no form, no outside resources, contact address shown, capture off in GoPhish);
fetch events saved 1 click; complete set GoPhish to Completed; no answer named the participant. It
found that GoPhish's own certificate cannot be checked, so `make gophish-cert` and
`PHISHGUARD_GOPHISH_CA_FILE` were added (decisions.md); rerun through the real client, certificate
checked. Tests: `test_simulation_api.py` 8 passed; dashboard 23 passed, build clean.

**Not done:** the pre-condition (ethics approval, your action); your approval of the 8 draft
templates in `Docs/simulation_templates.md` (4 categories × train/holdout, fictional names checked
against the real-brand list and a web search; not loaded anywhere); loading real monthly data and real simulation samples into `rq3.run_round` (needs
months of collected data and real samples).

## Phase 7 — Browser extension and email gateway

**Status:** In progress (skeletons 2026-11-04 in commit bf4574d, fixed after review).
- [x] Added 2026-11-06: local verdict cache, session rule that stops repeat visits to a blocked URL
  before they load, "Open once anyway", Firefox manifest keys, fail-open choice recorded in
  decisions.md. Logic is unit-tested; **not yet loaded in a real browser**.
- [x] Extension (MV3): settings popup (API address + key), warning page for "block", badge
  for "warn", nothing on errors / 503; `manifest.json` now in `public/` so `dist/` loads;
  pure logic unit-tested (5 tests); in `make lint` / `make test`
- [x] IMAP gateway: `BODY.PEEK[]` (mail stays unread), last UID per UIDVALIDITY in a state
  file (each email once), stops and retries on API errors / 503, logging, non-root image,
  pinned requirements; 6 offline tests (fake IMAP, mocked API); in `make lint` / `make test`
- [x] Visual-similarity check (D6, perceptual hash, 2026-11-08): `src/visual.ts` (favicon dHash,
  8-bit limit, never fetches a favicon from the web), `src/brandHashes.json` from `brand-icons`
  (29 of 35 brands), wired into `background.ts` as a warn-only badge; `favicon` permission. Tests:
  extension 18 passed (incl. the same hashes as `test_brand_icons.py`, 3 passed); build clean. Not
  yet tried in a real browser; no detection rate (no snapshot has a favicon).
- [x] 2026-11-09, checking before the page is shown (options C + D, you chose): API
  `GET /extension/blocked-hosts` (hosts only, shared domains left out; `test_extension_api.py` 3
  passed); extension `src/precheck.ts`, `checking.html`, rules in `background.ts`, `alarms`
  permission; extension 28 passed, build clean. **First real-browser run** (headless Edge, built
  extension, API on the host): blocklisted host stopped before loading; first visit through the
  checking page; second visit straight through. Temporary test rows deleted afterwards.
- [ ] End-to-end test against a running API with a trained model (after Phase 5)

## Phase 8 — Dashboard, deployment, final evaluation and RQ3 rounds

**Status:** In progress. **The locked test set has not been read.**
- [x] Dashboard pages on the read-only admin API (overview, detections, campaigns, experiments,
  models, threat intel, settings; the API key stays in sessionStorage): 18 tests, build passes.
  Rendered in headless Edge on invented API answers, at desktop and phone width (2026-11-06): no
  console errors, no sideways scrolling. Not yet seen against a real running API.
- [x] 2026-11-08: CORS for the dashboard origins only (it could not have reached the API without
  it; `test_cors.py`); deployment walkthrough `Docs/deployment.md` (settings to simulations, ports,
  backups); `final-report` also writes `final_results.md`; RQ2's `results.md` now has its own title
  and names its McNemar reference.
- [x] `evaluation/final.py`: `final-eval` refuses without `--confirm-models-are-frozen`, logs each
  access in `data/models/final/locked_test_access.jsonl`, refuses a second run per final model;
  `final-report` rebuilds every number from the saved predictions. Tested on synthetic data only.

**Acceptance checks:**
- [ ] One script reproduces every number: built, not yet run on real results
- [ ] Locked-test access logged, once per final model: guard tested, real run waits for frozen models
- [ ] Results reported as they are: only possible after the final run

**Not done:** real final evaluation, three RQ3 monthly rounds with 5 seeds each, RQ2 table; the
walkthrough is written but not yet followed on a clean machine.
