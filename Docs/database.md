# Database schema

PostgreSQL 16, SQLAlchemy 2 models in `backend/phishguard/models/`, migrations in
`backend/phishguard/db/migrations/versions/`. Initial revision: `b56beefdb0fc` (2026-11-02).

Rules (see `Docs/decisions.md`):
- Every primary key is a UUID (v4).
- Email addresses are encrypted (Fernet); `email_hash` is an HMAC-SHA256 blind index used for
  lookups and uniqueness.
- Email scans keep only a hash, the sender domain and the verdict.
- Enum columns are VARCHAR + CHECK constraint.
- The research dataset is **not** in the database; it lives in `/data/` files.

## How the tables connect

```
api_clients ──< scans >── model_versions ──< experiment_runs
                 ├── scan_features (1:1)
                 └──< scan_feedback
templates ──< campaigns ──< simulation_events >── participants
     └──────────< simulation_samples >── simulation_events (1:1)
ti_lookups (standalone)          admin_users (standalone)
```

`──<` means one-to-many.

## Delete rules

| When this is deleted | Then |
|---|---|
| participant (consent withdrawn) | their `simulation_events` and `simulation_samples` are deleted |
| campaign | its `simulation_events` (and their samples) are deleted |
| scan | its `scan_features` and `scan_feedback` are deleted |
| api_client | its scans keep existing with `api_client_id = NULL` |
| model_version used by a scan or template used by a campaign/sample | blocked (RESTRICT) |
| model_version used by an experiment run | run kept with `model_version_id = NULL` |

## Tables

### Access

**admin_users** — dashboard login
`id`, `email` (encrypted), `email_hash` (unique), `password_hash`, `role` (admin/viewer),
`is_active`, `created_at`, `last_login_at`

**api_clients** — keys for the extension and gateway (only a hash of the key is stored)
`id`, `name`, `client_type` (extension/gateway), `key_prefix`, `key_hash` (unique),
`is_active`, `created_at`, `last_used_at`, `revoked_at`

### Detection

**model_versions** — every trained model and ensemble
`id`, `name`, `modality` (url/email), `kind` (random_forest … cascade), `artifact_path`,
`data_hash`, `feature_set_hash`, `seed`, `block_threshold`, `warn_threshold` (warn < block,
both in (0, 1]), `cv_metrics`, `locked_test_metrics`, `sim_holdout_metrics` (JSONB),
`status` (candidate/active/retired/rejected), `promotion_reason`, `trained_at`, `promoted_at`

**scans** — one check and its verdict
`id`, `api_client_id`, `model_version_id`, `sample_type` (url/email), `input_hash` (indexed),
`url`, `sender_domain`, `score` (0–1), `ti_score` (0–100), `decision` (block/warn/allow),
`used_distilbert`, `top_features` (JSONB, SHAP), `latency_ms`, `created_at` (indexed)

**scan_features** — the F1–F140 vector of a scan (exactly 140 values)
`scan_id` (PK), `extractor_version`, `values` (float[])

**scan_feedback** — reports that a verdict was wrong
`id`, `scan_id`, `reported_label` (phishing/legitimate), `source` (extension/gateway/admin),
`comment`, `created_at`

**ti_lookups** — permanent record of each threat-intelligence call (RQ2)
`id`, `indicator`, `indicator_hash`, `indicator_type` (url/domain/ip/hash),
`provider` (virustotal/otx/urlhaus), `provider_score`, `raw_response` (JSONB, as received),
`fetched_at`, `expires_at`

### Simulation

**participants** — consenting volunteers only
`id`, `participant_code` (unique), `email` (encrypted), `email_hash` (unique),
`consent_form_version`, `consent_given_at`, `consent_withdrawn_at`, `created_at`

**templates** — simulation email + landing page for a fictional organisation
`id`, `name` (unique), `gophish_template_id`, `attack_category`, `fictional_org`,
`split` (train/holdout), `created_at`

**campaigns**
`id`, `name`, `gophish_campaign_id`, `template_id`, `status`
(draft/running/completed/cancelled), `created_at`, `launched_at`, `completed_at`

**simulation_events** — no column for submitted form data, by design
`id`, `campaign_id`, `participant_id`, `event_type` (sent/opened/clicked/submitted/reported),
`occurred_at`; unique on (campaign, participant, event type, time) so imports are idempotent

### Feedback loop and experiments

**simulation_samples** — failed-simulation samples used as phishing training data
`id`, `simulation_event_id` (unique), `template_id`, `content_ref`,
`usage` (train/sim_holdout only), `collected_month`, `created_at`

**experiment_runs** — one result row: model × evaluation set × seed
`id`, `experiment` (rq1/rq2/rq3), `round`, `seed`, `arm` (A/B/C, baseline, …),
`model_version_id`, `eval_set` (dev_cv/fresh_feed/sim_holdout/locked_test/recent_email),
`k`, `metrics` (JSONB), `created_at`

## Rules still to enforce in controllers (Phase 6)

- A `simulation_sample` from a `holdout` template must have `usage = sim_holdout`
  (cross-table rule; not expressible as a simple CHECK).
- When importing GoPhish results, drop any submitted form data before saving.
