# PhishGuard ML pipeline

Offline research pipeline: builds the dataset, trains and evaluates the models, and runs the
RQ1–RQ3 experiments. It is the Python package `phishguard_ml` and imports shared code (the
F1–F140 feature extractor, the enum values) from the `phishguard` package in `backend/`, so
training and the live API use the same code.

```
phishguard_ml/
  paths.py      where data is read and written (repo-root data/, or PHISHGUARD_DATA_DIR)
  data/         records, downloaders, cleaning, labelling, sampling, split (Phase 1)
  training/     training, tuning, calibration, ensembles, RQ3 harness (Phases 3 and 6)
  evaluation/   metrics, confidence intervals, McNemar, final evaluation (Phases 3 and 8)
notebooks/      exploration only; no result in the thesis comes only from a notebook
tests/
```

This folder holds **code**. The data itself lives in `/data/` at the repo root (gitignored):
`raw/`, `snapshots/`, `processed/`, `splits/`.

## The record format

Every source is converted to one `SampleRecord` (`phishguard_ml/data/records.py`) and stored
as Parquet with a fixed schema:

| Field | Meaning |
|---|---|
| `sample_id` | UUID v5 of sample type + content hash: same content → same id |
| `sample_type` | `url` or `email` (from the source) |
| `raw_content` | the URL, or the full email as received |
| `label` | `phishing` or `legitimate` (from the source) |
| `attack_category` | decision D1 rules; always empty for legitimate samples |
| `source` | phishtank, openphish, tranco, nazario, spamassassin, enron, own_mailbox |
| `source_date` | date given by the source, if any |
| `collected_at` | when we downloaded it (UTC) |
| `group_key` | split grouping key (decision D4) |
| `content_hash` | SHA-256 of the normalised content (used for de-duplication) |
| `snapshot_ref` | URLs only: where the page/DNS/TLS/RDAP snapshot is stored |

## Install and test (PowerShell)

The `phishguard` package is installed from `../backend` first; it is deliberately not listed
as a dependency in `pyproject.toml`, so pip never fetches an unrelated package of the same
name from PyPI.

```powershell
# from the repo root, with the backend venv active (.\backend\.venv\Scripts\Activate.ps1)
make install      # installs backend and ml
make test
make lint
```

## Building the dataset (Phase 1)

Run from `ml/` with the venv active. Each step reads the previous step's output under `data/`.

```powershell
python -m phishguard_ml download                 # all sources -> data/raw/<source>/<day>/
python -m phishguard_ml build                    # -> data/processed/records.parquet
# Snapshots: ONLY in the container (phishing pages are never fetched from your PC)
docker compose --profile collect run --rm snapshot          # from the repo root
python -m phishguard_ml rdap                     # domain registration data (registries only)
python -m phishguard_ml label                    # -> data/processed/labelled.parquet
python -m phishguard_ml count                    # look at the numbers, then choose sizes (D3)
python -m phishguard_ml split --n-url N --n-email M   # frozen split, made ONCE
python -m phishguard_ml verify-split             # fails if the split changed
python -m phishguard_ml datacard                 # refresh Docs/data_card.md
python -m phishguard_ml features                 # F1-F140 -> data/processed/features.parquet (Phase 2)
docker compose --profile collect up -d collector # daily fresh data for RQ3 (repo root)
```

`python -m phishguard_ml snapshot` on your PC is refused on purpose; only `ml/Dockerfile` sets
the flag that allows it.

Own-mailbox check set: put exported `.eml` files (personal content removed) in
`data/raw/own_mailbox/`; `build` writes them to `data/processed/own_mailbox.parquet`, which is
never part of the dataset or the split.
