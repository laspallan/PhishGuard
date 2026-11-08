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
```

## Training and development results (Phase 3)

Needs the `train` extra (`make install`). Uses the development split only.

```powershell
python -m phishguard_ml train --modality url --feature-set all --trials 50
python -m phishguard_ml train --modality url --feature-set no_path      # D10c
python -m phishguard_ml train --modality url --feature-set no_rdap      # F46-F52 left out
python -m phishguard_ml train --modality url --feature-set no_tranco    # F57-F58 left out
python -m phishguard_ml train --modality email --feature-set no_header  # headline email result
python -m phishguard_ml train --modality email --feature-set all
python -m phishguard_ml train --modality email --feature-set no_age
python -m phishguard_ml report                   # -> data/models/results.md / results.json
docker compose --profile collect up -d collector # daily fresh data for RQ3 (repo root)
```

### Text models (LSTM, CNN, DistilBERT)

`backend/.venv` cannot load PyTorch on this PC, so the text models have their own environment.
ZKBioTime sets `PYTHONHOME` for the whole machine, so clear it for this environment only:

```bash
uv venv ml/.venv-text --python 3.11 --managed-python --seed
env -u PYTHONHOME uv pip install --python ml/.venv-text/Scripts/python.exe torch --index-url https://download.pytorch.org/whl/cpu
env -u PYTHONHOME uv pip install --python ml/.venv-text/Scripts/python.exe -e "backend[dev]" -e "ml[dev,train,text]"
```

CNN, after `train_queue.ps1` has finished: `powershell -File ml\train_text_queue.ps1`. The LSTM is
left out of that queue because it is too slow on this CPU (timing in `PROGRESS.md`, Phase 3 step 4).

LSTM and DistilBERT run on Google Colab, on development rows only. The locked test set stays on this
PC. Each run reads one file from `data/colab/`, made by `text-export`. In Colab, choose Runtime >
Change runtime type > GPU, mount Google Drive, upload the script and the data file, then for the LSTM:

```bash
pip install optuna
python train_lstm.py --data dev_text_email_text_body.parquet --out /content/drive/MyDrive/pg_lstm_email
# A disconnect costs at most one training: run the same command again. Copy the folder back, then:
python -m phishguard_ml text-import path/to/pg_lstm_email
```

Use one Drive folder per run, for `email text_body`, `url text_host` and `url text_full`. Each line of
its output shows the seconds that training took. For DistilBERT:

```bash
python -m phishguard_ml text-export --modality email --input text_body   # -> data/colab/
# Upload that file and ml/colab/train_distilbert.py to Colab (GPU runtime), then:
#   pip install transformers
#   python train_distilbert.py --data dev_text_email_text_body.parquet --out /content/drive/MyDrive/pg_email
# A disconnect costs at most one fold: run the same command again. Copy the folder back, then:
python -m phishguard_ml text-import path/to/pg_email
```

Do the same for `--modality url --input text_host` and `--input text_full`.

## Threat intelligence and RQ2 (Phase 4)

Needs `PHISHGUARD_VIRUSTOTAL_API_KEY` and `PHISHGUARD_ALIENVAULT_OTX_API_KEY` in `.env`, and the
collector running. Lookups go only to VirusTotal and OTX (read-only); no URL is submitted.

```powershell
python -m phishguard_ml ti-record --daily   # 250 phishing + 250 legitimate a day -> data/ti_responses/
python -m phishguard_ml rq2                 # after 8 days and url/live: -> data/models/rq2/results.md
```

`--daily` checks every 30 minutes and stops at the day's quota, so a restart never exceeds
VirusTotal's 500 lookups a day.

## Notifications for long jobs

`ml\notify_status.ps1` shows a Windows notification when a training run ends (or fails), a training
queue finishes, the SpamAssassin baseline is imported, or today's RQ2 lookups reach 500. It reads
local files only. To run it every 30 minutes while you are logged in:

```powershell
schtasks /Create /SC MINUTE /MO 30 /TN "PhishGuard status" /TR "powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File D:\PhishGuard\ml\notify_status.ps1" /F
schtasks /Delete /TN "PhishGuard status" /F      # to stop it
```

## Brand favicon hashes for the extension (D6)

Needs the `brand` extra (Pillow). Fetches `/favicon.ico` from each brand's own domains only and
writes `frontend/extension/src/brandHashes.json` (hashes only); rebuild the extension afterwards.

```powershell
python -m phishguard_ml brand-icons
```

## Final evaluation (Phase 8)

```bash
python -m phishguard_ml choose-band                # stage-1 band table, development data
python -m phishguard_ml final-eval --confirm-models-are-frozen   # the ONE use of the locked test set
python -m phishguard_ml final-report               # every final number, from the saved predictions
python -m phishguard_ml results                    # or `make results`: every table above, in one go
```

`results` recomputes the development, RQ2 and final tables from the saved files. It reruns only what
has been run before (so RQ2 is never computed early on part of the data) and never calls `final-eval`.

`final-eval` refuses without the flag, logs each access in
`data/models/final/locked_test_access.jsonl`, and refuses a model version that was evaluated
before. Do not run it until every model is frozen.

`python -m phishguard_ml snapshot` on your PC is refused on purpose; only `ml/Dockerfile` sets
the flag that allows it.

Own-mailbox check set: put exported `.eml` files (personal content removed) in
`data/raw/own_mailbox/`; `build` writes them to `data/processed/own_mailbox.parquet`, which is
never part of the dataset or the split.
