# PhishGuard ML pipeline

Offline research pipeline: builds the dataset, trains and evaluates the models, and runs the
RQ1–RQ3 experiments. It imports shared code (such as the F1–F140 feature extractor) from the
`phishguard` package in `backend/`, so training and the live API use the same code.

```
data/         downloaders, cleaning, labelling, sampling, split, monthly collector (Phase 1)
training/     model training, tuning, calibration, ensembles, RQ3 harness (Phases 3 and 6)
evaluation/   metrics, confidence intervals, McNemar, final evaluation (Phases 3 and 8)
notebooks/    exploration only; no result in the thesis comes only from a notebook
```

This folder holds **code**. The data itself lives in `/data/` at the repo root (gitignored):
`raw/`, `snapshots/`, `processed/`, `splits/`.
