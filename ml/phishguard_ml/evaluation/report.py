"""Development (CV) results table for every saved run, plus the two ensembles.

For each modality and feature set: every tabular model's OOF predictions, calibrated
cross-fitted, scored at 0.5 (accuracy, precision, recall, F1, FPR with group-bootstrap 95% CIs),
the calibration error, the FPR at the warn (0.60) and block (0.90) thresholds, the FPR per
legitimate source (decision 2026-11-03 (b)), and McNemar against the soft-voting ensemble.
Ensembles are added when all three tabular models exist for the same rows.

Writes data/models/results.json and results.md. These are development results only; the
locked test set is evaluated once, in Phase 8.
"""

import json
from dataclasses import asdict
from pathlib import Path

import numpy as np
import pyarrow.parquet as pq

from phishguard_ml import paths
from phishguard_ml.evaluation import baseline, metrics
from phishguard_ml.training import calibration, ensembles
from phishguard_ml.training.tabular import MODELS

THRESHOLD = 0.5
# The cascade: this tabular soft vote first, DistilBERT on this text inside the band.
CASCADE_TABULAR = {"url": "live", "email": "no_header"}
CASCADE_TEXT = {"url": "text_full", "email": "text_body"}


def _column(values: list) -> np.ndarray:
    """Text columns stay Python strings: a fixed-width array is as wide as the longest value,
    and URL group keys can be whole links (1.2 GiB for one column of 87,706 rows)."""
    if values and isinstance(values[0], str):
        return np.asarray(values, dtype=object)
    return np.asarray(values)


def _runs() -> dict[tuple[str, str], dict[str, dict]]:
    found: dict[tuple[str, str], dict[str, dict]] = {}
    for oof_file in sorted(paths.models_dir().glob("*/*/*/oof.parquet")):
        folder = oof_file.parent
        table = pq.read_table(oof_file).to_pydict()
        found.setdefault((folder.parent.parent.name, folder.parent.name), {})[folder.name] = {
            key: _column(value) for key, value in table.items()
        }
    return found


def _row(name: str, y, p, groups, sources, reference: np.ndarray | None, n_boot: int) -> dict:
    """`p` are probabilities, or 0/1 decisions for the signature baseline (no calibration)."""
    predicted = (p >= THRESHOLD).astype(int)
    is_probability = not np.isin(p, (0, 1)).all()
    legitimate = y == 0
    per_source = {
        str(s): metrics.scores(
            y[legitimate & (sources == s)], predicted[legitimate & (sources == s)]
        ).fpr
        for s in np.unique(sources[legitimate])
    }
    row = {
        "model": name,
        "n": int(len(y)),
        **asdict(metrics.scores(y, predicted)),
        "ci95": metrics.bootstrap_ci(y, predicted, list(groups), n_boot=n_boot),
        "ece": metrics.expected_calibration_error(y, p) if is_probability else None,
        "fpr_at_warn": metrics.scores_at(y, p, ensembles.WARN).fpr if is_probability else None,
        "fpr_at_block": metrics.scores_at(y, p, ensembles.BLOCK).fpr if is_probability else None,
        "fpr_by_legitimate_source": per_source,
    }
    if reference is not None:
        row["mcnemar_vs_soft_vote"] = metrics.mcnemar(y, predicted, reference)
    return row


def build(n_boot: int = 1000) -> dict:
    results = {}
    _runs_found = _runs()
    for (modality, feature_set), runs in sorted(_runs_found.items()):
        first = next(iter(runs.values()))
        y, folds = first["label"].astype(int), first["fold"].astype(int)
        groups, sources = first["group"], first["source"]
        for run in runs.values():
            if not np.array_equal(run["sample_id"], first["sample_id"]):
                raise ValueError(f"{modality}/{feature_set}: runs cover different samples")
        raw = {name: run["p_phishing"] for name, run in runs.items()}
        calibrated = {name: calibration.cross_fitted(p, y, folds) for name, p in raw.items()}

        candidates = dict(calibrated)
        if all(m in raw for m in MODELS):
            candidates["soft_vote"] = ensembles.soft_vote([calibrated[m] for m in MODELS])
            candidates["stacker"] = ensembles.stacked_out_of_fold(
                [raw[m] for m in MODELS], y, folds
            )
            text_run = _runs_found.get((modality, CASCADE_TEXT[modality]), {}).get("distilbert")
            if text_run is not None and feature_set == CASCADE_TABULAR[modality]:
                if not np.array_equal(text_run["sample_id"], first["sample_id"]):
                    raise ValueError(f"{modality}: DistilBERT covers different samples")
                candidates["cascade"] = ensembles.cascade(
                    candidates["soft_vote"],
                    calibration.cross_fitted(text_run["p_phishing"], y, folds),
                )
        detected = baseline.load() if modality == "email" else None
        if detected is not None:
            ids = first["sample_id"]
            if any(str(i) not in detected for i in ids):
                raise ValueError("the SpamAssassin baseline does not cover every development email")
            candidates["spamassassin_baseline"] = np.array([float(detected[str(i)]) for i in ids])
        reference = (
            (candidates["soft_vote"] >= THRESHOLD).astype(int)
            if "soft_vote" in candidates
            else None
        )
        results[f"{modality}/{feature_set}"] = [
            _row(name, y, p, groups, sources, None if name == "soft_vote" else reference, n_boot)
            for name, p in candidates.items()
        ]
    folder = paths.models_dir()
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "results.json").write_text(json.dumps(results, indent=1))
    (folder / "results.md").write_text(markdown(results), encoding="utf-8")
    return results


def _fmt(value: float) -> str:
    return (
        "–" if value is None or (isinstance(value, float) and np.isnan(value)) else f"{value:.4f}"
    )


DEV_TITLE = "Development results (5-fold CV, out-of-fold, calibrated, threshold 0.5)"


def markdown(results: dict, title: str = DEV_TITLE, reference: str = "soft vote") -> str:
    """`reference` names what the McNemar column compares against (the rows' reference)."""
    lines = [f"# {title}", ""]
    for key, rows in results.items():
        lines += [
            f"## {key}",
            "",
            "| Model | n | Accuracy | Precision | Recall | F1 [95% CI] | FPR [95% CI] | ECE "
            f"| McNemar p vs {reference} |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
        for r in rows:
            f1_low, f1_high = r["ci95"]["f1"]
            fpr_low, fpr_high = r["ci95"]["fpr"]
            p_value = r.get("mcnemar_vs_soft_vote", {}).get("p_value")
            lines.append(
                f"| {r['model']} | {r['n']} | {_fmt(r['accuracy'])} | {_fmt(r['precision'])} | "
                f"{_fmt(r['recall'])} | {_fmt(r['f1'])} [{_fmt(f1_low)}, {_fmt(f1_high)}] | "
                f"{_fmt(r['fpr'])} [{_fmt(fpr_low)}, {_fmt(fpr_high)}] | {_fmt(r['ece'])} | "
                f"{_fmt(p_value)} |"
            )
        lines.append("")
    return "\n".join(lines)


def results_path() -> Path:
    return paths.models_dir() / "results.md"
