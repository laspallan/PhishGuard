"""Tabular models on F1–F140: random forest, XGBoost, LightGBM (Phase 3).

- Out-of-fold (OOF) predictions: for each of the 5 development folds, the model is trained on
  the other 4 and predicts the held-out fold, so every development sample gets one prediction
  from a model that never saw it. Ensembles and calibration are later fitted on these.
- Tuning: Optuna (TPE sampler, seed 42) minimises the log loss of the OOF predictions over the
  5 folds. Single level, not nested (decided 2026-11-03): the CV score is slightly optimistic;
  the locked test set gives the unbiased estimate in Phase 8. Log loss is used because it
  rewards good probabilities (needed for calibration and thresholds) and needs no threshold.
- Missing values stay NaN; all three models handle NaN natively (checked on the installed
  versions: scikit-learn 1.9.1, XGBoost 3.2.0, LightGBM 4.7.0).
"""

import json
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import optuna
import pyarrow as pa
import pyarrow.parquet as pq
from lightgbm import LGBMClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import log_loss
from xgboost import XGBClassifier

from phishguard.services.features.extractor import feature_code_hash
from phishguard_ml import paths
from phishguard_ml.training.devdata import DevData

SEED = 42
MODELS = ("random_forest", "xgboost", "lightgbm")


def make_model(name: str, params: dict, seed: int = SEED, n_jobs: int = -1):
    if name == "random_forest":
        return RandomForestClassifier(random_state=seed, n_jobs=n_jobs, **params)
    if name == "xgboost":
        return XGBClassifier(
            tree_method="hist", eval_metric="logloss", random_state=seed, n_jobs=n_jobs, **params
        )
    if name == "lightgbm":
        return LGBMClassifier(random_state=seed, n_jobs=n_jobs, verbose=-1, **params)
    raise ValueError(f"unknown model {name!r}; choose from {MODELS}")


def search_space(name: str, trial: optuna.Trial) -> dict:
    if name == "random_forest":
        return {
            "n_estimators": trial.suggest_int("n_estimators", 200, 800, step=100),
            "max_depth": trial.suggest_categorical("max_depth", [None, 10, 20, 40]),
            "min_samples_leaf": trial.suggest_int("min_samples_leaf", 1, 10),
            "max_features": trial.suggest_categorical("max_features", ["sqrt", "log2", 0.3]),
        }
    if name == "xgboost":
        return {
            "n_estimators": trial.suggest_int("n_estimators", 200, 1000, step=100),
            "max_depth": trial.suggest_int("max_depth", 3, 10),
            "learning_rate": trial.suggest_float("learning_rate", 0.01, 0.3, log=True),
            "subsample": trial.suggest_float("subsample", 0.6, 1.0),
            "colsample_bytree": trial.suggest_float("colsample_bytree", 0.5, 1.0),
            "min_child_weight": trial.suggest_float("min_child_weight", 1.0, 10.0),
            "reg_lambda": trial.suggest_float("reg_lambda", 1e-3, 10.0, log=True),
        }
    if name == "lightgbm":
        return {
            "n_estimators": trial.suggest_int("n_estimators", 200, 1000, step=100),
            "num_leaves": trial.suggest_int("num_leaves", 15, 255),
            "learning_rate": trial.suggest_float("learning_rate", 0.01, 0.3, log=True),
            "min_child_samples": trial.suggest_int("min_child_samples", 5, 100),
            "subsample": trial.suggest_float("subsample", 0.6, 1.0),
            "subsample_freq": 1,
            "colsample_bytree": trial.suggest_float("colsample_bytree", 0.5, 1.0),
            "reg_lambda": trial.suggest_float("reg_lambda", 1e-3, 10.0, log=True),
        }
    raise ValueError(f"unknown model {name!r}; choose from {MODELS}")


def out_of_fold(name: str, params: dict, data: DevData, seed: int = SEED) -> np.ndarray:
    """P(phishing) for every development sample, from the model not trained on its fold."""
    oof = np.full(len(data.y), np.nan)
    for fold in np.unique(data.folds):
        train, held_out = data.folds != fold, data.folds == fold
        model = make_model(name, params, seed).fit(data.X[train], data.y[train])
        oof[held_out] = model.predict_proba(data.X[held_out])[:, 1]
    return oof


def tune(
    name: str,
    data: DevData,
    n_trials: int,
    seed: int = SEED,
    progress: Callable[[int, float], None] | None = None,
) -> tuple[dict, float]:
    """Best parameters and their OOF log loss after `n_trials` Optuna trials."""
    optuna.logging.set_verbosity(optuna.logging.WARNING)

    def objective(trial: optuna.Trial) -> float:
        loss = log_loss(data.y, out_of_fold(name, search_space(name, trial), data, seed))
        if progress:
            progress(trial.number, loss)
        return loss

    study = optuna.create_study(direction="minimize", sampler=optuna.samplers.TPESampler(seed=seed))
    study.optimize(objective, n_trials=n_trials)
    best = dict(study.best_params)
    if name == "lightgbm":
        best["subsample_freq"] = 1  # fixed, not searched
    return best, float(study.best_value)


@dataclass(frozen=True)
class RunInfo:
    model: str
    modality: str
    feature_set: str
    params: dict
    oof_log_loss: float
    n_trials: int
    seed: int
    feature_code_hash: str
    split_sha256: dict
    n_samples: int
    trained_at: str


def run_dir(modality: str, feature_set: str, model: str) -> Path:
    return paths.models_dir() / modality / feature_set / model


def save_run(info: RunInfo, data: DevData, oof: np.ndarray) -> Path:
    folder = run_dir(info.modality, info.feature_set, info.model)
    folder.mkdir(parents=True, exist_ok=True)
    pq.write_table(
        pa.table(
            {
                "sample_id": data.sample_ids,
                "fold": data.folds.astype("int8"),
                "label": data.y.astype("int8"),
                "source": data.sources,
                "group": data.groups,
                "p_phishing": oof,
            }
        ),
        folder / "oof.parquet",
    )
    (folder / "run.json").write_text(json.dumps(asdict(info), indent=1))
    return folder


def train_and_save(
    name: str,
    data: DevData,
    *,
    modality: str,
    feature_set: str,
    n_trials: int,
    split_sha256: dict,
    seed: int = SEED,
    progress: Callable[[int, float], None] | None = None,
) -> RunInfo:
    params, _ = tune(name, data, n_trials, seed, progress)
    oof = out_of_fold(name, params, data, seed)
    info = RunInfo(
        model=name,
        modality=modality,
        feature_set=feature_set,
        params=params,
        oof_log_loss=float(log_loss(data.y, oof)),
        n_trials=n_trials,
        seed=seed,
        feature_code_hash=feature_code_hash(),
        split_sha256=split_sha256,
        n_samples=len(data.y),
        trained_at=datetime.now(UTC).isoformat(),
    )
    save_run(info, data, oof)
    return info
