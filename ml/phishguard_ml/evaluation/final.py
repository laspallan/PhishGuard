"""Final evaluation on the locked test set (Phase 8). This is its only use in the project.

`run` opens the locked test set for the final models, only with explicit confirmation, logs the
access first, refuses a model version that was evaluated before, and saves every prediction.
`report` computes all numbers from those saved predictions and never opens the test set, so it
can be run any number of times and reproduces every reported number.

Ensembles use only what was fixed on the development set: the calibrators, and a stacker fitted on
out-of-fold predictions.
"""

import json
from collections.abc import Callable
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

import joblib
import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

from phishguard.models.enums import Modality
from phishguard.services.features.extractor import FEATURE_NAMES, email_features, feature_code_hash
from phishguard_ml import paths
from phishguard_ml.data.records import read_records
from phishguard_ml.evaluation import metrics
from phishguard_ml.evaluation import report as dev_report
from phishguard_ml.training import devdata, ensembles, registry
from phishguard_ml.training.tabular import MODELS

THRESHOLD = 0.5
TEXT_MODELS = ("lstm", "cnn_1d", "distilbert")
# The cascade and which feature set it takes its tabular soft vote from.
CASCADE_TABULAR = {"url": "live", "email": "no_header"}
CASCADE_TEXT = {"url": "text_full", "email": "text_body"}


class AlreadyEvaluatedError(RuntimeError):
    """This model version has already seen the locked test set."""


def _folder() -> Path:
    return paths.models_dir() / "final"


def access_log_path() -> Path:
    return _folder() / "locked_test_access.jsonl"


def predictions_path() -> Path:
    return _folder() / "predictions.parquet"


def evaluated_versions() -> set[str]:
    if not access_log_path().exists():
        return set()
    lines = access_log_path().read_text(encoding="utf-8").splitlines()
    return {version for line in lines for version in json.loads(line)["versions"]}


def _tabular_predictor(entry: dict) -> Callable[[devdata.DevText], np.ndarray]:
    folder = paths.models_dir() / entry["path"]
    model = joblib.load(folder / "model.joblib")

    def raw(data: devdata.DevText) -> np.ndarray:
        return model.predict_proba(data.X)[:, 1]

    return raw


def _text_predictor(entry: dict) -> Callable[[devdata.DevText], np.ndarray]:
    """PyTorch is imported only here: run in ml/.venv-text when text models are registered."""
    folder = paths.models_dir() / entry["path"]
    if entry["model"] == "distilbert":
        from phishguard_ml.evaluation.latency import distilbert_predictor

        predict = distilbert_predictor(folder)
        return lambda data: predict(data.texts)
    from phishguard_ml.training import text_train

    fitted = text_train.load_final(folder, entry["modality"])
    return lambda data: fitted.predict(data.texts)


def _stacker_inputs(entry: dict) -> tuple[np.ndarray, np.ndarray]:
    oof = pq.read_table(paths.models_dir() / entry["path"] / "oof.parquet")
    return np.asarray(oof.column("p_phishing")), np.asarray(oof.column("label"))


def run(*, confirmed: bool = False, entries: list[dict] | None = None) -> dict:
    """Predictions of every registered final model, plus ensembles and cascade."""
    if not confirmed:
        raise devdata.LockedTestNotConfirmedError(
            "run `final-eval --confirm-models-are-frozen` only when all models are frozen"
        )
    entries = registry.load_registry() if entries is None else entries
    current = feature_code_hash()
    tabular = [e for e in entries if e["model"] in MODELS]
    stale = [e["version"] for e in tabular if e["feature_code_hash"] != current]
    if stale:
        raise ValueError(f"built by other feature code, retrain first: {stale}")
    versions = [e["version"] for e in entries]
    seen = evaluated_versions() & set(versions)
    if seen:
        raise AlreadyEvaluatedError(f"already evaluated on the locked test set: {sorted(seen)}")

    _folder().mkdir(parents=True, exist_ok=True)
    with access_log_path().open("a", encoding="utf-8") as log:  # logged before it is opened
        record = {"at": datetime.now(UTC).isoformat(), "versions": versions}
        log.write(json.dumps(record) + "\n")

    columns = ("modality", "feature_set", "model", "sample_id", "label", "group", "source", "p")
    rows: dict[str, list] = {k: [] for k in columns}

    def add(modality, feature_set, name, data, p):
        for key, values in zip(
            ("sample_id", "label", "group", "source", "p"),
            (data.sample_ids, data.y, data.groups, data.sources, p),
            strict=True,
        ):
            rows[key].extend(np.asarray(values).tolist())
        rows["modality"].extend([modality] * len(p))
        rows["feature_set"].extend([feature_set] * len(p))
        rows["model"].extend([name] * len(p))

    calibrated_by_set: dict[tuple[str, str], dict[str, np.ndarray]] = {}
    data_by_set: dict[tuple[str, str], devdata.DevText] = {}
    for (modality, feature_set), group in _by_set(entries).items():
        is_text = group[0]["model"] in TEXT_MODELS
        data = devdata.load_locked_test(
            Modality(modality),
            "all" if is_text else feature_set,
            feature_set if is_text else None,
            confirmed=True,
        )
        data_by_set[(modality, feature_set)] = data
        calibrated, raw = {}, {}
        for entry in group:
            predictor = (_text_predictor if is_text else _tabular_predictor)(entry)
            raw[entry["model"]] = predictor(data)
            calibrator = joblib.load(paths.models_dir() / entry["path"] / "calibrator.joblib")
            calibrated[entry["model"]] = calibrator.predict(raw[entry["model"]])
            add(modality, feature_set, entry["model"], data, calibrated[entry["model"]])
        if all(m in calibrated for m in MODELS):
            vote = ensembles.soft_vote([calibrated[m] for m in MODELS])
            add(modality, feature_set, "soft_vote", data, vote)
            calibrated["soft_vote"] = vote
            ordered = [next(e for e in group if e["model"] == m) for m in MODELS]
            oof = [_stacker_inputs(e) for e in ordered]
            stacker = ensembles.fit_stacker([p for p, _ in oof], oof[0][1])
            add(
                modality, feature_set, "stacker", data,
                ensembles.stacker_predict(stacker, [raw[m] for m in MODELS]),
            )  # fmt: skip
        calibrated_by_set[(modality, feature_set)] = calibrated

    for modality, tabular_set in CASCADE_TABULAR.items():
        vote = calibrated_by_set.get((modality, tabular_set), {}).get("soft_vote")
        text_set = CASCADE_TEXT[modality]
        text = calibrated_by_set.get((modality, text_set), {}).get("distilbert")
        if vote is not None and text is not None:
            data = data_by_set[(modality, tabular_set)]
            add(modality, tabular_set, "cascade", data, ensembles.cascade(vote, text))

    pq.write_table(pa.table(rows), predictions_path())
    return report()


def _by_set(entries: list[dict]) -> dict[tuple[str, str], list[dict]]:
    found: dict[tuple[str, str], list[dict]] = {}
    for entry in entries:
        found.setdefault((entry["modality"], entry["feature_set"]), []).append(entry)
    return found


def recent_email_check(entries: list[dict] | None = None) -> dict:
    """FPR on the recent legitimate emails from your own mailbox: evaluation only, and not part of
    the dataset or the split, so this does not touch the locked test set. {} until they exist."""
    path = paths.processed_dir() / "own_mailbox.parquet"
    if not path.exists():
        return {}
    emails = [r.raw_content for r in read_records(path)]
    entries = registry.load_registry() if entries is None else entries
    out = {}
    for entry in entries:
        if entry["modality"] != "email" or entry["model"] not in MODELS:
            continue
        positions = [FEATURE_NAMES.index(name) for name in entry["feature_names"]]
        X = np.array([np.asarray(email_features(raw, {}))[positions] for raw in emails])
        folder = paths.models_dir() / entry["path"]
        raw_p = joblib.load(folder / "model.joblib").predict_proba(X)[:, 1]
        p = joblib.load(folder / "calibrator.joblib").predict(raw_p)
        out[f"{entry['feature_set']}/{entry['model']}"] = {
            "n": len(emails),
            "fpr": float((p >= THRESHOLD).mean()),
            "fpr_at_warn": float((p >= ensembles.WARN).mean()),
            "fpr_at_block": float((p >= ensembles.BLOCK).mean()),
        }
    (_folder() / "recent_email_check.json").parent.mkdir(parents=True, exist_ok=True)
    (_folder() / "recent_email_check.json").write_text(json.dumps(out, indent=1))
    return out


def report(n_boot: int = 1000) -> dict:
    """Every final number, from the saved predictions only."""
    columns = pq.read_table(predictions_path()).to_pydict()
    arrays = {k: np.asarray(v) for k, v in columns.items()}
    results: dict[str, list[dict]] = {}
    keys = sorted(
        {*zip(columns["modality"], columns["feature_set"], columns["model"], strict=True)}
    )
    for modality, feature_set, name in keys:
        chosen = (
            (arrays["modality"] == modality)
            & (arrays["feature_set"] == feature_set)
            & (arrays["model"] == name)
        )
        y, p = arrays["label"][chosen].astype(int), arrays["p"][chosen].astype(float)
        predicted = (p >= THRESHOLD).astype(int)
        results.setdefault(f"{modality}/{feature_set}", []).append(
            {
                "model": name,
                "n": int(len(y)),
                **asdict(metrics.scores(y, predicted)),
                "ci95": metrics.bootstrap_ci(
                    y, predicted, list(arrays["group"][chosen]), n_boot=n_boot
                ),
                "ece": metrics.expected_calibration_error(y, p),
                "fpr_at_warn": metrics.scores_at(y, p, ensembles.WARN).fpr,
                "fpr_at_block": metrics.scores_at(y, p, ensembles.BLOCK).fpr,
            }
        )
    (_folder() / "final_results.json").write_text(json.dumps(results, indent=1))
    # The same table format as the development results, so the thesis copies no number by hand.
    text = dev_report.markdown(
        results, title="Final results on the locked test set (calibrated, threshold 0.5)"
    )
    (_folder() / "final_results.md").write_text(text, encoding="utf-8")
    return results
