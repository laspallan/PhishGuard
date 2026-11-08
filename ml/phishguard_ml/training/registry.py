"""Model registry: the final model of a run, trained on the whole development set.

Each run folder (data/models/<modality>/<feature set>/<model>/) holds, after `fit_final`:
  oof.parquet   out-of-fold predictions (from tabular.train_and_save)
  run.json      parameters, seed, OOF log loss, feature-code hash, split hashes
  model.joblib  the model refitted on all development rows with the tuned parameters
  calibrator.joblib  isotonic calibrator fitted on all OOF predictions
  model.json    version id and everything needed to check a model is used correctly
and data/models/registry.json lists every registered version. A model must only be used with
features whose `feature_code_hash` equals the one recorded here.
"""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import joblib
import numpy as np
import pyarrow.parquet as pq

from phishguard_ml import paths
from phishguard_ml.training import calibration, tabular
from phishguard_ml.training.devdata import DevData


def registry_path() -> Path:
    return paths.models_dir() / "registry.json"


def load_registry() -> list[dict]:
    return json.loads(registry_path().read_text()) if registry_path().exists() else []


def fit_final(folder: Path, data: DevData) -> dict:
    run = json.loads((folder / "run.json").read_text())
    if run["n_samples"] != len(data.y):
        raise ValueError("the development data differ from the data the run was tuned on")
    model = tabular.make_model(run["model"], run["params"], run["seed"]).fit(data.X, data.y)
    oof = pq.read_table(folder / "oof.parquet")
    calibrator = calibration.fit_calibrator(
        np.asarray(oof.column("p_phishing").to_numpy()), np.asarray(oof.column("label").to_numpy())
    )
    joblib.dump(model, folder / "model.joblib")
    joblib.dump(calibrator, folder / "calibrator.joblib")
    return register(folder, run, "model.joblib", feature_names=data.feature_names)


def register(folder: Path, run: dict, model_file: str, *, feature_names: list[str]) -> dict:
    """Writes model.json (last, it marks a finished run) and adds the version to the registry."""
    model_hash = hashlib.sha256((folder / model_file).read_bytes()).hexdigest()
    entry = {
        "version": f"{run['modality']}-{run['feature_set']}-{run['model']}-{model_hash[:12]}",
        "path": folder.relative_to(paths.models_dir()).as_posix(),
        "model": run["model"],
        "modality": run["modality"],
        "feature_set": run["feature_set"],
        "feature_names": feature_names,
        "params": run["params"],
        "seed": run["seed"],
        "feature_code_hash": run["feature_code_hash"],
        "split_sha256": run["split_sha256"],
        "oof_log_loss": run["oof_log_loss"],
        "model_sha256": model_hash,
        "registered_at": datetime.now(UTC).isoformat(),
    }
    (folder / "model.json").write_text(json.dumps(entry, indent=1))
    entries = [e for e in load_registry() if e["path"] != entry["path"]] + [entry]
    registry_path().parent.mkdir(parents=True, exist_ok=True)
    registry_path().write_text(json.dumps(entries, indent=1))
    return entry
