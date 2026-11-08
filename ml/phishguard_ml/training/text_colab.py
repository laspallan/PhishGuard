"""The two ends of the Colab runs (`ml/colab/train_distilbert.py`, `ml/colab/train_lstm.py`).

Export writes development rows only, so the locked test set stays on this PC. Import refuses a
result whose samples, labels or folds differ from the current development set, or that was made
with other text code or another split. Neither function needs PyTorch.
"""

import json
import shutil
from dataclasses import asdict
from pathlib import Path

import joblib
import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

from phishguard.services.text_input import text_code_hash
from phishguard_ml import paths
from phishguard_ml.training import calibration, registry, tabular
from phishguard_ml.training.devdata import DevText
from phishguard_ml.training.text_settings import TOKENS, code_hash

# Files each Colab run must bring back, and the first of them is the one the registry hashes.
MODEL_FILES = {
    "distilbert": ("model/model.safetensors",),
    "lstm": ("model.pt", "vocabulary.json"),
}

# DistilBERT tokens, not characters or words: its pieces of words use more than the LSTM's tokens.
MAX_LENGTH = {"url": 128, "email": 256}


def export_path(modality: str, text_input: str) -> Path:
    return paths.data_dir() / "colab" / f"dev_text_{modality}_{text_input}.parquet"


def export(data: DevText, modality: str, text_input: str, split_sha256: dict) -> Path:
    path = export_path(modality, text_input)
    path.parent.mkdir(parents=True, exist_ok=True)
    table = pa.table(
        {
            "sample_id": data.sample_ids,
            "text": data.texts,
            "label": data.y.astype("int8"),
            "fold": data.folds.astype("int8"),
            "group": data.groups,
            "source": data.sources,
        }
    ).replace_schema_metadata(
        {
            "modality": modality,
            "text_input": text_input,
            "max_length": str(MAX_LENGTH[modality]),
            "text_code_hash": text_code_hash(),
            "lstm_code_hash": code_hash(modality),
            "tokens": json.dumps(asdict(TOKENS[modality])),
            "split_sha256": json.dumps(split_sha256),
        }
    )
    pq.write_table(table, path)
    return path


def import_run(source: Path, data: DevText, split_sha256: dict) -> dict:
    run = json.loads((source / "run.json").read_text())
    oof = pq.read_table(source / "oof.parquet").to_pydict()
    p = np.asarray(oof["p_phishing"], dtype=float)
    if run["model"] not in MODEL_FILES:
        raise ValueError(f"not a Colab run: {run['model']}")
    if run["split_sha256"] != split_sha256:
        raise ValueError("this run used another split")
    expected = text_code_hash() if run["model"] == "distilbert" else code_hash(run["modality"])
    if run["feature_code_hash"] != expected:
        raise ValueError("this run used other text code; export and train again")
    if (
        oof["sample_id"] != data.sample_ids
        or not np.array_equal(oof["label"], data.y)
        or not np.array_equal(oof["fold"], data.folds)
    ):
        raise ValueError("the samples, labels or folds differ from the development set")
    if not np.isfinite(p).all() or p.min() < 0 or p.max() > 1:
        raise ValueError("the predictions are not probabilities")
    files = MODEL_FILES[run["model"]]
    if not all((source / name).exists() for name in files):
        raise ValueError("the final model is missing")

    folder = tabular.run_dir(run["modality"], run["feature_set"], run["model"])
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "model.json").unlink(missing_ok=True)
    shutil.copy2(source / "oof.parquet", folder / "oof.parquet")
    shutil.copy2(source / "run.json", folder / "run.json")
    if run["model"] == "distilbert":
        shutil.copytree(source / "model", folder / "model", dirs_exist_ok=True)
    else:
        for name in files:
            shutil.copy2(source / name, folder / name)
    joblib.dump(calibration.fit_calibrator(p, data.y), folder / "calibrator.joblib")
    return registry.register(folder, run, files[0], feature_names=[])
