"""Reads the model registry written by the training pipeline and loads models for serving.

`<data_dir>/models/registry.json` (ml/.../training/registry.py) is a JSON list of registered
versions. The backend does not import the ml package (the API image contains only the backend),
so the path comes from the settings (PHISHGUARD_DATA_DIR).

A model is served only if it was built by the current feature code, and its file still has the
recorded hash: joblib files run code when loaded, and changed features would mean wrong scores.
"""

import hashlib
import json
import logging
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import numpy as np

from phishguard.core.config import get_settings
from phishguard.services.features.extractor import feature_code_hash

log = logging.getLogger(__name__)


class ServingModel:
    """One registered model and its calibrator: feature values in, P(phishing) out."""

    def __init__(self, entry: dict[str, Any], model: Any, calibrator: Any):
        self.entry = entry
        self.model = model
        self.calibrator = calibrator

    @property
    def version(self) -> str:
        return self.entry["version"]

    def probability(self, values: Mapping[str, float]) -> float:
        row = np.array([[values[name] for name in self.entry["feature_names"]]], dtype=float)
        raw = self.model.predict_proba(row)[:, 1]
        return float(self.calibrator.predict(raw)[0])

    def explanations(self, values: Mapping[str, float], top: int = 5) -> list[dict[str, float]]:
        """The features that moved this score most: SHAP values (log-odds), computed by XGBoost
        and LightGBM themselves. Random forests return [] rather than an invented explanation;
        an explanation problem never costs the verdict."""
        names = self.entry["feature_names"]
        row = np.array([[values[name] for name in names]], dtype=float)
        try:
            if self.entry.get("model") == "lightgbm":
                contributions = self.model.predict(row, pred_contrib=True)[0][:-1]
            elif self.entry.get("model") == "xgboost":
                import xgboost

                booster = self.model.get_booster()
                matrix = xgboost.DMatrix(row, feature_names=booster.feature_names)
                contributions = booster.predict(matrix, pred_contribs=True)[0][:-1]
            else:
                return []
        except Exception as error:
            log.warning("no explanation: %s", type(error).__name__)
            return []
        ranked = sorted(zip(names, row[0], contributions, strict=True), key=lambda c: -abs(c[2]))
        return [
            {
                "feature": name,
                "value": None if np.isnan(value) else float(value),
                "importance": float(shap_value),
            }
            for name, value, shap_value in ranked[:top]
        ]


class ModelLoader:
    def __init__(self, models_dir: Path | None = None):
        self.models_dir = Path(models_dir or get_settings().data_dir / "models")
        self.entries: list[dict[str, Any]] = []
        self._serving: dict[tuple[str, str], ServingModel | None] = {}

    def load_registry(self) -> list[dict[str, Any]]:
        """Registered versions, or [] if there is no (readable) registry yet."""
        path = self.models_dir / "registry.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = []
        self.entries = [e for e in data if isinstance(e, dict)] if isinstance(data, list) else []
        self._serving.clear()
        return self.entries

    @property
    def loaded(self) -> bool:
        return bool(self.entries)

    def serving_model(self, modality: str, feature_set: str) -> ServingModel | None:
        """The usable model of this feature set with the lowest out-of-fold log loss."""
        key = (modality, feature_set)
        if key not in self._serving:
            self._serving[key] = self._load_best(modality, feature_set)
        return self._serving[key]

    def _load_best(self, modality: str, feature_set: str) -> ServingModel | None:
        current = feature_code_hash()
        candidates = [
            e
            for e in self.entries
            if e.get("modality") == modality
            and e.get("feature_set") == feature_set
            and e.get("feature_code_hash") == current
        ]
        for entry in sorted(candidates, key=lambda e: e["oof_log_loss"]):
            model = self._load(entry)
            if model is not None:
                return model
        return None

    def _load(self, entry: dict[str, Any]) -> ServingModel | None:
        import joblib  # needs the `serve` extra; the collector image does not install it

        folder = (self.models_dir / entry["path"]).resolve()
        if not folder.is_relative_to(self.models_dir.resolve()):
            log.error("registry path outside the models folder: %s", entry["version"])
            return None
        try:
            digest = hashlib.sha256((folder / "model.joblib").read_bytes()).hexdigest()
            if digest != entry["model_sha256"]:
                log.error("model file changed since it was registered: %s", entry["version"])
                return None
            return ServingModel(
                entry,
                joblib.load(folder / "model.joblib"),
                joblib.load(folder / "calibrator.joblib"),
            )
        except OSError as error:
            log.error("cannot read %s: %s", entry["version"], type(error).__name__)
            return None
