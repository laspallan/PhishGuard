"""SHAP summaries for the tabular models (mean |SHAP value| per feature).

TreeExplainer on a random sample of development rows (seed 42). Values are in the model's own
output units (probability for the random forest, log-odds for XGBoost / LightGBM), so feature
rankings are compared within a model, not raw values across models. For the random forest the
values of the phishing class are used.
"""

import numpy as np
import shap

from phishguard_ml.training.devdata import DevData

SEED = 42


def mean_abs_shap(model, data: DevData, sample: int = 2000, seed: int = SEED) -> list[dict]:
    rng = np.random.default_rng(seed)
    rows = rng.choice(len(data.y), size=min(sample, len(data.y)), replace=False)
    values = shap.TreeExplainer(model)(data.X[rows]).values
    if values.ndim == 3:  # (rows, features, classes): keep the phishing class
        values = values[:, :, 1]
    importance = np.abs(values).mean(axis=0)
    order = np.argsort(importance)[::-1]
    return [
        {"feature": data.feature_names[i], "mean_abs_shap": float(importance[i])} for i in order
    ]
