"""Ensembles, decision thresholds and the cascade (Phase 3).

- Soft voting: mean of the models' calibrated probabilities.
- Stacker: logistic regression on the models' raw OOF probabilities (as log-odds), cross-fitted
  by fold. Raw, not calibrated, inputs: the cross-fitted calibrators of the other folds were
  fitted with this fold's labels, so stacking calibrated values would leak them. Logistic
  regression calibrates its own output.
- Decisions: block if p >= 0.90, warn if p >= 0.60, else allow (plan defaults; any change is
  chosen on development OOF data only).
- Cascade: the tabular ensemble decides alone outside [0.30, 0.80]; inside that band the text
  model (DistilBERT) is asked and its probability is used.
"""

import numpy as np
from sklearn.linear_model import LogisticRegression

SEED = 42
WARN, BLOCK = 0.60, 0.90
CASCADE_BAND = (0.30, 0.80)
_EPS = 1e-6


def soft_vote(probabilities: list[np.ndarray]) -> np.ndarray:
    return np.mean(np.column_stack(probabilities), axis=1)


def _log_odds(probabilities: list[np.ndarray]) -> np.ndarray:
    p = np.clip(np.column_stack(probabilities), _EPS, 1 - _EPS)
    return np.log(p / (1 - p))


def fit_stacker(probabilities: list[np.ndarray], y: np.ndarray) -> LogisticRegression:
    return LogisticRegression(max_iter=1000, random_state=SEED).fit(_log_odds(probabilities), y)


def stacker_predict(model: LogisticRegression, probabilities: list[np.ndarray]) -> np.ndarray:
    return model.predict_proba(_log_odds(probabilities))[:, 1]


def stacked_out_of_fold(
    probabilities: list[np.ndarray], y: np.ndarray, folds: np.ndarray
) -> np.ndarray:
    """Stacker prediction for each fold from a stacker fitted on the other folds."""
    out = np.full(len(y), np.nan)
    for fold in np.unique(folds):
        held_out = folds == fold
        model = fit_stacker([p[~held_out] for p in probabilities], y[~held_out])
        out[held_out] = stacker_predict(model, [p[held_out] for p in probabilities])
    return out


def decide(p: np.ndarray, warn: float = WARN, block: float = BLOCK) -> np.ndarray:
    p = np.asarray(p)
    return np.where(p >= block, "block", np.where(p >= warn, "warn", "allow"))


def in_cascade_band(p_tabular: np.ndarray, band: tuple[float, float] = CASCADE_BAND) -> np.ndarray:
    p = np.asarray(p_tabular)
    return (p >= band[0]) & (p <= band[1])


def cascade(
    p_tabular: np.ndarray, p_text: np.ndarray, band: tuple[float, float] = CASCADE_BAND
) -> np.ndarray:
    """Final probability: the text model's inside the band, the tabular one outside."""
    return np.where(in_cascade_band(p_tabular, band), p_text, p_tabular)
