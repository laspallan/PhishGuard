"""Metrics on out-of-fold (or, in Phase 8, test) predictions.

- Classification metrics at a threshold: accuracy, precision, recall, F1, FPR
  (phishing = positive class).
- 95% confidence intervals by **group bootstrap**: whole groups (registered domain / sender,
  decision D4) are resampled, because samples of one group are not independent; resampling
  single samples would make the intervals too narrow.
- McNemar's test (exact binomial, two-sided) for two models on the same samples.
- Expected calibration error (10 equal-width bins) to check calibration.
"""

from dataclasses import dataclass

import numpy as np
from scipy.stats import binomtest

SEED = 42


@dataclass(frozen=True)
class Scores:
    accuracy: float
    precision: float
    recall: float
    f1: float
    fpr: float


def scores(y: np.ndarray, predicted: np.ndarray) -> Scores:
    """`predicted` is 0/1. Undefined ratios (e.g. precision, nothing predicted positive) are NaN."""
    y, predicted = np.asarray(y, dtype=int), np.asarray(predicted, dtype=int)
    tp = int(((predicted == 1) & (y == 1)).sum())
    fp = int(((predicted == 1) & (y == 0)).sum())
    tn = int(((predicted == 0) & (y == 0)).sum())
    fn = int(((predicted == 0) & (y == 1)).sum())

    def ratio(a: int, b: int) -> float:
        return a / b if b else float("nan")

    precision, recall = ratio(tp, tp + fp), ratio(tp, tp + fn)
    f1 = ratio(2 * tp, 2 * tp + fp + fn)
    return Scores(ratio(tp + tn, len(y)), precision, recall, f1, ratio(fp, fp + tn))


def scores_at(y: np.ndarray, p: np.ndarray, threshold: float) -> Scores:
    return scores(y, (np.asarray(p) >= threshold).astype(int))


def bootstrap_ci(
    y: np.ndarray,
    predicted: np.ndarray,
    groups: list[str],
    *,
    n_boot: int = 1000,
    seed: int = SEED,
) -> dict[str, tuple[float, float]]:
    """95% percentile intervals of every metric, resampling groups with replacement."""
    y, predicted = np.asarray(y), np.asarray(predicted)
    labels, index = np.unique(np.asarray(groups), return_inverse=True)
    members = [np.flatnonzero(index == g) for g in range(len(labels))]
    rng = np.random.default_rng(seed)
    samples = {name: [] for name in Scores.__dataclass_fields__}
    for _ in range(n_boot):
        chosen = np.concatenate([members[g] for g in rng.integers(0, len(members), len(members))])
        s = scores(y[chosen], predicted[chosen])
        for name in samples:
            samples[name].append(getattr(s, name))
    return {
        name: (float(np.nanpercentile(v, 2.5)), float(np.nanpercentile(v, 97.5)))
        for name, v in samples.items()
    }


def mcnemar(y: np.ndarray, predicted_a: np.ndarray, predicted_b: np.ndarray) -> dict:
    """Exact McNemar test: do models A and B make different numbers of errors?"""
    y = np.asarray(y)
    a_right = np.asarray(predicted_a) == y
    b_right = np.asarray(predicted_b) == y
    only_a = int((a_right & ~b_right).sum())
    only_b = int((~a_right & b_right).sum())
    n = only_a + only_b
    p_value = binomtest(only_a, n, 0.5).pvalue if n else 1.0
    return {"only_a_right": only_a, "only_b_right": only_b, "p_value": float(p_value)}


def expected_calibration_error(y: np.ndarray, p: np.ndarray, bins: int = 10) -> float:
    y, p = np.asarray(y, dtype=float), np.asarray(p, dtype=float)
    edges = np.linspace(0.0, 1.0, bins + 1)
    which = np.clip(np.digitize(p, edges[1:-1], right=False), 0, bins - 1)
    error = 0.0
    for b in range(bins):
        in_bin = which == b
        if in_bin.any():
            error += in_bin.mean() * abs(p[in_bin].mean() - y[in_bin].mean())
    return float(error)


def threshold_for_fpr(y: np.ndarray, p: np.ndarray, max_fpr: float) -> float:
    """Lowest threshold whose false-positive rate on (y, p) is at most `max_fpr`."""
    y, p = np.asarray(y), np.asarray(p)
    negatives = np.sort(p[y == 0])[::-1]
    allowed = int(np.floor(max_fpr * len(negatives)))
    if allowed >= len(negatives):
        return 0.0
    # scores strictly above the (allowed+1)-th highest negative score flag at most `allowed`
    return float(np.nextafter(negatives[allowed], np.inf))
