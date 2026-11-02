import numpy as np
import pytest

from phishguard_ml.evaluation import metrics
from phishguard_ml.training import calibration


def test_scores_by_hand():
    y = np.array([1, 1, 1, 0, 0, 0, 0, 0])
    predicted = np.array([1, 1, 0, 1, 0, 0, 0, 0])  # TP 2, FN 1, FP 1, TN 4
    s = metrics.scores(y, predicted)
    assert s.accuracy == pytest.approx(6 / 8)
    assert s.precision == pytest.approx(2 / 3)
    assert s.recall == pytest.approx(2 / 3)
    assert s.f1 == pytest.approx(2 * 2 / (2 * 2 + 1 + 1))
    assert s.fpr == pytest.approx(1 / 5)
    assert np.isnan(metrics.scores(y, np.zeros(8)).precision)  # nothing predicted positive


def test_scores_at_threshold_includes_the_threshold():
    s = metrics.scores_at(np.array([1, 0]), np.array([0.9, 0.6]), 0.9)
    assert s.recall == 1 and s.fpr == 0


def test_group_bootstrap_is_reproducible_and_brackets_the_estimate():
    rng = np.random.default_rng(1)
    y = rng.integers(0, 2, 400)
    predicted = np.where(rng.random(400) < 0.85, y, 1 - y)
    groups = [f"g{i // 4}" for i in range(400)]  # 100 groups of 4
    ci = metrics.bootstrap_ci(y, predicted, groups, n_boot=200)
    assert ci == metrics.bootstrap_ci(y, predicted, groups, n_boot=200)
    low, high = ci["accuracy"]
    assert low <= metrics.scores(y, predicted).accuracy <= high


def test_mcnemar_exact_by_hand():
    y = np.ones(10, dtype=int)
    result = metrics.mcnemar(y, np.ones(10), np.zeros(10))  # A right 10 times where B is wrong
    assert result["only_a_right"] == 10 and result["only_b_right"] == 0
    assert result["p_value"] == pytest.approx(2 * 0.5**10)
    assert metrics.mcnemar(y, np.ones(10), np.ones(10))["p_value"] == 1.0


def test_expected_calibration_error_by_hand():
    # bin [0.8, 0.9): 4 predictions of 0.8, 2 positives -> |0.8 - 0.5| * 4/4
    assert metrics.expected_calibration_error(np.array([1, 1, 0, 0]), np.full(4, 0.8)) == (
        pytest.approx(0.3)
    )


def test_threshold_for_fpr():
    y = np.array([0] * 10 + [1] * 5)
    p = np.array([0.05 * i for i in range(10)] + [0.9] * 5)  # negatives 0.00 .. 0.45
    t = metrics.threshold_for_fpr(y, p, max_fpr=0.1)  # 1 of 10 negatives may be flagged
    assert metrics.scores_at(y, p, t).fpr <= 0.1
    assert 0.4 < t <= 0.45 + 1e-9


def test_cross_fitted_calibration_never_uses_the_samples_own_fold():
    rng = np.random.default_rng(0)
    p = rng.random(500)
    y = (rng.random(500) < p).astype(int)
    folds = np.arange(500) % 5
    first = calibration.cross_fitted(p, y, folds)

    changed = y.copy()
    changed[folds == 0] = 1 - changed[folds == 0]  # flip every label in fold 0
    again = calibration.cross_fitted(p, changed, folds)

    assert np.array_equal(first[folds == 0], again[folds == 0])  # fold 0 unaffected
    assert not np.array_equal(first[folds != 0], again[folds != 0])
    assert ((first >= 0) & (first <= 1)).all()
