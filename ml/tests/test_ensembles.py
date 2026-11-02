import numpy as np
import pytest

from phishguard_ml.training import ensembles


def test_soft_vote_is_the_mean():
    assert ensembles.soft_vote([np.array([0.2, 1.0]), np.array([0.4, 0.0])]).tolist() == [
        pytest.approx(0.3),
        pytest.approx(0.5),
    ]


def test_stacker_out_of_fold_ignores_the_folds_own_labels():
    rng = np.random.default_rng(0)
    y = rng.integers(0, 2, 400)
    good = np.clip(y * 0.7 + rng.random(400) * 0.3, 0, 1)
    noise = rng.random(400)
    folds = np.arange(400) % 5
    first = ensembles.stacked_out_of_fold([good, noise], y, folds)

    flipped = y.copy()
    flipped[folds == 2] = 1 - flipped[folds == 2]
    again = ensembles.stacked_out_of_fold([good, noise], flipped, folds)

    assert np.allclose(first[folds == 2], again[folds == 2])
    assert ((first > 0.5) == y).mean() > 0.9  # learns to trust the good model


def test_stacker_weights_the_informative_model():
    rng = np.random.default_rng(1)
    y = rng.integers(0, 2, 500)
    good, noise = np.clip(y * 0.8 + rng.random(500) * 0.2, 0, 1), rng.random(500)
    model = ensembles.fit_stacker([good, noise], y)
    assert abs(model.coef_[0][0]) > 5 * abs(model.coef_[0][1])


def test_decisions_at_the_plan_thresholds():
    assert ensembles.decide(np.array([0.59, 0.60, 0.89, 0.90])).tolist() == [
        "allow", "warn", "warn", "block",
    ]  # fmt: skip


def test_cascade_uses_the_text_model_only_inside_the_band():
    tab = np.array([0.10, 0.30, 0.55, 0.80, 0.95])
    text = np.array([0.99, 0.99, 0.99, 0.01, 0.01])
    assert ensembles.cascade(tab, text).tolist() == [0.10, 0.99, 0.99, 0.01, 0.95]
    assert ensembles.in_cascade_band(tab).sum() == 3  # 0.30, 0.55, 0.80 (inclusive)
