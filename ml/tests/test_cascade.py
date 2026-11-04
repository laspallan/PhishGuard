import numpy as np
import pytest

from phishguard_ml.training.cascade import Cascade


class Fixed:
    """A stand-in model that returns fixed P(phishing) and records what it was asked."""

    def __init__(self, p):
        self.p = np.asarray(p, dtype=float)
        self.asked: list = []

    def predict_proba(self, X):
        self.asked.append(list(X))
        values = self.p[: len(X)] if len(self.p) >= len(X) else np.full(len(X), self.p[0])
        return np.column_stack([1 - values, values])


def test_cascade_asks_the_text_model_only_inside_the_band():
    tabular = Fixed([0.10, 0.55, 0.95])
    text = Fixed([0.99])
    p = Cascade(tabular, text).predict_proba(np.zeros((3, 2)), ["a", "b", "c"])
    assert p.tolist() == [0.10, 0.99, 0.95]
    assert text.asked == [["b"]]  # only the sample with 0.55


def test_cascade_requires_the_text_model():
    with pytest.raises(ValueError):
        Cascade(Fixed([0.5]), None).predict_proba(np.zeros((1, 2)), ["a"])
