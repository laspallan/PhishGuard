"""Probability calibration of out-of-fold predictions (isotonic regression).

Cross-fitted: the calibrated value of a sample in fold k comes from a calibrator fitted on the
OOF predictions of the other folds, so no sample is calibrated with its own label (that would
make calibration look better than it is). The calibrator used for deployment is fitted on all
OOF predictions. Isotonic rather than Platt (sigmoid) scaling: tree-model scores are often not
sigmoid-shaped, and tens of thousands of OOF predictions are enough for isotonic not to overfit.
"""

import numpy as np
from sklearn.isotonic import IsotonicRegression


def fit_calibrator(p: np.ndarray, y: np.ndarray) -> IsotonicRegression:
    return IsotonicRegression(y_min=0.0, y_max=1.0, out_of_bounds="clip").fit(p, y)


def cross_fitted(p: np.ndarray, y: np.ndarray, folds: np.ndarray) -> np.ndarray:
    calibrated = np.full(len(p), np.nan)
    for fold in np.unique(folds):
        held_out = folds == fold
        calibrator = fit_calibrator(p[~held_out], y[~held_out])
        calibrated[held_out] = calibrator.predict(p[held_out])
    return calibrated
