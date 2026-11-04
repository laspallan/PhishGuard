"""Cascade: tabular first, DistilBERT if score in [0.30, 0.80].

The band rule itself is `ensembles.cascade` (tested); this class wires two fitted models to it.
"""

from __future__ import annotations

from phishguard_ml.training import ensembles


class Cascade:
    def __init__(self, tabular_model=None, transformer_model=None):
        self.tabular = tabular_model
        self.transformer = transformer_model
        self.low, self.high = ensembles.CASCADE_BAND

    def predict_proba(self, X_tabular, X_text=None):
        if self.tabular is None:
            raise ValueError("tabular model required")
        p = self.tabular.predict_proba(X_tabular)[:, 1]
        if self.transformer is None or X_text is None:
            raise ValueError("cascade needs the text model and the text inputs")
        in_band = ensembles.in_cascade_band(p, (self.low, self.high))
        p_text = p.copy()
        if in_band.any():  # the text model is asked only inside the band (saves latency)
            selected = [t for t, keep in zip(X_text, in_band, strict=True) if keep]
            p_text[in_band] = self.transformer.predict_proba(selected)[:, 1]
        return ensembles.cascade(p, p_text, (self.low, self.high))
