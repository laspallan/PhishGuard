"""Cascade: tabular first, DistilBERT if score in [0.30, 0.80]."""
from __future__ import annotations


class Cascade:
    def __init__(self, tabular_model=None, transformer_model=None):
        self.tabular = tabular_model
        self.transformer = transformer_model
        self.low = 0.30
        self.high = 0.80

    def predict_proba(self, X_tabular, X_text=None):
        if self.tabular is None:
            raise ValueError("tabular model required")
        p = self.tabular.predict_proba(X_tabular)[:, 1]
        # If transformer available and score in range, could refine - stub
        return p
