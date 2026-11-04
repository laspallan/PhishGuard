"""RQ3 harness: A/B/C comparison with simulation data."""
from __future__ import annotations


class RQ3Harness:
    def __init__(self, seed: int = 42):
        self.seed = seed

    def run_round(self, round_num: int, data_feeds, sim_samples):
        # Model A: static up to month M
        # Model B: dev + fresh feed
        # Model C: B with k phishing replaced by k sim samples (size-matched)
        return {
            "round": round_num,
            "seed": self.seed,
            "model_a": {"f1": 0.0, "fpr": 0.0},
            "model_b": {"f1": 0.0, "fpr": 0.0},
            "model_c": {"f1": 0.0, "fpr": 0.0},
        }
