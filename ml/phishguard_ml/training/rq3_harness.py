"""RQ3 harness: A/B/C comparison with simulation data."""

from __future__ import annotations


class RQ3Harness:
    def __init__(self, seed: int = 42):
        self.seed = seed

    def run_round(self, round_num: int, data_feeds, sim_samples):
        # Model A: static up to month M
        # Model B: dev + fresh feed
        # Model C: B with k phishing replaced by k sim samples (size-matched)
        raise NotImplementedError("RQ3 rounds run in Phase 6, after ethics approval")
