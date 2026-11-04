"""RQ3 harness stub."""
from __future__ import annotations


class RQ3Harness:
    def run_round(self, round_num: int, seed: int = 42):
        # Stub for A/B/C comparison
        return {
            "round": round_num,
            "seed": seed,
            "model_a_f1": 0.0,
            "model_b_f1": 0.0,
            "model_c_f1": 0.0,
        }
