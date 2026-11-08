"""RQ3 harness: does retraining with failed-simulation samples help? (Phase 6)

For round r, each arm trains with the same model type, features, parameters and seed:
  A  static: the development set only
  B  development + every fresh sample up to month M+r-1
  C  B with k fresh phishing samples replaced by k simulation samples (same size, same labels)
All three are scored on the fresh data of month M+r and on the simulation-holdout set. C against
B is the main comparison, because the only difference between them is the k samples.

Scores use threshold 0.5 on uncalibrated probabilities, the same for every arm: calibrating would
add another fitted step that differs between arms. Differences get a group-bootstrap 95% CI and
an exact McNemar test.

Guards: the holdout templates never reach training, and a simulation sample can never be in the
locked test set (`check_simulation_samples`). The locked test set itself is not read here.
"""

from collections.abc import Iterable
from dataclasses import asdict, dataclass

import numpy as np

from phishguard_ml.evaluation import metrics
from phishguard_ml.training import tabular

SEEDS = (42, 43, 44, 45, 46)
SIMULATION = "simulation"
COMPARISONS = (("B", "A"), ("C", "B"), ("C", "A"))  # C vs B is the main one
THRESHOLD = 0.5


@dataclass(frozen=True)
class Pool:
    X: np.ndarray
    y: np.ndarray
    ids: list[str]
    groups: list[str]
    sources: list[str]

    def __len__(self) -> int:
        return len(self.y)

    def take(self, index: np.ndarray) -> "Pool":
        return Pool(
            self.X[index],
            self.y[index],
            [self.ids[i] for i in index],
            [self.groups[i] for i in index],
            [self.sources[i] for i in index],
        )


def join(pools: Iterable[Pool]) -> Pool:
    pools = list(pools)
    return Pool(
        np.vstack([p.X for p in pools]),
        np.concatenate([p.y for p in pools]),
        [i for p in pools for i in p.ids],
        [g for p in pools for g in p.groups],
        [s for p in pools for s in p.sources],
    )


def check_simulation_samples(train: Pool, holdout: Pool, locked_test_ids: set[str]) -> None:
    for pool in (train, holdout):
        if set(pool.sources) - {SIMULATION}:
            raise ValueError("every simulation sample must have source=simulation")
        if (pool.y != 1).any():
            raise ValueError("simulation samples are phishing by definition")
    if set(train.ids) & set(holdout.ids):
        raise ValueError("a simulation-holdout sample is in the training samples")
    if (set(train.ids) | set(holdout.ids)) & locked_test_ids:
        raise ValueError("a simulation sample is in the locked test set")


def training_sets(
    development: Pool, fresh_so_far: Pool, simulation: Pool, k: int, seed: int
) -> dict[str, Pool]:
    """The three arms. B and C have the same size and the same label balance by construction."""
    phishing = np.flatnonzero(fresh_so_far.y == 1)
    if k > len(phishing) or k > len(simulation):
        raise ValueError(
            f"k={k} needs that many fresh phishing ({len(phishing)}) "
            f"and simulation samples ({len(simulation)})"
        )
    rng = np.random.default_rng(seed)
    removed = rng.choice(phishing, size=k, replace=False)
    kept = np.setdiff1d(np.arange(len(fresh_so_far)), removed)
    added = rng.choice(len(simulation), size=k, replace=False)
    return {
        "A": development,
        "B": join([development, fresh_so_far]),
        "C": join([development, fresh_so_far.take(kept), simulation.take(added)]),
    }


def _difference_ci(y, predicted_a, predicted_b, groups, *, n_boot, seed) -> dict:
    """95% interval of (a - b) for F1, recall and FPR, resampling groups with both models paired."""
    labels, index = np.unique(np.asarray(groups), return_inverse=True)
    members = [np.flatnonzero(index == g) for g in range(len(labels))]
    rng = np.random.default_rng(seed)
    samples: dict[str, list[float]] = {"f1": [], "recall": [], "fpr": []}
    for _ in range(n_boot):
        chosen = np.concatenate([members[g] for g in rng.integers(0, len(members), len(members))])
        a = metrics.scores(y[chosen], predicted_a[chosen])
        b = metrics.scores(y[chosen], predicted_b[chosen])
        for name in samples:
            samples[name].append(getattr(a, name) - getattr(b, name))
    out = {}
    for name, values in samples.items():
        values = np.asarray(values, dtype=float)
        finite = values[np.isfinite(values)]
        out[name] = (
            (float(np.percentile(finite, 2.5)), float(np.percentile(finite, 97.5)))
            if len(finite)
            else (float("nan"), float("nan"))
        )
    return out


def run_round(
    round_number: int,
    *,
    model: str,
    params: dict,
    development: Pool,
    fresh_so_far: Pool,
    next_month: Pool,
    simulation: Pool,
    holdout: Pool,
    locked_test_ids: set[str],
    k: int | None = None,
    seeds: Iterable[int] = SEEDS,
    n_boot: int = 1000,
) -> dict:
    check_simulation_samples(simulation, holdout, locked_test_ids)
    if k is None:
        k = min(len(simulation), int((fresh_so_far.y == 1).sum()))
    evaluation_sets = {"fresh_feed": next_month, "sim_holdout": holdout}
    runs, comparisons = [], []
    for seed in seeds:
        arms = training_sets(development, fresh_so_far, simulation, k, seed)
        predicted: dict[str, dict[str, np.ndarray]] = {}
        for arm, data in arms.items():
            fitted = tabular.make_model(model, params, seed).fit(data.X, data.y)
            predicted[arm] = {
                name: (fitted.predict_proba(pool.X)[:, 1] >= THRESHOLD).astype(int)
                for name, pool in evaluation_sets.items()
            }
            for name, pool in evaluation_sets.items():
                runs.append(
                    {
                        "round": round_number,
                        "seed": seed,
                        "arm": arm,
                        "eval_set": name,
                        "k": k if arm == "C" else 0,
                        "n_train": len(data),
                        "n_train_phishing": int(data.y.sum()),
                        **asdict(metrics.scores(pool.y, predicted[arm][name])),
                    }
                )
        for name, pool in evaluation_sets.items():
            for first, second in COMPARISONS:
                a, b = predicted[first][name], predicted[second][name]
                comparisons.append(
                    {
                        "round": round_number,
                        "seed": seed,
                        "eval_set": name,
                        "comparison": f"{first}-{second}",
                        "difference_ci95": _difference_ci(
                            pool.y, a, b, pool.groups, n_boot=n_boot, seed=seed
                        ),
                        "mcnemar": metrics.mcnemar(pool.y, a, b),
                    }
                )
    return {"round": round_number, "k": k, "runs": runs, "comparisons": comparisons}


def should_promote(current: dict, candidate: dict) -> bool:
    """Promote only if F1 rises and FPR does not, on both the locked test set and the holdout.
    A holdout of phishing only has no FPR (NaN): that cannot count as a rise."""
    for set_name in ("locked_test", "sim_holdout"):
        now, new = current[set_name], candidate[set_name]
        if not new["f1"] > now["f1"]:
            return False
        if np.isfinite(new["fpr"]) and np.isfinite(now["fpr"]) and new["fpr"] > now["fpr"]:
            return False
    return True
