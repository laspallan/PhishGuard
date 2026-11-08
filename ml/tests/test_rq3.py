"""The RQ3 harness on replayed monthly data with fake simulation samples."""

import numpy as np
import pytest

from phishguard_ml.training.rq3 import (
    Pool,
    check_simulation_samples,
    run_round,
    should_promote,
    training_sets,
)

RF = {"n_estimators": 10}


def _pool(n, *, phishing_share=0.5, prefix="s", source="feed", seed=0) -> Pool:
    rng = np.random.default_rng(seed)
    y = (np.arange(n) < round(n * phishing_share)).astype(int)
    X = rng.normal(size=(n, 3))
    X[:, 0] += y * 3
    return Pool(
        X, y, [f"{prefix}{i}" for i in range(n)], [f"{prefix}g{i}" for i in range(n)], [source] * n
    )


def _simulation(n, prefix="sim", seed=1) -> Pool:
    return _pool(n, phishing_share=1.0, prefix=prefix, source="simulation", seed=seed)


def test_b_and_c_have_the_same_size_and_label_balance_and_a_is_static():
    development, fresh = _pool(100, prefix="d"), _pool(60, prefix="f", seed=2)
    for k in (0, 1, 7, 30):
        arms = training_sets(development, fresh, _simulation(30), k, seed=42)
        assert len(arms["B"]) == len(arms["C"]) == 160
        assert arms["B"].y.sum() == arms["C"].y.sum()
        assert sum(s == "simulation" for s in arms["C"].sources) == k
        assert sum(s == "simulation" for s in arms["B"].sources) == 0
        assert arms["A"].ids == development.ids


def test_c_only_replaces_phishing_samples_and_keeps_the_development_set():
    development, fresh = _pool(100, prefix="d"), _pool(60, prefix="f", seed=2)
    c = training_sets(development, fresh, _simulation(30), 10, seed=42)["C"]
    assert set(development.ids) <= set(c.ids)
    removed = set(fresh.ids) - set(c.ids)
    assert len(removed) == 10
    assert all(fresh.y[fresh.ids.index(i)] == 1 for i in removed)


def test_k_cannot_exceed_what_is_available():
    with pytest.raises(ValueError):
        training_sets(_pool(10), _pool(10, prefix="f"), _simulation(3), 4, seed=42)


def test_a_simulation_sample_can_never_be_in_the_locked_test_set():
    with pytest.raises(ValueError, match="locked test set"):
        check_simulation_samples(_simulation(3), _simulation(3, "hold"), {"sim1"})
    with pytest.raises(ValueError, match="locked test set"):
        check_simulation_samples(_simulation(3), _simulation(3, "hold"), {"hold2"})


def test_a_holdout_sample_can_never_be_trained_on():
    with pytest.raises(ValueError, match="holdout"):
        check_simulation_samples(_simulation(3), _simulation(3), set())


def test_only_real_simulation_samples_are_accepted():
    with pytest.raises(ValueError, match="source=simulation"):
        check_simulation_samples(_pool(4, phishing_share=1.0), _simulation(2, "h"), set())
    legitimate = Pool(np.zeros((1, 3)), np.array([0]), ["x"], ["g"], ["simulation"])
    with pytest.raises(ValueError, match="phishing"):
        check_simulation_samples(legitimate, _simulation(2, "h"), set())


def test_a_round_runs_end_to_end_on_replayed_months():
    development = _pool(120, prefix="d")
    months = [_pool(60, prefix=f"m{i}", seed=i + 3) for i in range(3)]
    holdout = _simulation(20, "hold", seed=9)

    for r in (1, 2):
        result = run_round(
            r,
            model="random_forest",
            params=RF,
            development=development,
            fresh_so_far=Pool(
                np.vstack([m.X for m in months[:r]]),
                np.concatenate([m.y for m in months[:r]]),
                [i for m in months[:r] for i in m.ids],
                [g for m in months[:r] for g in m.groups],
                [s for m in months[:r] for s in m.sources],
            ),
            next_month=months[r],
            simulation=_simulation(15),
            holdout=holdout,
            locked_test_ids=set(),
            seeds=(42, 43),
            n_boot=10,
        )
        # 2 seeds x 3 arms x 2 evaluation sets; 2 seeds x 3 comparisons x 2 sets
        assert len(result["runs"]) == 12 and len(result["comparisons"]) == 12
        assert result["k"] == 15
        b = [x for x in result["runs"] if x["arm"] == "B"]
        c = [x for x in result["runs"] if x["arm"] == "C"]
        assert {x["n_train"] for x in b} == {x["n_train"] for x in c}
        assert {x["n_train_phishing"] for x in b} == {x["n_train_phishing"] for x in c}
        assert {x["comparison"] for x in result["comparisons"]} == {"B-A", "C-B", "C-A"}
        fresh = [x for x in result["runs"] if x["eval_set"] == "fresh_feed"]
        assert all(x["f1"] > 0.8 for x in fresh)  # the pattern is easy on purpose


def test_same_seed_repeats_the_round():
    options = dict(
        model="random_forest", params=RF, development=_pool(80, prefix="d"),
        fresh_so_far=_pool(40, prefix="f", seed=2), next_month=_pool(30, prefix="n", seed=3),
        simulation=_simulation(10), holdout=_simulation(10, "h"), locked_test_ids=set(),
        seeds=(42,), n_boot=5,
    )  # fmt: skip
    first, second = run_round(1, **options), run_round(1, **options)
    assert [r["f1"] for r in first["runs"]] == [r["f1"] for r in second["runs"]]


def _metrics(f1_locked, fpr_locked, f1_hold, fpr_hold=float("nan")):
    return {
        "locked_test": {"f1": f1_locked, "fpr": fpr_locked},
        "sim_holdout": {"f1": f1_hold, "fpr": fpr_hold},
    }


@pytest.mark.parametrize(
    ("candidate", "expected"),
    [
        (_metrics(0.91, 0.01, 0.81), True),
        (_metrics(0.91, 0.009, 0.81), True),
        (_metrics(0.90, 0.01, 0.81), False),  # F1 must improve, not just hold
        (_metrics(0.91, 0.02, 0.81), False),  # FPR rose on the locked test set
        (_metrics(0.91, 0.01, 0.79), False),  # F1 fell on the holdout
        (_metrics(float("nan"), 0.01, 0.81), False),  # an undefined score never promotes
    ],
)
def test_promotion_rule(candidate, expected):
    assert should_promote(_metrics(0.90, 0.01, 0.80), candidate) is expected
