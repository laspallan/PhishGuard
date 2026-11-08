import numpy as np
import pytest

from phishguard_ml.evaluation.band import band_for_share, choose


def test_the_band_holds_about_the_target_share_and_is_centred():
    rng = np.random.default_rng(0)
    p = rng.uniform(0, 1, 10_000)
    y = (p > 0.5).astype(int)
    row = band_for_share(p, y, 0.2)
    assert row["share_fetched"] == pytest.approx(0.2, abs=0.01)
    assert row["low"] == pytest.approx(0.4, abs=0.01)
    assert row["high"] == pytest.approx(0.6, abs=0.01)


def test_errors_are_counted_by_hand():
    p = np.array([0.0, 0.05, 0.95, 1.0, 0.1, 0.9, 0.5, 0.5])
    y = np.array([0, 0, 0, 1, 1, 1, 0, 1])
    row = band_for_share(p, y, 0.25)
    # Decided alone: 3 legitimate (0.0, 0.05, 0.95), one wrongly at or above 0.60.
    assert row["fpr_without_fetch"] == pytest.approx(1 / 3)
    # Decided alone: 3 phishing (1.0, 0.1, 0.9), one wrongly below 0.60.
    assert row["miss_rate_without_fetch"] == pytest.approx(1 / 3)


def test_a_wider_band_fetches_more():
    rng = np.random.default_rng(1)
    p, y = rng.uniform(0, 1, 2000), rng.integers(0, 2, 2000)
    shares = [band_for_share(p, y, s)["share_fetched"] for s in (0.05, 0.2, 0.5)]
    assert shares == sorted(shares)


def test_no_band_before_m1_exists():
    with pytest.raises(FileNotFoundError):
        choose()
