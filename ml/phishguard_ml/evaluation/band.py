"""The stage-1 "uncertain" band for live URL scans (D11b), on development predictions only.

The band decides how many URLs get their page fetched. Given a target share of URLs to fetch, it
takes the band around 0.5 that holds that share of M1's calibrated out-of-fold scores, and reports
how often M1 alone would be wrong on the URLs it decides by itself. Those errors are what the
share buys: a wider band fetches more pages and leaves fewer mistakes to M1.
"""

import json

import numpy as np
import pyarrow.parquet as pq

from phishguard_ml import paths
from phishguard_ml.training import calibration, ensembles
from phishguard_ml.training.tabular import MODELS

FEATURE_SET = "live_stage1"
SHARES = (0.05, 0.10, 0.20, 0.30, 0.50)


def band_for_share(p: np.ndarray, y: np.ndarray, share: float) -> dict:
    """Band and error rates outside it. `share` of the URLs fall inside, ties aside."""
    half_width = float(np.quantile(np.abs(p - 0.5), share))
    low, high = max(0.5 - half_width, 0.0), min(0.5 + half_width, 1.0)
    outside = (p <= low) | (p >= high)
    decided_y, decided_p = y[outside], p[outside]
    legitimate, phishing = decided_y == 0, decided_y == 1
    return {
        "target_share": share,
        "low": low,
        "high": high,
        "share_fetched": float((~outside).mean()),
        # allow below 0.60 and warn or block from it, as the live decision does
        "fpr_without_fetch": float((decided_p[legitimate] >= ensembles.WARN).mean())
        if legitimate.any()
        else float("nan"),
        "miss_rate_without_fetch": float((decided_p[phishing] < ensembles.WARN).mean())
        if phishing.any()
        else float("nan"),
    }


def choose(shares: tuple[float, ...] = SHARES) -> dict:
    """One table per trained M1 model; the model with the lowest log loss is what is served."""
    tables = {}
    for model in MODELS:
        path = paths.models_dir() / "url" / FEATURE_SET / model / "oof.parquet"
        if not path.exists():
            continue
        oof = pq.read_table(path)
        y = np.asarray(oof.column("label")).astype(int)
        p = calibration.cross_fitted(
            np.asarray(oof.column("p_phishing")), y, np.asarray(oof.column("fold")).astype(int)
        )
        tables[model] = [band_for_share(p, y, share) for share in shares]
    if not tables:
        raise FileNotFoundError("M1 is not trained yet (url/live_stage1)")
    (paths.models_dir() / "stage1_band.json").write_text(json.dumps(tables, indent=1))
    return tables
