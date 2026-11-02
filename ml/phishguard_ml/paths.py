"""Where the pipeline reads and writes data.

All data lives under the repo-root `data/` folder (gitignored), or under
PHISHGUARD_DATA_DIR if that environment variable is set.
"""

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def data_dir() -> Path:
    override = os.environ.get("PHISHGUARD_DATA_DIR")
    return Path(override) if override else REPO_ROOT / "data"


def raw_dir() -> Path:
    """Downloads exactly as received: raw/<source>/<YYYY-MM-DD>/."""
    return data_dir() / "raw"


def snapshots_dir() -> Path:
    """Page, DNS, TLS and RDAP snapshots taken by the snapshot collector."""
    return data_dir() / "snapshots"


def processed_dir() -> Path:
    """Cleaned records and feature matrices."""
    return data_dir() / "processed"


def splits_dir() -> Path:
    """The frozen locked-test / development split and CV folds."""
    return data_dir() / "splits"


def models_dir() -> Path:
    """Trained models, out-of-fold predictions and their metadata (Phase 3)."""
    return data_dir() / "models"
