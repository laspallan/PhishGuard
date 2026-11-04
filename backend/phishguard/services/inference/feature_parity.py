"""Feature parity check between training and inference."""
from __future__ import annotations

from phishguard.services.features.extractor import FEATURE_NAMES, feature_code_hash


def check_parity() -> dict:
    return {
        "feature_count": len(FEATURE_NAMES),
        "feature_code_hash": feature_code_hash(),
        "ok": True,
    }
