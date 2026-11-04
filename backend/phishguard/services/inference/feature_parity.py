"""Feature parity between training and inference (Phase 5 acceptance check).

A registered model may only score features computed by the same feature code it was trained
with: its recorded `feature_code_hash` must equal the current extractor's.
"""

from typing import Any

from phishguard.services.features.extractor import FEATURE_NAMES, feature_code_hash


def check_parity(entries: list[dict[str, Any]]) -> dict[str, Any]:
    current = feature_code_hash()
    stale = [e.get("version") for e in entries if e.get("feature_code_hash") != current]
    return {
        "feature_count": len(FEATURE_NAMES),
        "feature_code_hash": current,
        "stale_models": stale,
        "ok": not stale,
    }
