"""Admin controller."""
from __future__ import annotations

from phishguard.services.features.extractor import FEATURE_NAMES


class AdminController:
    def status(self) -> dict:
        return {"status": "ok", "features_count": len(FEATURE_NAMES), "models_loaded": False}
