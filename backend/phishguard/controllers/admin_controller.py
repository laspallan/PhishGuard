"""Admin controller."""

from phishguard.services.features.extractor import FEATURE_NAMES
from phishguard.services.inference.model_loader import ModelLoader


class AdminController:
    def status(self) -> dict:
        loader = ModelLoader()
        loader.load_registry()
        return {
            "status": "ok",
            "features_count": len(FEATURE_NAMES),
            "models_loaded": loader.loaded,
        }
