"""Models controller: the versions registered by the training pipeline."""

from phishguard.services.inference.model_loader import ModelLoader


class ModelsController:
    def list(self) -> dict:
        loader = ModelLoader()
        return {
            "models": [
                {
                    "name": e.get("model", ""),
                    "modality": e.get("modality", ""),
                    "version": e.get("version"),
                    "metrics": {"oof_log_loss": e["oof_log_loss"]} if "oof_log_loss" in e else None,
                }
                for e in loader.load_registry()
            ]
        }
