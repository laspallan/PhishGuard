"""Inference service (Phase 5).

No verdict is ever invented: until a trained model from the registry is wired in (Phase 5,
after the Phase 3 training runs), scans raise ModelNotLoadedError and the API answers 503, so
the extension and the gateway never act on a placeholder score.
"""

from typing import Any

from phishguard.services.inference.model_loader import ModelLoader


class ModelNotLoadedError(RuntimeError):
    """No trained model is registered / loaded yet."""


class InferenceService:
    def __init__(self, loader: ModelLoader | None = None):
        self.loader = loader or ModelLoader()
        self.loader.load_registry()

    @property
    def models_loaded(self) -> bool:
        return self.loader.loaded

    def _require_model(self) -> None:
        if not self.models_loaded:
            raise ModelNotLoadedError("no trained model is registered yet")
        # Registered models exist, but loading them for live scoring is Phase 5 work.
        raise ModelNotLoadedError("live scoring with registered models is not implemented yet")

    async def scan_url(self, url: str) -> dict[str, Any]:
        self._require_model()
        return {}

    async def scan_email(self, raw_email: str) -> dict[str, Any]:
        self._require_model()
        return {}
