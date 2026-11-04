"""Inference service package."""

from phishguard.services.inference.service import InferenceService, ModelNotLoadedError

__all__ = ["InferenceService", "ModelNotLoadedError"]
