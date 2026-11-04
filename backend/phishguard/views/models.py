"""Models views."""
from __future__ import annotations

from fastapi import APIRouter

from phishguard.controllers.models_controller import ModelsController
from phishguard.schemas.models import ModelsResponse

router = APIRouter(prefix="/models", tags=["models"])
controller = ModelsController()


@router.get("", response_model=ModelsResponse)
def list_models():
    return controller.list()
