"""Models views."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from phishguard.controllers.models_controller import ModelsController
from phishguard.core.auth import require_api_key
from phishguard.schemas.models import ModelsResponse

router = APIRouter(prefix="/models", tags=["models"], dependencies=[Depends(require_api_key)])
controller = ModelsController()


@router.get("", response_model=ModelsResponse)
def list_models():
    return controller.list()
