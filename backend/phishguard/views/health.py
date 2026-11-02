from typing import Annotated

from fastapi import APIRouter, Depends

from phishguard.controllers import health_controller
from phishguard.core.config import Settings, get_settings
from phishguard.schemas.health import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health(settings: Annotated[Settings, Depends(get_settings)]) -> HealthResponse:
    return health_controller.get_health(settings)
