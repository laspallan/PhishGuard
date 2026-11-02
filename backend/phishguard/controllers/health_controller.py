"""Liveness check. Database and Redis checks are added in Phase 5, when the API uses them."""

from phishguard import __version__
from phishguard.core.config import Settings
from phishguard.schemas.health import HealthResponse


def get_health(settings: Settings) -> HealthResponse:
    return HealthResponse(
        status="ok",
        app_name=settings.app_name,
        version=__version__,
        environment=settings.environment,
    )
