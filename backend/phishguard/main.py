"""FastAPI application entry point: builds the app and registers the views."""

from fastapi import FastAPI

from phishguard import __version__
from phishguard.core.config import get_settings
from phishguard.views import admin, health, models, scan


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title=settings.app_name, version=__version__)
    app.include_router(health.router)
    app.include_router(scan.router)
    app.include_router(models.router)
    app.include_router(admin.router)
    return app


app = create_app()
