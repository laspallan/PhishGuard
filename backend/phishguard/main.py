"""FastAPI application entry point: builds the app and registers the views."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from phishguard import __version__
from phishguard.core.config import get_settings
from phishguard.views import admin, extension, health, models, scan, simulation


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title=settings.app_name, version=__version__)
    # The dashboard is served from another origin and sends X-API-Key, so the browser asks first.
    # Only the listed origins; no cookies are used, so credentials stay off.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.dashboard_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["X-API-Key", "Content-Type"],
    )
    app.include_router(health.router)
    app.include_router(scan.router)
    app.include_router(models.router)
    app.include_router(admin.router)
    app.include_router(simulation.router)
    app.include_router(extension.router)
    return app


app = create_app()
