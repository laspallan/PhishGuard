"""Celery app and background tasks (Phase 5)."""
from phishguard.workers.celery_app import app

__all__ = ["app"]
