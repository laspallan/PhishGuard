"""Celery app for background tasks (Phase 5)."""
from __future__ import annotations

from celery import Celery

from phishguard.core.config import get_settings

settings = get_settings()
broker = settings.redis_url or "redis://localhost:6379/0"
backend = settings.redis_url or "redis://localhost:6379/0"

app = Celery("phishguard", broker=broker, backend=backend)

app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)
