"""Background tasks."""

from __future__ import annotations

from phishguard.workers.celery_app import app


@app.task
def scan_url_task(url: str) -> dict:
    # Placeholder - real implementation would call inference
    return {"url": url, "status": "queued"}


@app.task
def ti_lookup_task(url: str) -> dict:
    return {"url": url, "status": "queued"}
