"""The API's side of live evidence (decision D11): ask the collector through Redis, wait until
the deadline, never contact the scanned URL. No answer in time means None, never an error, so
the scan can still answer from what it already has (marked partial)."""

import logging

from phishguard.services.evidence import EVIDENCE_QUEUE, EVIDENCE_TASK
from phishguard.workers.celery_app import app

log = logging.getLogger(__name__)

# The collector gets 0.5 s less than this, for the way through Redis and back.
WAIT_SECONDS = 6.5


def request_evidence(
    url: str, stage: int, *, celery=app, wait_seconds: float = WAIT_SECONDS
) -> dict | None:
    """The collector's answer, or None if it is late, failed, or Redis is down. Blocks: call it
    with asyncio.to_thread from async code."""
    try:
        job = celery.send_task(
            EVIDENCE_TASK,
            args=[url, stage, max(wait_seconds - 0.5, 0.5)],
            queue=EVIDENCE_QUEUE,
            expires=wait_seconds,  # nobody is waiting after that: the worker must not fetch it
            retry=False,
        )
        return job.get(timeout=wait_seconds)
    except Exception as error:  # any failure here is a degraded answer, not a failed scan
        log.warning("no evidence: %s", type(error).__name__)  # the URL stays out of the logs
        return None
