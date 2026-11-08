"""Live scan evidence collector (Phase 5, decision D11; Docs/live_url_scanning.md).

A Celery worker in the same locked-down image as the snapshot collector. It reuses the snapshot
functions, so live and training evidence have one format; the API never contacts a scanned URL.

  stage 1  DNS only: resolvers, never the target host
  stage 2  + page and TLS: the target host, and only if the URL is safe to fetch (D11d)

Everything runs in parallel under one deadline. What is late is left out and listed in `late`;
the answer still comes back, so the API can decide on what it has. Nothing is written to disk.
"""

import base64
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx

from phishguard.services.evidence import (
    EVIDENCE_QUEUE,
    EVIDENCE_TASK,
    STAGE_FETCH,
    STAGE_NO_TARGET_CONTACT,
    is_safe_to_fetch,
)
from phishguard.workers.celery_app import app
from phishguard_ml.data import snapshot
from phishguard_ml.data.download import user_agent
from phishguard_ml.data.records import Source

log = logging.getLogger(__name__)

DEADLINE_SECONDS = 6.0
DNS_LIFETIME = 1.4  # per record type; dns_info asks for four
TLS_TIMEOUT = 2.5  # per attempt; tls_info can make two
SOFT_LIMIT_SECONDS = 8  # Celery's backstop (e.g. a hung system DNS lookup in a thread)
HARD_LIMIT_SECONDS = 10

_client: httpx.Client | None = None  # one per worker process, each handling one job at a time


def _http_client() -> httpx.Client:
    global _client
    if _client is None:
        _client = snapshot.pinned_client(headers={"User-Agent": user_agent(Source.TRANCO)})
    return _client


def collect(
    url: str,
    stage: int,
    *,
    deadline_seconds: float = DEADLINE_SECONDS,
    client: httpx.Client | None = None,
) -> dict:
    """The evidence for one URL: {stage, meta, page_b64, dns, tls, late}."""
    if os.environ.get(snapshot.CONTAINER_FLAG) != "1":
        raise snapshot.NotInSnapshotContainerError(
            "Evidence is collected only inside the evidence-collector container."
        )
    if stage not in (STAGE_NO_TARGET_CONTACT, STAGE_FETCH):
        raise ValueError(f"unknown stage {stage!r}")
    answer: dict = {
        "stage": stage,
        "meta": {"url": url, "fetched_at": datetime.now(UTC).isoformat()},
        "page_b64": None,
        "dns": None,
        "tls": None,
        "late": [],
    }
    try:
        host = urlsplit(url).hostname or ""
        snapshot.check_safe_target(url)
    except (snapshot.UnsafeTargetError, ValueError) as error:
        answer["meta"]["skipped"] = str(error)
        if "does not resolve" not in str(error):
            answer["meta"]["unsafe_host"] = True  # same rule as take_snapshot: no DNS, no TLS
            return answer
    if stage == STAGE_FETCH and not is_safe_to_fetch(url):
        answer["meta"]["skipped"] = "not safe to fetch: stage 2 refused"
        answer["refused"] = True
        return answer

    deadline = time.monotonic() + deadline_seconds
    # Not a `with` block: its exit would wait for threads that are already late.
    pool = ThreadPoolExecutor(max_workers=3)
    jobs = {"dns": pool.submit(snapshot.dns_info, host, DNS_LIFETIME)}
    if stage == STAGE_FETCH:
        http = client or _http_client()
        jobs["page"] = pool.submit(snapshot.fetch_page, url, http, deadline=deadline)
        jobs["tls"] = pool.submit(snapshot.tls_info, host, timeout=TLS_TIMEOUT)
    for name, job in jobs.items():
        try:
            value = job.result(timeout=max(deadline - time.monotonic(), 0))
        except FutureTimeoutError:
            answer["late"].append(name)
            continue
        if name == "page":
            meta, html = value
            answer["meta"] = meta
            answer["page_b64"] = base64.b64encode(html).decode() if html is not None else None
            if meta.get("skipped") == "deadline":
                answer["late"].append("page")
        else:
            answer[name] = value
    pool.shutdown(wait=False, cancel_futures=True)
    if answer["meta"].get("unsafe_host"):  # e.g. it changed its answer between the two checks
        answer["dns"] = answer["tls"] = None
    return answer


@app.task(name=EVIDENCE_TASK, soft_time_limit=SOFT_LIMIT_SECONDS, time_limit=HARD_LIMIT_SECONDS)
def collect_evidence(url: str, stage: int, deadline_seconds: float = DEADLINE_SECONDS) -> dict:
    return collect(url, stage, deadline_seconds=min(deadline_seconds, DEADLINE_SECONDS))


def run_worker(concurrency: int) -> None:
    if os.environ.get(snapshot.CONTAINER_FLAG) != "1":
        raise snapshot.NotInSnapshotContainerError(
            "The evidence worker runs only inside its container "
            "(docker compose --profile live up -d evidence-collector)."
        )
    app.worker_main(
        [
            "worker",
            f"--queues={EVIDENCE_QUEUE}",
            f"--concurrency={concurrency}",
            "--loglevel=INFO",
            "--without-gossip",
            "--without-mingle",
        ]
    )
