"""Latency of the running API, as a client sees it (Phase 5: median and p95; Phase 7: the time
limit of the extension's checking page).

Sends `POST /scan/url` for development **legitimate** URLs only, one at a time and below the API's
per-key rate limit. Phishing pages are fetched only by the evidence collector, never from here, and
this sends none. Writes data/models/latency_live.json.
"""

import json
import random
import time
from collections.abc import Callable

import httpx
import numpy as np

from phishguard_ml import paths

RATE_LIMIT_PER_MINUTE = 60  # the API's default (PHISHGUARD_SCAN_RATE_LIMIT_PER_MINUTE)


def output_path():
    return paths.models_dir() / "latency_live.json"


def _stats(values: list[float]) -> dict:
    if not values:
        return {"n": 0, "median_ms": None, "p95_ms": None}
    ordered = np.sort(values)
    return {
        "n": len(values),
        "median_ms": float(np.median(ordered)),
        "p95_ms": float(np.percentile(ordered, 95)),
    }


def summarise(rows: list[dict]) -> dict:
    """`rows`: one per request: status, client_ms, and for HTTP 200 the answer's stage."""
    answered = [r for r in rows if r["status"] == 200]
    by_stage = {
        f"stage_{s}": _stats([r["client_ms"] for r in answered if r.get("stage") == s])
        for s in sorted({r.get("stage") for r in answered if r.get("stage") is not None})
    }
    overall = _stats([r["client_ms"] for r in answered])
    return {
        "requests": len(rows),
        "answered": len(answered),
        "not_answered_by_status": {
            str(s): sum(r["status"] == s for r in rows)
            for s in sorted({r["status"] for r in rows} - {200})
        },
        "all_answered": overall,
        **by_stage,
        # The checking page should wait for most first visits: p95, rounded up to 100 ms.
        "suggested_gate_timeout_ms": (
            int(np.ceil(overall["p95_ms"] / 100) * 100) if overall["p95_ms"] else None
        ),
    }


def measure(
    urls: list[str],
    client: httpx.Client,
    *,
    api_base: str,
    api_key: str,
    pause_s: float = 60 / RATE_LIMIT_PER_MINUTE + 0.1,
    sleep: Callable[[float], None] = time.sleep,
) -> dict:
    rows = []
    for url in urls:
        started = time.perf_counter()
        try:
            response = client.post(
                f"{api_base.rstrip('/')}/scan/url",
                json={"url": url},
                headers={"X-API-Key": api_key},
            )
            status = response.status_code
            body = response.json() if status == 200 else {}
        except (httpx.HTTPError, ValueError):
            status, body = 0, {}  # 0 = no answer at all
        rows.append(
            {
                "status": status,
                "client_ms": (time.perf_counter() - started) * 1000,
                "stage": body.get("stage"),
                "server_ms": body.get("latency_ms"),
            }
        )
        sleep(pause_s)
    return summarise(rows)


def run(n: int, api_base: str, api_key: str, seed: int = 42) -> dict:
    from phishguard.models.enums import Label, Modality
    from phishguard_ml.training.devdata import development_records

    legitimate = [
        r.raw_content for r in development_records(Modality.URL) if r.label is Label.LEGITIMATE
    ]
    chosen = random.Random(seed).sample(legitimate, min(n, len(legitimate)))
    with httpx.Client(timeout=30) as client:
        result = measure(chosen, client, api_base=api_base, api_key=api_key)
    result["url_kind"] = "development legitimate URLs (Tranco)"
    output_path().parent.mkdir(parents=True, exist_ok=True)
    output_path().write_text(json.dumps(result, indent=1))
    return result
