"""Threat-intelligence clients, rate limits, cache and service — all offline (mocked HTTP)."""

import asyncio
import json

import fakeredis
import httpx
import pytest

from phishguard.core.config import Settings
from phishguard.services.intel import service as intel_service
from phishguard.services.intel.alienvault import AlienVaultOTXClient
from phishguard.services.intel.cache import TICache
from phishguard.services.intel.ratelimit import RateLimiter
from phishguard.services.intel.recorder import TIRecorder
from phishguard.services.intel.scoring import compute_ti_score
from phishguard.services.intel.virustotal import VirusTotalClient, url_id

VT_REPORT = {"data": {"attributes": {"last_analysis_stats": {"malicious": 3, "suspicious": 1}}}}
VT, OTX = "https://www.virustotal.com", "https://otx.alienvault.com"


def run(coroutine):
    return asyncio.run(coroutine)


def transport(routes: dict[str, httpx.Response], seen: list[httpx.Request]):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        for prefix, response in routes.items():
            if str(request.url).startswith(prefix):
                return response
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def test_virustotal_lookup_is_read_only_and_never_submits():
    seen: list[httpx.Request] = []
    vt = VirusTotalClient("k", transport=transport({}, seen))  # every URL unknown -> 404
    private = "https://private.example/reset?token=abc"
    assert run(vt.get_url_report(private)) == {"status": "not_found"}
    assert [r.method for r in seen] == ["GET"]  # no POST /urls submission
    assert seen[0].headers["x-apikey"] == "k"
    assert seen[0].url.path == f"/api/v3/urls/{url_id(private)}"


def test_url_id_is_unpadded_urlsafe_base64():
    assert url_id("http://a.b/") == "aHR0cDovL2EuYi8"  # base64 "aHR0cDovL2EuYi8=" without "="


def test_errors_are_reported_not_raised():
    seen: list[httpx.Request] = []
    vt = VirusTotalClient("k", transport=transport({VT: httpx.Response(429)}, seen))
    assert run(vt.get_url_report("http://x.example/")) == {"error": "http_429"}
    assert run(VirusTotalClient(None).get_url_report("http://x.example/")) == {
        "error": "no_api_key"
    }


def test_rate_limiter_waits_per_minute_and_stops_at_the_daily_quota():
    now = [0.0]
    waits: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        waits.append(seconds)
        now[0] += seconds

    limiter = RateLimiter(per_minute=4, per_day=5, clock=lambda: now[0], sleep=fake_sleep)

    async def five_then_one():
        results = [await limiter.acquire() for _ in range(5)]
        return results, await limiter.acquire()

    results, sixth = run(five_then_one())
    assert results == [True] * 5
    assert waits == [60.0]  # the 5th request waited for the first minute to pass
    assert sixth is False  # 5 per day used up: refused at once, no waiting


def test_rate_limit_does_not_block_other_tasks():
    limiter = RateLimiter(per_minute=1)

    async def scenario():
        await limiter.acquire()
        waiting = asyncio.create_task(limiter.acquire())  # has to wait about 60 s
        await asyncio.sleep(0.01)  # this only runs if the wait does not block the loop
        waiting.cancel()
        return "the event loop still runs"

    assert run(scenario()) == "the event loop still runs"


@pytest.fixture
def online_settings(monkeypatch):
    settings = Settings(_env_file=None, environment="test", ti_offline=False)
    monkeypatch.setattr(intel_service, "get_settings", lambda: settings)
    return settings


def _service(routes, seen, recorder=None):
    vt = VirusTotalClient("vt", transport=transport(routes, seen))
    otx = AlienVaultOTXClient("otx", transport=transport(routes, seen))
    return intel_service.IntelService(cache=TICache(), vt=vt, otx=otx, recorder=recorder)


def test_service_scores_caches_and_records(online_settings, tmp_path):
    seen: list[httpx.Request] = []
    otx_body = {"pulse_info": {"count": 2}}
    routes = {VT: httpx.Response(200, json=VT_REPORT), OTX: httpx.Response(200, json=otx_body)}
    svc = _service(routes, seen, recorder=TIRecorder(tmp_path))

    first = run(svc.lookup_url("http://evil.example/"))
    assert first["complete"] is True
    assert first["ti_score"] == compute_ti_score(VT_REPORT, otx_body)
    again = run(svc.lookup_url("http://evil.example/"))
    assert again["cached"] is True and len(seen) == 2  # the second lookup came from the cache
    line = json.loads(next(tmp_path.glob("ti_*.jsonl")).read_text().splitlines()[0])
    assert line["url"] == "http://evil.example/" and "queried_at" in line


def test_failed_lookups_are_not_cached(online_settings):
    seen: list[httpx.Request] = []
    routes = {VT: httpx.Response(429), OTX: httpx.Response(200, json={})}
    svc = _service(routes, seen)
    assert run(svc.lookup_url("http://x.example/"))["complete"] is False
    run(svc.lookup_url("http://x.example/"))
    assert len(seen) == 4  # asked again: the 429 was not remembered as "clean"


def test_no_keys_or_offline_means_unknown_not_zero(monkeypatch):
    settings = Settings(_env_file=None, environment="test", ti_offline=True)
    monkeypatch.setattr(intel_service, "get_settings", lambda: settings)
    result = run(intel_service.IntelService().lookup_url("http://x.example/"))
    assert result["ti_score"] is None and result["complete"] is False


def test_cache_with_redis_and_bounded_memory():
    redis_cache = TICache(fakeredis.FakeRedis(), ttl_seconds=60)
    redis_cache.set("a", {"ti_score": 1.0})
    assert redis_cache.get("a") == {"ti_score": 1.0}

    memory = TICache(max_entries=2)
    for key in ("a", "b", "c"):
        memory.set(key, {"k": key})
    assert memory.get("a") is None and memory.get("c") == {"k": "c"}  # oldest evicted


def test_compute_ti_score_empty():
    assert compute_ti_score(None, None) == 0.0
