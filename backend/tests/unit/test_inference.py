"""Basic tests for inference service."""
import asyncio

from phishguard.services.inference import InferenceService


def test_inference_url():
    svc = InferenceService()
    res = asyncio.run(svc.scan_url("http://example.com"))
    assert res["verdict"] in ("block", "warn", "allow")
    assert "ti_score" in res
    assert "latency_ms" in res
