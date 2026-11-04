"""Basic tests for TI service."""
import asyncio
import os

from phishguard.services.intel import IntelService
from phishguard.services.intel.scoring import compute_ti_score


def test_compute_ti_score_empty():
    assert compute_ti_score(None, None) == 0.0


def test_intel_offline():
    os.environ["PHISHGUARD_TI_OFFLINE"] = "true"
    svc = IntelService()
    res = asyncio.run(svc.lookup_url("http://example.com"))
    assert res["ti_score"] == 0.0
