"""Threat intelligence service with caching and offline support."""
from __future__ import annotations

import asyncio
from typing import Any

from phishguard.core.config import get_settings
from phishguard.services.intel.alienvault import AlienVaultOTXClient
from phishguard.services.intel.cache import TICache
from phishguard.services.intel.scoring import compute_ti_score
from phishguard.services.intel.virustotal import VirusTotalClient


class IntelService:
    def __init__(self, cache: TICache | None = None):
        self.settings = get_settings()
        self.cache = cache or TICache()
        vt_key = (
            self.settings.virustotal_api_key.get_secret_value()
            if self.settings.virustotal_api_key
            else None
        )
        otx_key = (
            self.settings.alienvault_otx_api_key.get_secret_value()
            if self.settings.alienvault_otx_api_key
            else None
        )
        self.vt = VirusTotalClient(api_key=vt_key)
        self.otx = AlienVaultOTXClient(api_key=otx_key)
        self.offline = self.settings.ti_offline

    async def lookup_url(self, url: str) -> dict[str, Any]:
        cache_key = f"ti:url:{url}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached
        if self.offline or (not self.vt.api_key and not self.otx.api_key):
            result = {"ti_score": 0.0, "vt": None, "otx": None, "cached": False}
            self.cache.set(cache_key, result)
            return result
        vt_task = self.vt.get_url_report(url)
        otx_task = self.otx.get_url_general(url)
        vt_resp, otx_resp = await asyncio.gather(vt_task, otx_task, return_exceptions=True)
        if isinstance(vt_resp, Exception):
            vt_resp = {"error": str(vt_resp)}
        if isinstance(otx_resp, Exception):
            otx_resp = {"error": str(otx_resp)}
        ti_score = compute_ti_score(vt_resp, otx_resp)
        result = {"ti_score": ti_score, "vt": vt_resp, "otx": otx_resp, "cached": False}
        self.cache.set(cache_key, result)
        return result
