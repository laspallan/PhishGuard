"""Threat-intelligence lookup for one URL: VirusTotal + AlienVault OTX -> ti_score (Phase 4).

- No keys or offline mode: ti_score is None ("unknown"), never 0 (0 would read as "clean").
- A lookup where a provider failed (quota, HTTP error, timeout) is returned with
  `complete: False` and is not cached, so it is retried later.
- Every raw response can be recorded with a timestamp (TIRecorder, decision D7).
"""

import asyncio
from typing import Any

from phishguard.core.config import get_settings
from phishguard.services.intel.alienvault import AlienVaultOTXClient
from phishguard.services.intel.cache import TICache
from phishguard.services.intel.recorder import TIRecorder
from phishguard.services.intel.scoring import compute_ti_score
from phishguard.services.intel.virustotal import VirusTotalClient


class IntelService:
    def __init__(
        self,
        cache: TICache | None = None,
        vt: VirusTotalClient | None = None,
        otx: AlienVaultOTXClient | None = None,
        recorder: TIRecorder | None = None,
    ):
        settings = get_settings()
        self.offline = settings.ti_offline
        self.cache = cache or TICache.from_url(settings.redis_url)
        self.vt = vt or VirusTotalClient(
            settings.virustotal_api_key.get_secret_value() if settings.virustotal_api_key else None
        )
        self.otx = otx or AlienVaultOTXClient(
            settings.alienvault_otx_api_key.get_secret_value()
            if settings.alienvault_otx_api_key
            else None
        )
        self.recorder = recorder

    async def lookup_url(self, url: str) -> dict[str, Any]:
        if self.offline or (not self.vt.api_key and not self.otx.api_key):
            return {"ti_score": None, "vt": None, "otx": None, "complete": False, "cached": False}
        key = f"ti:url:{url}"
        cached = self.cache.get(key)
        if cached is not None:
            return {**cached, "cached": True}
        vt_response, otx_response = await asyncio.gather(
            self.vt.get_url_report(url), self.otx.get_url_general(url)
        )
        complete = "error" not in vt_response and "error" not in otx_response
        result = {
            "ti_score": compute_ti_score(vt_response, otx_response),
            "vt": vt_response,
            "otx": otx_response,
            "complete": complete,
            "cached": False,
        }
        if self.recorder is not None:
            self.recorder.record(url, {"vt": vt_response, "otx": otx_response})
        if complete:
            self.cache.set(key, {k: v for k, v in result.items() if k != "cached"})
        return result
