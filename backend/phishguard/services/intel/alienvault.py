"""AlienVault OTX client (URL/domain lookups)."""
from __future__ import annotations

from typing import Any

import httpx

from phishguard.services.intel.ratelimit import RateLimiter


class AlienVaultOTXClient:
    def __init__(self, api_key: str | None = None, timeout: float = 10.0):
        self.api_key = api_key
        self.timeout = timeout
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.limiter = RateLimiter(rate_per_second=1.0, burst=2)

    async def get_url_general(self, url: str) -> dict[str, Any]:
        if not self.api_key:
            return {"error": "no_api_key"}
        self.limiter.wait()
        headers = {"X-OTX-API-KEY": self.api_key}
        from urllib.parse import quote

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                resp = await client.get(
                    f"{self.base_url}/indicators/url/{quote(url, safe='')}/general",
                    headers=headers,
                )
                if resp.status_code >= 400:
                    return {"error": f"http_{resp.status_code}"}
                return resp.json()
            except Exception as e:
                return {"error": str(e)}
