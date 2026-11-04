"""AlienVault OTX client: read-only URL indicator lookups.

GET /api/v1/indicators/url/{url}/general with header X-OTX-API-KEY (the header name is taken
from the official OTX Python SDK; the external API page does not state it). OTX documents no
rate limit, so a polite 30 requests per minute of our own is used.
"""

from typing import Any
from urllib.parse import quote

import httpx

from phishguard.services.intel.ratelimit import RateLimiter

BASE_URL = "https://otx.alienvault.com/api/v1"


class AlienVaultOTXClient:
    def __init__(
        self,
        api_key: str | None = None,
        *,
        timeout: float = 10.0,
        limiter: RateLimiter | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.api_key = api_key
        self.timeout = timeout
        self.limiter = limiter or RateLimiter(per_minute=30)
        self.transport = transport

    async def get_url_general(self, url: str) -> dict[str, Any]:
        if not self.api_key:
            return {"error": "no_api_key"}
        if not await self.limiter.acquire():
            return {"error": "daily_quota_used"}
        async with httpx.AsyncClient(timeout=self.timeout, transport=self.transport) as client:
            try:
                response = await client.get(
                    f"{BASE_URL}/indicators/url/{quote(url, safe='')}/general",
                    headers={"X-OTX-API-KEY": self.api_key},
                )
            except httpx.HTTPError as error:
                return {"error": f"{type(error).__name__}"}
        if response.status_code == 404:
            return {"status": "not_found"}
        if response.status_code >= 400:
            return {"error": f"http_{response.status_code}"}
        try:
            return response.json()
        except ValueError:
            return {"error": "not_json"}
