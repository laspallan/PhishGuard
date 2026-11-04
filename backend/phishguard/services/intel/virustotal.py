"""VirusTotal API v3 client: read-only URL lookups.

GET /api/v3/urls/{id}, where id is the URL in unpadded URL-safe base64
(https://docs.virustotal.com/reference/url). URLs are **never submitted** for scanning: a
submitted URL becomes visible to other VirusTotal users, and scanned URLs can contain private
tokens (password-reset links, session ids). A URL VirusTotal does not know is "not_found".
"""

import base64
from typing import Any

import httpx

from phishguard.services.intel.ratelimit import RateLimiter

BASE_URL = "https://www.virustotal.com/api/v3"


def url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


class VirusTotalClient:
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
        self.limiter = limiter or RateLimiter(per_minute=4, per_day=500)
        self.transport = transport

    async def get_url_report(self, url: str) -> dict[str, Any]:
        if not self.api_key:
            return {"error": "no_api_key"}
        if not await self.limiter.acquire():
            return {"error": "daily_quota_used"}
        async with httpx.AsyncClient(timeout=self.timeout, transport=self.transport) as client:
            try:
                response = await client.get(
                    f"{BASE_URL}/urls/{url_id(url)}", headers={"x-apikey": self.api_key}
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
