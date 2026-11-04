"""VirusTotal v3 client (URL lookups)."""
from __future__ import annotations

import asyncio
from typing import Any

import httpx

from phishguard.services.intel.ratelimit import RateLimiter


class VirusTotalClient:
    def __init__(self, api_key: str | None = None, timeout: float = 10.0):
        self.api_key = api_key
        self.timeout = timeout
        self.base_url = "https://www.virustotal.com/api/v3"
        # Free tier is quite limited; keep conservative defaults
        self.limiter = RateLimiter(rate_per_second=0.25, burst=1)

    async def get_url_report(self, url: str) -> dict[str, Any]:
        if not self.api_key:
            return {"error": "no_api_key"}
        self.limiter.wait()
        headers = {"x-apikey": self.api_key}
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                # Submit URL for analysis if needed is optional; try report by URL id
                import base64

                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                resp = await client.get(f"{self.base_url}/urls/{url_id}", headers=headers)
                if resp.status_code == 404:
                    # Try to submit
                    submit = await client.post(
                        f"{self.base_url}/urls", headers=headers, data={"url": url}
                    )
                    if submit.status_code not in (200, 202):
                        return {"error": f"submit_{submit.status_code}"}
                    # Return partial
                    return {"submitted": True}
                if resp.status_code >= 400:
                    return {"error": f"http_{resp.status_code}"}
                return resp.json()
            except Exception as e:
                return {"error": str(e)}
