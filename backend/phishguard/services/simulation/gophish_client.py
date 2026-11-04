"""GoPhish API client for simulations."""

from __future__ import annotations

from typing import Any


class GoPhishAPIClient:
    def __init__(self, api_key: str | None = None, base_url: str = "http://localhost:3333"):
        self.api_key = api_key
        self.base_url = base_url

    async def create_campaign(self, campaign: dict[str, Any]) -> dict[str, Any]:
        return {"id": 1, "name": campaign.get("name")}

    async def get_campaigns(self) -> list[dict[str, Any]]:
        return []

    async def get_campaign_results(self, campaign_id: int) -> dict[str, Any]:
        return {"results": []}
