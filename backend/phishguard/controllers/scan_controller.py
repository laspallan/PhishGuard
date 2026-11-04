"""Scan controller."""
from __future__ import annotations

from phishguard.services.inference import InferenceService


class ScanController:
    def __init__(self, inference: InferenceService | None = None):
        self.inference = inference or InferenceService()

    async def scan_url(self, url: str) -> dict:
        return await self.inference.scan_url(url)

    async def scan_email(self, raw_email: str) -> dict:
        return await self.inference.scan_email(raw_email)
