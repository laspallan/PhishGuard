"""Simulation service."""
from __future__ import annotations

from phishguard.services.simulation.events import SimulationEvent
from phishguard.services.simulation.gophish import GoPhishClient
from phishguard.services.simulation.templates import TemplateType


class SimulationService:
    def __init__(self):
        self.client = GoPhishClient()

    async def create_campaign(self, name: str, template_type: TemplateType):
        campaign = {"name": name, "template_type": template_type.value}
        return await self.client.create_campaign(campaign)
