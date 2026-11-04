"""Simulation event store (Phase 6). No credential values stored."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass
class SimulationEvent:
    campaign_id: str
    recipient_id: str
    delivered: bool = False
    opened: bool = False
    clicked: bool = False
    submitted: bool = False  # boolean only, never values
    timestamp: datetime | None = None
