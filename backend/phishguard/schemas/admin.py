"""Pydantic schemas for admin endpoints."""
from __future__ import annotations

from pydantic import BaseModel


class AdminStatus(BaseModel):
    status: str
    features_count: int
    models_loaded: bool
