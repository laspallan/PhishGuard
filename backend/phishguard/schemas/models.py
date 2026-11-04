"""Pydantic schemas for models info."""

from __future__ import annotations

from pydantic import BaseModel


class ModelInfo(BaseModel):
    name: str
    modality: str
    version: str | None = None
    metrics: dict | None = None


class ModelsResponse(BaseModel):
    models: list[ModelInfo]
