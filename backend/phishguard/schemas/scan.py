"""Pydantic schemas for scanning."""

from __future__ import annotations

from pydantic import BaseModel, Field


class URLScanRequest(BaseModel):
    url: str = Field(..., description="URL to scan")


class EmailScanRequest(BaseModel):
    raw_email: str = Field(..., description="Raw email content")


class FeatureExplanation(BaseModel):
    feature: str
    value: float
    importance: float


class VerdictResponse(BaseModel):
    verdict: str  # block | warn | allow
    score: float
    ti_score: float
    explanations: list[FeatureExplanation] = []
    model_version: str | None = None
    latency_ms: float | None = None
