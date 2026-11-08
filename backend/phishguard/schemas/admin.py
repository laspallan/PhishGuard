"""Pydantic schemas for admin endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class AdminStatus(BaseModel):
    status: str
    features_count: int
    models_loaded: bool
    warn_threshold: float
    block_threshold: float
    threat_intel_configured: bool
    simulations_allowed: bool  # False until the ethics approval reference is set


class Overview(BaseModel):
    total_scans: int
    by_decision: dict[str, int]
    by_modality: dict[str, int]
    median_latency_ms: float | None
    p95_latency_ms: float | None


class RecentScan(BaseModel):
    created_at: datetime
    sample_type: str
    target: str | None  # URL (without query if it may hold a secret) or sender domain
    decision: str
    score: float
    latency_ms: int | None


class CampaignSummary(BaseModel):
    """Totals only: the dashboard never shows what one participant did."""

    name: str
    status: str
    fictional_org: str
    template_split: str
    participants_by_event: dict[str, int]


class ExperimentResult(BaseModel):
    experiment: str
    round: int | None
    seed: int
    arm: str
    eval_set: str
    k: int | None
    metrics: dict[str, Any]
