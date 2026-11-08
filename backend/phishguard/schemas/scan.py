"""Pydantic schemas for scanning."""

from __future__ import annotations

from urllib.parse import urlsplit

from pydantic import BaseModel, Field, field_validator


class URLScanRequest(BaseModel):
    url: str = Field(..., description="URL to scan (http or https)", max_length=8192)

    @field_validator("url")
    @classmethod
    def _http_only(cls, value: str) -> str:
        try:
            parts = urlsplit(value)
            host = parts.hostname
        except ValueError as error:
            raise ValueError("not a valid URL") from error
        if parts.scheme not in ("http", "https") or not host:
            raise ValueError("only http and https URLs can be scanned")
        return value


class EmailScanRequest(BaseModel):
    raw_email: str = Field(..., description="Raw email content")


class FeatureExplanation(BaseModel):
    feature: str
    value: float | None  # None = the feature was missing for this input
    importance: float  # SHAP value in log-odds: above 0 pushes towards phishing


class VerdictResponse(BaseModel):
    verdict: str  # block | warn | allow
    score: float
    ti_score: float | None = None  # None until the formula is decided (Phase 4)
    explanations: list[FeatureExplanation] = []
    model_version: str | None = None
    latency_ms: float | None = None
    stage: int | None = None  # URL scans: 1 = no contact with the target, 2 = page fetched
    evidence: str | None = None  # complete | partial (some evidence late, failed or withheld)
    cached: bool = False
