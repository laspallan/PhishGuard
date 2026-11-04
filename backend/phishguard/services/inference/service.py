"""Inference service stub - will load trained models if available."""
from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

from phishguard.services.features.extractor import UrlEvidence, email_features, url_features
from phishguard.services.inference.feature_parity import check_parity
from phishguard.services.inference.model_loader import ModelLoader
from phishguard.services.inference.persist import ScanPersister
from phishguard.services.intel import IntelService


class InferenceService:
    def __init__(self):
        self.intel = IntelService()
        self.loader = ModelLoader()
        self.persister = ScanPersister()
        self.models_loaded = self.loader.load_registry()
        self.model_version = self.loader.metadata.get("version") if self.loader.metadata else None

    async def scan_url(self, url: str, tranco_ranks: dict | None = None) -> dict[str, Any]:
        start = time.perf_counter()
        # Get TI score
        ti_result = await self.intel.lookup_url(url)
        ti_score = ti_result.get("ti_score", 0.0)
        # Extract features
        evidence = UrlEvidence(url=url, captured_at=datetime.now(UTC))
        try:
            features = url_features(evidence, tranco_ranks or {})
        except Exception:
            features = []
        # Simple heuristic until models loaded
        score = min(1.0, (ti_score / 100.0) + 0.1)
        if score >= 0.9:
            verdict = "block"
        elif score >= 0.6:
            verdict = "warn"
        else:
            verdict = "allow"
        latency_ms = (time.perf_counter() - start) * 1000
        result = {
            "verdict": verdict,
            "score": score,
            "ti_score": ti_score,
            "explanations": [],
            "model_version": self.model_version,
            "latency_ms": latency_ms,
        }
        try:
            self.persister.persist_scan({"type": "url", "input": url, **result})
        except Exception:
            pass
        return result

    async def scan_email(self, raw_email: str, tranco_ranks: dict | None = None) -> dict[str, Any]:
        start = time.perf_counter()
        ti_score = 0.0
        try:
            features = email_features(raw_email, tranco_ranks or {})
        except Exception:
            features = []
        score = 0.2
        if score >= 0.9:
            verdict = "block"
        elif score >= 0.6:
            verdict = "warn"
        else:
            verdict = "allow"
        latency_ms = (time.perf_counter() - start) * 1000
        result = {
            "verdict": verdict,
            "score": score,
            "ti_score": ti_score,
            "explanations": [],
            "model_version": self.model_version,
            "latency_ms": latency_ms,
        }
        try:
            self.persister.persist_scan({"type": "email", **result})
        except Exception:
            pass
        return result

