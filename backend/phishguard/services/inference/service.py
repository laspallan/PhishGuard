"""Inference service (Phase 5, decision D11; flow in Docs/live_url_scanning.md).

URL scan:
  stage 1  M1 (`live_stage1`) on the URL and DNS, without contacting the target. Confident: done.
  stage 2  only if M1 is unsure and the URL is safe to fetch: M2 (`live`) adds page and TLS.
Rules for what is not known (D11d, D11e): a URL that may carry a secret is never fetched and is
at most `warn`; a partial answer is `block` if M1 alone is sure, otherwise `warn`, never `allow`.

No verdict is ever invented: without a usable trained model the scan raises ModelNotLoadedError
and the API answers 503, so the extension and the gateway never act on a placeholder score.
`ti_score` stays None until its formula is decided (Phase 4). Models run in a worker thread.
"""

import asyncio
import logging
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any

from phishguard.core.config import Settings, get_settings
from phishguard.models.enums import Modality
from phishguard.services.evidence import (
    STAGE_FETCH,
    STAGE_NO_TARGET_CONTACT,
    evidence_from_answer,
    is_safe_to_fetch,
)
from phishguard.services.features import email_parts, extractor
from phishguard.services.features.extractor import FEATURE_NAMES
from phishguard.services.inference.evidence_client import request_evidence
from phishguard.services.inference.model_loader import ModelLoader, ServingModel
from phishguard.services.inference.persist import input_hash, record_scan, storable_url
from phishguard.services.inference.scan_store import ScanStore

log = logging.getLogger(__name__)

WARN, BLOCK = 0.60, 0.90  # same as ml/.../training/ensembles.py (a test compares them)
URL_FEATURE_SET_STAGE1 = "live_stage1"  # M1
URL_FEATURE_SET = "live"  # M2
EMAIL_FEATURE_SET = "no_header"  # the headline email models (Enron lacks delivery headers)

TOTAL_WAIT_SECONDS = 6.5
STAGE1_WAIT_SECONDS = 3.0
MIN_STAGE2_SECONDS = 1.0
VERDICT_TTL_SECONDS = 3600
PARTIAL_VERDICT_TTL_SECONDS = 300  # sooner again: the collector may be back
_AUTO = object()


class ModelNotLoadedError(RuntimeError):
    """No usable trained model is registered yet."""


class RateLimitedError(RuntimeError):
    """This API client has sent too many URL scans this minute."""


def decision_for(probability: float) -> str:
    if probability >= BLOCK:
        return "block"
    return "warn" if probability >= WARN else "allow"


def _by_name(values: list[float]) -> dict[str, float]:
    return dict(zip(FEATURE_NAMES, values, strict=True))


def url_values(url: str, answer: Mapping[str, Any], collected_at: datetime) -> list[float]:
    """F1-F140 of a URL from the collector's answer, through the same code as training. Live
    scans pass no Tranco ranks and no RDAP: the live feature sets do not use them (D11c)."""
    return extractor.url_features(evidence_from_answer(url, collected_at, dict(answer)), {})


def _default_recorder(settings: Settings) -> Callable[..., None] | None:
    if not settings.database_url:
        return None
    from phishguard.db.session import get_sessionmaker

    return lambda **fields: record_scan(get_sessionmaker(), **fields)


class InferenceService:
    def __init__(
        self,
        loader: ModelLoader | None = None,
        *,
        settings: Settings | None = None,
        evidence: Callable[..., dict | None] = request_evidence,
        store: ScanStore | None = None,
        recorder: Any = _AUTO,
    ):
        self.settings = settings or get_settings()
        self.loader = loader or ModelLoader()
        self.loader.load_registry()
        self.evidence = evidence
        self.store = store if store is not None else ScanStore.from_url(self.settings.redis_url)
        self.recorder = _default_recorder(self.settings) if recorder is _AUTO else recorder

    @property
    def models_loaded(self) -> bool:
        return self.loader.loaded

    def _model(self, modality: str, feature_set: str) -> ServingModel:
        model = self.loader.serving_model(modality, feature_set)
        if model is None:
            raise ModelNotLoadedError(f"no trained {modality}/{feature_set} model is available")
        return model

    def _record(self, model: ServingModel, result: dict[str, Any], **fields: Any) -> None:
        if self.recorder is None:
            return
        try:
            self.recorder(
                entry=model.entry,
                score=result["score"],
                decision=result["verdict"],
                latency_ms=result["latency_ms"],
                warn=WARN,
                block=BLOCK,
                top_features=result.get("explanations"),
                **fields,
            )
        except Exception as error:  # the user still gets the verdict; the failure is logged
            log.error("scan not saved: %s", type(error).__name__)

    async def scan_url(self, url: str, client_id: str = "") -> dict[str, Any]:
        return await asyncio.to_thread(self._scan_url, url, client_id)

    async def scan_email(self, raw_email: str) -> dict[str, Any]:
        return await asyncio.to_thread(self._scan_email, raw_email)

    # --- URL --------------------------------------------------------------------------------
    def _scan_url(self, url: str, client_id: str) -> dict[str, Any]:
        started = time.perf_counter()
        stage1_model = self._model(Modality.URL.value, URL_FEATURE_SET_STAGE1)
        stage2_model = self._model(Modality.URL.value, URL_FEATURE_SET)
        if not self.store.allow(client_id, self.settings.scan_rate_limit_per_minute):
            raise RateLimitedError("too many URL scans this minute")
        key = f"phishguard:verdict:{input_hash(url)}"
        cached = self.store.get(key)
        if cached is not None:
            latency = (time.perf_counter() - started) * 1000
            return {**cached, "cached": True, "latency_ms": latency}

        result, model, values = self._decide_url(url, stage1_model, stage2_model, started)
        ttl = (
            VERDICT_TTL_SECONDS if result["evidence"] == "complete" else PARTIAL_VERDICT_TTL_SECONDS
        )
        self.store.set(key, result, ttl)
        log.info(
            "url scan: stage=%s evidence=%s verdict=%s latency_ms=%.0f",
            result["stage"], result["evidence"], result["verdict"], result["latency_ms"],
        )  # fmt: skip
        self._record(
            model,
            result,
            modality=Modality.URL,
            input_text=url,
            url=storable_url(url),
            sender_domain=None,
            values=values,
        )
        return result

    def _decide_url(
        self, url: str, stage1_model: ServingModel, stage2_model: ServingModel, started: float
    ) -> tuple[dict[str, Any], ServingModel, list[float]]:
        def finish(model, probability, verdict, stage, evidence, values):
            result = {
                "verdict": verdict,
                "score": probability,
                "explanations": model.explanations(_by_name(values)),
                "ti_score": None,
                "model_version": model.version,
                "stage": stage,
                "evidence": evidence,
                "latency_ms": (time.perf_counter() - started) * 1000,
            }
            return result, model, values

        now = datetime.now(UTC)
        answer = self.evidence(url, STAGE_NO_TARGET_CONTACT, wait_seconds=STAGE1_WAIT_SECONDS)
        partial = answer is None or bool(answer.get("late"))
        values = url_values(url, answer or {}, now)
        probability = stage1_model.probability(_by_name(values))
        safe = is_safe_to_fetch(url)
        private_target = bool(((answer or {}).get("meta") or {}).get("unsafe_host"))
        unsure = self.settings.stage1_band_low < probability < self.settings.stage1_band_high

        if not unsure and not partial:
            verdict = decision_for(probability)
            if not safe and verdict == "block":
                verdict = "warn"  # D11d: decided without its page, so at most warn
            return finish(stage1_model, probability, verdict, 1, "complete", values)

        if unsure and safe and not private_target:
            left = TOTAL_WAIT_SECONDS - (time.perf_counter() - started)
            if left >= MIN_STAGE2_SECONDS:
                full = self.evidence(url, STAGE_FETCH, wait_seconds=left)
                if full is not None and not full.get("late") and not full.get("refused"):
                    full_values = url_values(url, full, now)
                    p = stage2_model.probability(_by_name(full_values))
                    return finish(stage2_model, p, decision_for(p), 2, "complete", full_values)

        # D11e: what is not known never becomes allow; D11d: nor block without its page.
        verdict = "block" if safe and decision_for(probability) == "block" else "warn"
        return finish(stage1_model, probability, verdict, 1, "partial", values)

    # --- email ------------------------------------------------------------------------------
    def _scan_email(self, raw_email: str) -> dict[str, Any]:
        started = time.perf_counter()
        model = self._model(Modality.EMAIL.value, EMAIL_FEATURE_SET)
        values = extractor.email_features(raw_email, {})  # no_header does not use Tranco
        probability = model.probability(_by_name(values))
        result = {
            "verdict": decision_for(probability),
            "score": probability,
            "explanations": model.explanations(_by_name(values)),
            "ti_score": None,
            "model_version": model.version,
            "evidence": "complete",
            "latency_ms": (time.perf_counter() - started) * 1000,
        }
        log.info("email scan: verdict=%s latency_ms=%.0f", result["verdict"], result["latency_ms"])
        sender = email_parts.parse(raw_email).first("from")
        domain = email_parts.domain_of_address(email_parts.address(sender)[1])
        self._record(
            model,
            result,
            modality=Modality.EMAIL,
            input_text=raw_email,
            url=None,
            sender_domain=domain[:253] or None,
            values=values,
        )
        return result
