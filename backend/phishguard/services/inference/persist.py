"""Saves each scan and its model version. For emails only a hash and the sender domain are kept,
never the body or subject; URLs that may carry a secret are stored without their query."""

import hashlib
from collections.abc import Callable
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from phishguard.models import ModelVersion, Scan, ScanFeatures
from phishguard.models.enums import Decision, Modality, ModelKind
from phishguard.services.evidence import is_safe_to_fetch

EXTRACTOR_VERSION_LENGTH = 32


def input_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def storable_url(url: str) -> str | None:
    if is_safe_to_fetch(url):
        return url
    try:
        parts = urlsplit(url)
        return urlunsplit((parts.scheme, parts.hostname or "", parts.path, "", ""))
    except ValueError:
        return None


def _model_version(
    session: Session, entry: dict[str, Any], warn: float, block: float
) -> ModelVersion:
    found = session.scalar(select(ModelVersion).where(ModelVersion.name == entry["version"]))
    if found is not None:
        return found
    row = ModelVersion(
        name=entry["version"],
        modality=Modality(entry["modality"]),
        kind=ModelKind(entry["model"]),
        artifact_path=entry["path"],
        data_hash=entry["split_sha256"]["dataset.parquet"],
        feature_set_hash=entry["feature_code_hash"],
        seed=entry["seed"],
        warn_threshold=warn,
        block_threshold=block,
        cv_metrics={"oof_log_loss": entry["oof_log_loss"]},
        trained_at=datetime.fromisoformat(entry["registered_at"]),
    )
    session.add(row)
    session.flush()
    return row


def record_scan(
    session_factory: Callable[[], Session],
    *,
    entry: dict[str, Any],
    modality: Modality,
    input_text: str,
    url: str | None,
    sender_domain: str | None,
    score: float,
    decision: str,
    latency_ms: float,
    values: list[float],
    warn: float,
    block: float,
    top_features: list[dict[str, Any]] | None = None,
) -> None:
    with session_factory() as session:
        version = _model_version(session, entry, warn, block)
        scan = Scan(
            model_version_id=version.id,
            sample_type=modality,
            input_hash=input_hash(input_text),
            url=url,
            sender_domain=sender_domain,
            score=score,
            decision=Decision(decision),
            top_features=top_features,
            latency_ms=int(latency_ms),
        )
        session.add(scan)
        session.flush()
        session.add(
            ScanFeatures(
                scan_id=scan.id,
                extractor_version=entry["feature_code_hash"][:EXTRACTOR_VERSION_LENGTH],
                values=values,
            )
        )
        session.commit()
