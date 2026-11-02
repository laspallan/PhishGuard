"""The live detection system: model versions, scans with their verdicts, and TI lookups."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, Float, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, validates

from phishguard.models.base import (
    Base,
    CreatedAtMixin,
    FloatArray,
    JSONDoc,
    UUIDPrimaryKeyMixin,
    str_enum,
    utcnow,
)
from phishguard.models.enums import (
    Decision,
    FeedbackSource,
    IndicatorType,
    Label,
    Modality,
    ModelKind,
    ModelStatus,
    TiProvider,
)

FEATURE_COUNT = 140


class ModelVersion(UUIDPrimaryKeyMixin, Base):
    """Every trained model (single models and ensembles) and whether it is in use."""

    __tablename__ = "model_versions"
    __table_args__ = (
        CheckConstraint(
            "block_threshold IS NULL OR (block_threshold > 0 AND block_threshold <= 1)",
            name="block_threshold_range",
        ),
        CheckConstraint(
            "warn_threshold IS NULL OR (warn_threshold > 0 AND warn_threshold <= 1)",
            name="warn_threshold_range",
        ),
        CheckConstraint(
            "block_threshold IS NULL OR warn_threshold IS NULL OR warn_threshold < block_threshold",
            name="warn_below_block",
        ),
    )

    name: Mapped[str] = mapped_column(String(100))
    modality: Mapped[Modality] = mapped_column(str_enum(Modality))
    kind: Mapped[ModelKind] = mapped_column(str_enum(ModelKind))
    artifact_path: Mapped[str] = mapped_column(String(500))
    data_hash: Mapped[str] = mapped_column(String(64))
    feature_set_hash: Mapped[str] = mapped_column(String(64))
    seed: Mapped[int]
    block_threshold: Mapped[float | None]
    warn_threshold: Mapped[float | None]
    cv_metrics: Mapped[dict[str, Any] | None] = mapped_column(JSONDoc)
    locked_test_metrics: Mapped[dict[str, Any] | None] = mapped_column(JSONDoc)
    sim_holdout_metrics: Mapped[dict[str, Any] | None] = mapped_column(JSONDoc)
    status: Mapped[ModelStatus] = mapped_column(
        str_enum(ModelStatus), default=ModelStatus.CANDIDATE
    )
    promotion_reason: Mapped[str | None] = mapped_column(Text)
    trained_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    promoted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Scan(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """One URL or email check and its verdict.

    For emails only a hash and the sender domain are kept, never the body or subject.
    """

    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint("score >= 0 AND score <= 1", name="score_range"),
        CheckConstraint("ti_score IS NULL OR (ti_score >= 0 AND ti_score <= 100)", name="ti_range"),
        CheckConstraint("latency_ms IS NULL OR latency_ms >= 0", name="latency_non_negative"),
        Index("ix_scans_created_at", "created_at"),
    )

    api_client_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("api_clients.id", ondelete="SET NULL")
    )
    model_version_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("model_versions.id", ondelete="RESTRICT")
    )
    sample_type: Mapped[Modality] = mapped_column(str_enum(Modality))
    input_hash: Mapped[str] = mapped_column(String(64), index=True)
    url: Mapped[str | None] = mapped_column(Text)
    sender_domain: Mapped[str | None] = mapped_column(String(253))
    score: Mapped[float] = mapped_column(Float)
    ti_score: Mapped[float | None] = mapped_column(Float)
    decision: Mapped[Decision] = mapped_column(str_enum(Decision))
    used_distilbert: Mapped[bool] = mapped_column(default=False)
    top_features: Mapped[list[dict[str, Any]] | None] = mapped_column(JSONDoc)
    latency_ms: Mapped[int | None]


class ScanFeatures(Base):
    """The F1-F140 vector behind a scan (one row per scan)."""

    __tablename__ = "scan_features"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True
    )
    extractor_version: Mapped[str] = mapped_column(String(32))
    values: Mapped[list[float]] = mapped_column(FloatArray)

    @validates("values")
    def _check_length(self, _key: str, value: list[float]) -> list[float]:
        if len(value) != FEATURE_COUNT:
            raise ValueError(f"expected {FEATURE_COUNT} feature values, got {len(value)}")
        return value


class ScanFeedback(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """A report that a verdict was wrong (e.g. "this site is safe")."""

    __tablename__ = "scan_feedback"

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    reported_label: Mapped[Label] = mapped_column(str_enum(Label))
    source: Mapped[FeedbackSource] = mapped_column(str_enum(FeedbackSource))
    comment: Mapped[str | None] = mapped_column(Text)


class TiLookup(UUIDPrimaryKeyMixin, Base):
    """Permanent record of each threat-intelligence call (Redis is only the cache).

    raw_response keeps the provider's reply as received, so no response fields are assumed.
    """

    __tablename__ = "ti_lookups"
    __table_args__ = (Index("ix_ti_lookups_indicator", "indicator_hash", "provider", "fetched_at"),)

    indicator: Mapped[str] = mapped_column(Text)
    indicator_hash: Mapped[str] = mapped_column(String(64))
    indicator_type: Mapped[IndicatorType] = mapped_column(str_enum(IndicatorType))
    provider: Mapped[TiProvider] = mapped_column(str_enum(TiProvider))
    provider_score: Mapped[float | None]
    raw_response: Mapped[dict[str, Any]] = mapped_column(JSONDoc)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
