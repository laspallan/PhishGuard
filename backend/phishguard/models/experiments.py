"""The feedback loop and experiment results (RQ1-RQ3)."""

import uuid
from datetime import date
from typing import Any

from sqlalchemy import Date, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from phishguard.models.base import Base, CreatedAtMixin, JSONDoc, UUIDPrimaryKeyMixin, str_enum
from phishguard.models.enums import EvalSet, Experiment, SampleUsage


class SimulationSample(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """A failed-simulation sample turned into phishing training data.

    usage is only train or sim_holdout: simulation data can never reach the locked test set,
    which is a frozen file outside the database.
    """

    __tablename__ = "simulation_samples"

    simulation_event_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("simulation_events.id", ondelete="CASCADE"), unique=True
    )
    template_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("templates.id", ondelete="RESTRICT"))
    content_ref: Mapped[str] = mapped_column(String(500))
    usage: Mapped[SampleUsage] = mapped_column(str_enum(SampleUsage))
    collected_month: Mapped[date] = mapped_column(Date)


class ExperimentRun(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """One result: a model (or the baseline) on one evaluation set with one seed.

    arm is free text so each experiment can name its arms (A/B/C, baseline, with_ti, ...).
    """

    __tablename__ = "experiment_runs"

    experiment: Mapped[Experiment] = mapped_column(str_enum(Experiment))
    round: Mapped[int | None]
    seed: Mapped[int]
    arm: Mapped[str] = mapped_column(String(50))
    model_version_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("model_versions.id", ondelete="SET NULL")
    )
    eval_set: Mapped[EvalSet] = mapped_column(str_enum(EvalSet))
    k: Mapped[int | None]
    metrics: Mapped[dict[str, Any]] = mapped_column(JSONDoc)
