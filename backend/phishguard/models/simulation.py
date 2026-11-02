"""Phishing simulations with consenting participants."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from phishguard.models.base import (
    Base,
    CreatedAtMixin,
    EncryptedEmailMixin,
    UUIDPrimaryKeyMixin,
    str_enum,
)
from phishguard.models.enums import AttackCategory, CampaignStatus, EventType, TemplateSplit


class Participant(UUIDPrimaryKeyMixin, EncryptedEmailMixin, CreatedAtMixin, Base):
    """A consenting volunteer. Deleting a participant deletes their events and samples."""

    __tablename__ = "participants"

    participant_code: Mapped[str] = mapped_column(String(32), unique=True)
    consent_form_version: Mapped[str] = mapped_column(String(32))
    consent_given_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consent_withdrawn_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Template(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """A simulation email + landing page, always for a fictional organisation.

    split=holdout templates are never used for training (simulation-holdout set, RQ3).
    """

    __tablename__ = "templates"

    name: Mapped[str] = mapped_column(String(100), unique=True)
    gophish_template_id: Mapped[int | None] = mapped_column(unique=True)
    attack_category: Mapped[AttackCategory] = mapped_column(str_enum(AttackCategory))
    fictional_org: Mapped[str] = mapped_column(String(100))
    split: Mapped[TemplateSplit] = mapped_column(str_enum(TemplateSplit))


class Campaign(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    __tablename__ = "campaigns"

    name: Mapped[str] = mapped_column(String(100))
    gophish_campaign_id: Mapped[int | None] = mapped_column(unique=True)
    template_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("templates.id", ondelete="RESTRICT"))
    status: Mapped[CampaignStatus] = mapped_column(
        str_enum(CampaignStatus), default=CampaignStatus.DRAFT
    )
    launched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SimulationEvent(UUIDPrimaryKeyMixin, Base):
    """What a participant did. There is deliberately no column for submitted form data."""

    __tablename__ = "simulation_events"
    __table_args__ = (
        UniqueConstraint(
            "campaign_id",
            "participant_id",
            "event_type",
            "occurred_at",
            name="uq_simulation_events_once",
        ),
    )

    campaign_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("campaigns.id", ondelete="CASCADE"))
    participant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("participants.id", ondelete="CASCADE")
    )
    event_type: Mapped[EventType] = mapped_column(str_enum(EventType))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
