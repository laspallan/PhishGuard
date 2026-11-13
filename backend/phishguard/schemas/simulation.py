"""Requests and answers of the campaign-management endpoints. An answer never contains an email
address or what one participant did."""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from phishguard.models.enums import AttackCategory, TemplateSplit


class TemplateIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    subject: str = Field(min_length=1)
    html: str = Field(min_length=1)  # GoPhish puts the simulation link where {{.URL}} is
    text: str = ""
    fictional_org: str = Field(min_length=1, max_length=100)
    attack_category: AttackCategory
    split: TemplateSplit


class ParticipantIn(BaseModel):
    email: str = Field(min_length=3, max_length=254, pattern=r"^[^@\s]+@[^@\s]+$")
    participant_code: str = Field(min_length=1, max_length=32)
    consent_form_version: str = Field(min_length=1, max_length=32)
    consent_given_at: datetime


class CampaignIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    template_id: uuid.UUID


class LaunchIn(BaseModel):
    participant_ids: list[uuid.UUID] = Field(min_length=1)
    smtp: str = Field(min_length=1)  # name of a GoPhish sending profile
    url: str = Field(min_length=1)  # where GoPhish serves the landing page


class Created(BaseModel):
    id: uuid.UUID
    status: str | None = None


class TemplateRow(BaseModel):
    id: uuid.UUID
    name: str
    fictional_org: str
    attack_category: str
    split: str


class ParticipantRow(BaseModel):
    """By code only: the email address is never sent back."""

    id: uuid.UUID
    participant_code: str
    consent_form_version: str
    consent_given_at: datetime
    withdrawn: bool


class CampaignRow(BaseModel):
    id: uuid.UUID
    name: str
    template_name: str
    status: str
    launched_at: datetime | None
    completed_at: datetime | None


class Erased(BaseModel):
    deleted: bool
    gophish_groups_changed: int
    # Launched campaigns whose GoPhish results still hold copies of targets (erase them after the
    # last fetch, with .../campaigns/{id}/erase-gophish).
    gophish_campaigns_still_holding_results: int


class SyncResult(BaseModel):
    saved: int
    already_saved: int
    unknown_address: int
    withdrawn: int
