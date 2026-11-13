"""Campaign management for the dashboard, behind the API key. Nothing can be sent before the
ethics approval reference is configured (checked in services/simulation/campaigns.py)."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from phishguard.controllers.simulation_controller import SimulationController
from phishguard.core.auth import require_api_key
from phishguard.core.config import Settings, get_settings
from phishguard.db.session import get_db
from phishguard.schemas.simulation import (
    CampaignIn,
    CampaignRow,
    Created,
    Erased,
    LaunchIn,
    ParticipantIn,
    ParticipantRow,
    SyncResult,
    TemplateIn,
    TemplateRow,
)

router = APIRouter(
    prefix="/admin/simulation", tags=["simulation"], dependencies=[Depends(require_api_key)]
)
controller = SimulationController()
Db = Annotated[Session, Depends(get_db)]
Config = Annotated[Settings, Depends(get_settings)]


@router.get("/templates", response_model=list[TemplateRow])
def templates(session: Db):
    return controller.templates(session)


@router.get("/participants", response_model=list[ParticipantRow])
def participants(session: Db):
    return controller.participants(session)


@router.get("/campaigns", response_model=list[CampaignRow])
def campaigns(session: Db):
    return controller.campaigns(session)


@router.post("/templates", response_model=Created, status_code=201)
def create_template(body: TemplateIn, session: Db, settings: Config):
    return controller.create_template(session, settings, body)


@router.post("/participants", response_model=Created, status_code=201)
def add_participant(body: ParticipantIn, session: Db):
    return controller.add_participant(session, body)


@router.post("/participants/{participant_id}/withdraw", response_model=Created)
def withdraw(participant_id: uuid.UUID, session: Db):
    return controller.withdraw(session, participant_id)


@router.post("/participants/{participant_id}/delete", response_model=Erased)
def erase_participant(participant_id: uuid.UUID, session: Db, settings: Config):
    """Withdrawn participants only: deletes their record, events and samples, and their address
    from PhishGuard's GoPhish groups."""
    return controller.erase_participant(session, settings, participant_id)


@router.post("/campaigns/{campaign_id}/erase-gophish", response_model=Created)
def erase_gophish_results(campaign_id: uuid.UUID, session: Db, settings: Config):
    """Completed campaigns only: deletes the campaign's results (addresses, IPs) from GoPhish."""
    return controller.erase_gophish_results(session, settings, campaign_id)


@router.post("/campaigns", response_model=Created, status_code=201)
def create_campaign(body: CampaignIn, session: Db):
    return controller.create_campaign(session, body)


@router.post("/campaigns/{campaign_id}/launch", response_model=Created)
def launch(campaign_id: uuid.UUID, body: LaunchIn, session: Db, settings: Config):
    return controller.launch(session, settings, campaign_id, body)


@router.post("/campaigns/{campaign_id}/sync", response_model=SyncResult)
def sync(campaign_id: uuid.UUID, session: Db, settings: Config):
    return controller.sync(session, settings, campaign_id)


@router.post("/campaigns/{campaign_id}/complete", response_model=Created)
def complete(campaign_id: uuid.UUID, session: Db, settings: Config):
    return controller.complete(session, settings, campaign_id)
