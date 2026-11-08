"""Admin views: read-only, behind the API key."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from phishguard.controllers.admin_controller import AdminController
from phishguard.core.auth import require_api_key
from phishguard.core.config import Settings, get_settings
from phishguard.db.session import get_db
from phishguard.schemas.admin import (
    AdminStatus,
    CampaignSummary,
    ExperimentResult,
    Overview,
    RecentScan,
)

router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(require_api_key)])
controller = AdminController()
Db = Annotated[Session, Depends(get_db)]
Config = Annotated[Settings, Depends(get_settings)]


@router.get("/status", response_model=AdminStatus)
def status(settings: Config):
    return controller.status(settings)


@router.get("/overview", response_model=Overview)
def overview(session: Db):
    return controller.overview(session)


@router.get("/scans", response_model=list[RecentScan])
def scans(session: Db, limit: Annotated[int, Query(ge=1, le=200)] = 50):
    return controller.recent_scans(session, limit)


@router.get("/campaigns", response_model=list[CampaignSummary])
def campaigns(session: Db):
    return controller.campaigns(session)


@router.get("/results")
def results(settings: Config) -> dict[str, Any]:
    return controller.results(settings)


@router.get("/experiments", response_model=list[ExperimentResult])
def experiments(session: Db):
    return controller.experiments(session)
