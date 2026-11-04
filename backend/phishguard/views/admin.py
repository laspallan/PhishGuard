"""Admin views."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from phishguard.controllers.admin_controller import AdminController
from phishguard.core.auth import require_api_key
from phishguard.schemas.admin import AdminStatus

router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(require_api_key)])
controller = AdminController()


@router.get("/status", response_model=AdminStatus)
def status():
    return controller.status()
