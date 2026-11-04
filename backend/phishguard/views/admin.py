"""Admin views."""
from __future__ import annotations

from fastapi import APIRouter

from phishguard.controllers.admin_controller import AdminController
from phishguard.schemas.admin import AdminStatus

router = APIRouter(prefix="/admin", tags=["admin"])
controller = AdminController()


@router.get("/status", response_model=AdminStatus)
def status():
    return controller.status()
