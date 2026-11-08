"""For the browser extension, behind the API key: hosts to block before they load."""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from phishguard.controllers.extension_controller import ExtensionController
from phishguard.core.auth import require_api_key
from phishguard.db.session import get_db
from phishguard.schemas.extension import BlockedHosts

router = APIRouter(prefix="/extension", tags=["extension"], dependencies=[Depends(require_api_key)])
controller = ExtensionController()
Db = Annotated[Session, Depends(get_db)]


@router.get("/blocked-hosts", response_model=BlockedHosts)
def blocked_hosts(session: Db):
    return controller.blocked_hosts(session)
