"""Scan views."""
from __future__ import annotations

from fastapi import APIRouter

from phishguard.controllers.scan_controller import ScanController
from phishguard.schemas.scan import EmailScanRequest, URLScanRequest, VerdictResponse

router = APIRouter(prefix="/scan", tags=["scan"])
controller = ScanController()


@router.post("/url", response_model=VerdictResponse)
async def scan_url(req: URLScanRequest):
    result = await controller.scan_url(req.url)
    return result


@router.post("/email", response_model=VerdictResponse)
async def scan_email(req: EmailScanRequest):
    result = await controller.scan_email(req.raw_email)
    return result
