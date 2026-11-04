"""Scan views. Answer 503 until a trained model is available (no placeholder verdicts)."""

from fastapi import APIRouter, Depends, HTTPException, status

from phishguard.controllers.scan_controller import ScanController
from phishguard.core.auth import require_api_key
from phishguard.schemas.scan import EmailScanRequest, URLScanRequest, VerdictResponse
from phishguard.services.inference.service import ModelNotLoadedError

router = APIRouter(prefix="/scan", tags=["scan"], dependencies=[Depends(require_api_key)])
controller = ScanController()


@router.post("/url", response_model=VerdictResponse)
async def scan_url(req: URLScanRequest):
    try:
        return await controller.scan_url(req.url)
    except ModelNotLoadedError as error:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(error)) from error


@router.post("/email", response_model=VerdictResponse)
async def scan_email(req: EmailScanRequest):
    try:
        return await controller.scan_email(req.raw_email)
    except ModelNotLoadedError as error:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(error)) from error
