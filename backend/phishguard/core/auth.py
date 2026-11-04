"""API key authentication for the extension, gateway and dashboard (header X-API-Key).

Fails closed: outside the development environment a missing PHISHGUARD_API_KEY makes the
protected endpoints answer 503 instead of letting every request through. Keys are compared in
constant time.
"""

import hmac
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status

from phishguard.core.config import Settings, get_settings


def require_api_key(
    settings: Annotated[Settings, Depends(get_settings)],
    x_api_key: Annotated[str | None, Header()] = None,
) -> str:
    if settings.api_key is None:
        if settings.environment == "development":
            return "development"
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "API key not configured")
    expected = settings.api_key.get_secret_value()
    if x_api_key is None or not hmac.compare_digest(x_api_key.encode(), expected.encode()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or missing API key")
    return "client"
