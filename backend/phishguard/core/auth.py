"""API key authentication for extension/gateway/admin."""
from __future__ import annotations

import os
from typing import Annotated

from fastapi import Header, HTTPException, status


async def require_api_key(x_api_key: Annotated[str | None, Header()] = None) -> str:
    expected = os.environ.get("PHISHGUARD_API_KEY") or os.environ.get("API_KEY")
    if expected and x_api_key != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )
    # If no key configured in env, allow for local dev (but log in real deployment)
    return x_api_key or "anonymous"
