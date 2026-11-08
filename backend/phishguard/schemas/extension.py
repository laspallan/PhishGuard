"""Answers for the browser extension."""

from datetime import datetime

from pydantic import BaseModel


class BlockedHosts(BaseModel):
    """Host names only, never URLs (a URL can carry the victim's address)."""

    hosts: list[str]
    block_days: int
    generated_at: datetime
