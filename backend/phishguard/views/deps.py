"""FastAPI dependencies."""
from __future__ import annotations

from phishguard.core.auth import require_api_key

__all__ = ["require_api_key"]
