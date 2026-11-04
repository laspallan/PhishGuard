"""Persist scan results to database."""

from __future__ import annotations

from typing import Any


class ScanPersister:
    def persist_scan(self, scan_data: dict[str, Any]) -> str | None:
        # Stub - will write to DB when session/DB is wired
        return None
