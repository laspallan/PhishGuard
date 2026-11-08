"""Offline recording of raw threat-intelligence responses with timestamps (decision D7).

One JSON line per lookup in <data_dir>/ti_responses/ti_<YYYY-MM-DD>.jsonl (UTC day).
"""

import json
from datetime import UTC, datetime
from pathlib import Path

from phishguard.core.config import get_settings


class TIRecorder:
    def __init__(self, out_dir: Path | None = None):
        self.out_dir = Path(out_dir or get_settings().data_dir / "ti_responses")

    def record(self, url: str, response: dict, extra: dict | None = None) -> Path:
        """`extra` adds fields to the line (the RQ2 recorder adds the sample id and label)."""
        now = datetime.now(UTC)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        path = self.out_dir / f"ti_{now.date().isoformat()}.jsonl"
        line = {**(extra or {}), "url": url, "queried_at": now.isoformat(), "response": response}
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(line) + "\n")
        return path
