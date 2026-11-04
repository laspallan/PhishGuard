"""Threat intelligence offline recording stub (Phase 4)."""
from __future__ import annotations

from pathlib import Path

from phishguard_ml import paths


class TIRecorder:
    def __init__(self, out_dir: Path | None = None):
        self.out_dir = out_dir or (paths.data_dir() / "ti_responses")
        self.out_dir.mkdir(parents=True, exist_ok=True)

    def record(self, url: str, response: dict):
        import json
        from datetime import datetime

        fname = self.out_dir / f"ti_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.jsonl"
        with fname.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"url": url, "response": response}) + "\n")
