"""Reads the model registry written by the training pipeline (ml/.../training/registry.py).

`<data_dir>/models/registry.json` is a JSON list of registered versions. The backend does not
import the ml package (the API image contains only the backend), so the path comes from the
settings (PHISHGUARD_DATA_DIR).
"""

import json
from pathlib import Path
from typing import Any

from phishguard.core.config import get_settings


class ModelLoader:
    def __init__(self, models_dir: Path | None = None):
        self.models_dir = Path(models_dir or get_settings().data_dir / "models")
        self.entries: list[dict[str, Any]] = []

    def load_registry(self) -> list[dict[str, Any]]:
        """Registered versions, or [] if there is no (readable) registry yet."""
        path = self.models_dir / "registry.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = []
        self.entries = [e for e in data if isinstance(e, dict)] if isinstance(data, list) else []
        return self.entries

    @property
    def loaded(self) -> bool:
        return bool(self.entries)
