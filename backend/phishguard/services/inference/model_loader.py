"""Load trained models from registry for inference."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class ModelLoader:
    def __init__(self, models_dir: Path | None = None):
        if models_dir is None:
            from phishguard_ml import paths

            models_dir = paths.models_dir()
        self.models_dir = Path(models_dir)
        self.loaded = False
        self.metadata: dict[str, Any] = {}

    def load_registry(self) -> dict[str, Any]:
        registry_path = self.models_dir / "registry.json"
        if registry_path.exists():
            try:
                with registry_path.open() as f:
                    self.metadata = json.load(f)
                self.loaded = True
                return self.metadata
            except Exception:
                pass
        self.loaded = False
        return {}
