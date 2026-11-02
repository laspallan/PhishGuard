from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolated_data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Every test writes under its own temporary data/ folder, never the real one."""
    data = tmp_path / "data"
    monkeypatch.setenv("PHISHGUARD_DATA_DIR", str(data))
    monkeypatch.delenv("PHISHGUARD_PHISHTANK_APP_KEY", raising=False)
    monkeypatch.delenv("PHISHGUARD_PHISHTANK_USERNAME", raising=False)
    return data
