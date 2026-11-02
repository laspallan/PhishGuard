from pathlib import Path

from phishguard_ml import paths


def test_default_data_dir_is_repo_root_data(monkeypatch):
    monkeypatch.delenv("PHISHGUARD_DATA_DIR", raising=False)

    assert paths.data_dir() == paths.REPO_ROOT / "data"
    assert (paths.REPO_ROOT / "ml" / "phishguard_ml").is_dir()


def test_data_dir_can_be_overridden(monkeypatch, tmp_path):
    monkeypatch.setenv("PHISHGUARD_DATA_DIR", str(tmp_path))

    assert paths.data_dir() == tmp_path
    assert paths.raw_dir() == tmp_path / "raw"
    assert paths.splits_dir() == Path(tmp_path) / "splits"
