"""`make results` reproduces only what exists, and never opens the locked test set."""

import pytest

from phishguard_ml.evaluation import final, rebuild, report
from phishguard_ml.training import devdata, rq2


@pytest.fixture
def guarded(monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        raise AssertionError("make results must not open the locked test set")

    monkeypatch.setattr(devdata, "load_locked_test", forbidden)
    monkeypatch.setattr(final, "run", forbidden)
    monkeypatch.setattr(rq2, "results_dir", lambda: tmp_path / "rq2")
    monkeypatch.setattr(final, "predictions_path", lambda: tmp_path / "final" / "p.parquet")
    calls = []
    monkeypatch.setattr(report, "build", lambda n_boot: calls.append("development"))
    monkeypatch.setattr(rq2, "run", lambda n_boot: calls.append("rq2"))
    monkeypatch.setattr(final, "report", lambda n_boot: calls.append("final"))
    return tmp_path, calls


def test_nothing_produced_yet_means_everything_is_skipped(guarded, monkeypatch):
    _, calls = guarded
    monkeypatch.setattr(report, "_runs", lambda: {})
    done = rebuild.rebuild(n_boot=10)
    assert calls == [] and all(v.startswith("skipped") for v in done.values())


def test_only_results_that_exist_are_rebuilt(guarded, monkeypatch):
    tmp_path, calls = guarded
    monkeypatch.setattr(report, "_runs", lambda: {("url", "all"): {}})
    (tmp_path / "final").mkdir()
    (tmp_path / "final" / "p.parquet").write_bytes(b"")
    done = rebuild.rebuild(n_boot=10)
    assert calls == ["development", "final"]  # rq2 was never run, so it is not run early
    assert done["rq2"].startswith("skipped")
    (tmp_path / "rq2").mkdir()
    (tmp_path / "rq2" / "results.json").write_text("{}")
    rebuild.rebuild(n_boot=10)
    assert calls[-3:] == ["development", "rq2", "final"]
