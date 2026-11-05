import json
import re
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

import phishguard_ml
from phishguard.models.enums import Modality
from phishguard.services.features.extractor import FEATURE_NAMES, feature_code_hash
from phishguard_ml.data import split
from phishguard_ml.data.records import SampleRecord, Source
from phishguard_ml.features import matrix
from phishguard_ml.training import devdata, tabular
from phishguard_ml.training.devdata import DevData, StaleFeaturesError, feature_set

PACKAGE = Path(phishguard_ml.__file__).parent
T = "2026-11-02T00:00Z"


def test_only_devdata_may_open_the_split():
    """Locked-test guard: no training / evaluation code reads the split except devdata.py."""
    pattern = re.compile(r"load_split|split\.parquet|dataset\.parquet|splits_dir")
    offenders = [
        str(p.relative_to(PACKAGE))
        for folder in ("training", "evaluation")
        for p in (PACKAGE / folder).rglob("*.py")
        if p.name != "devdata.py" and pattern.search(p.read_text(encoding="utf-8"))
    ]
    assert offenders == []


def test_feature_sets():
    assert len(feature_set(Modality.URL, "all")) == 95
    no_path = feature_set(Modality.URL, "no_path")
    assert len(no_path) == 15 + 50  # host-only F1-F45 features + F46-F95
    assert "path_length" not in no_path and "hostname_length" in no_path
    assert len(feature_set(Modality.URL, "no_rdap")) == 95 - 7
    assert "tranco_rank" not in feature_set(Modality.URL, "no_tranco")
    assert feature_set(Modality.EMAIL, "no_header") == list(FEATURE_NAMES[115:])
    assert len(feature_set(Modality.EMAIL, "no_age")) == 45 - 8
    with pytest.raises(ValueError):
        feature_set(Modality.EMAIL, "no_path")


def _write_matrix(records, code_hash):
    rng = np.random.default_rng(0)
    columns = {"sample_id": [str(r.sample_id) for r in records]}
    for name in FEATURE_NAMES:
        columns[name] = rng.normal(size=len(records))
    table = pa.table(columns).replace_schema_metadata({"feature_code_hash": code_hash})
    matrix.features_path().parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(table, matrix.features_path())


def _emails(n):
    out = []
    for i in range(n):
        source = Source.NAZARIO if i % 2 else Source.SPAMASSASSIN
        out.append(
            SampleRecord.create(
                source=source,
                raw_content=f"Subject: s{i}\n\nbody {i}",
                collected_at=T,
                group_key=f"sender:{i}@x-test.com",
            )
        )
    return out


def test_load_development_keeps_dev_rows_of_one_modality(isolated_data_dir):
    emails = _emails(80)
    url = SampleRecord.create(
        source=Source.TRANCO, raw_content="https://a-test.com/", collected_at=T,
        group_key="domain:a-test.com",
    )  # fmt: skip
    dataset = [*emails, url]
    # the URL is a dev row of the other modality (one sample cannot be split on its own)
    rows = [*split.make_split(emails), {"sample_id": str(url.sample_id), "set": "dev", "fold": 0}]
    split.write_split(dataset, rows, {})
    _write_matrix(dataset, feature_code_hash())

    data = devdata.load_development(Modality.EMAIL, "no_header")

    dev_ids = {r["sample_id"] for r in rows if r["set"] == "dev"}
    test_ids = {r["sample_id"] for r in rows if r["set"] == "test"}
    assert set(data.sample_ids) <= dev_ids and not set(data.sample_ids) & test_ids
    assert str(url.sample_id) not in data.sample_ids
    assert data.X.shape == (len(data.sample_ids), 25)
    assert set(data.folds) <= {0, 1, 2, 3, 4}
    assert set(data.y) == {0, 1}


def test_stale_feature_matrix_is_refused(isolated_data_dir):
    dataset = _emails(40)
    split.write_split(dataset, split.make_split(dataset), {})
    _write_matrix(dataset, "0" * 64)
    with pytest.raises(StaleFeaturesError):
        devdata.load_development(Modality.EMAIL)


def _synthetic(n=300, seed=0) -> DevData:
    rng = np.random.default_rng(seed)
    X = rng.normal(size=(n, 4))
    X[rng.random(n) < 0.1, 2] = np.nan  # some missing values
    y = (X[:, 0] + 0.3 * rng.normal(size=n) > 0).astype(int)
    return DevData(
        sample_ids=[f"s{i}" for i in range(n)], X=X, y=y, folds=np.arange(n) % 5,
        groups=[f"g{i}" for i in range(n)], sources=["nazario"] * n,
        feature_names=["a", "b", "c", "d"],
    )  # fmt: skip


def test_out_of_fold_never_predicts_a_fold_it_trained_on(monkeypatch):
    data = _synthetic()
    data = DevData(**{**data.__dict__, "X": np.arange(len(data.y), dtype=float)[:, None]})
    seen = []

    class Recorder:
        def fit(self, X, y):
            self.trained = set(X[:, 0].astype(int))
            return self

        def predict_proba(self, X):
            rows = set(X[:, 0].astype(int))
            seen.append(rows & self.trained)
            return np.tile([0.5, 0.5], (len(X), 1))

    monkeypatch.setattr(tabular, "make_model", lambda *a, **k: Recorder())
    oof = tabular.out_of_fold("xgboost", {}, data)
    assert seen and all(not overlap for overlap in seen)
    assert not np.isnan(oof).any()


@pytest.mark.parametrize("name", tabular.MODELS)
def test_each_model_learns_and_tuning_is_reproducible(name):
    data = _synthetic()
    first = tabular.tune(name, data, n_trials=2)
    again = tabular.tune(name, data, n_trials=2)
    assert first[0] == again[0]  # same seed -> same parameters
    assert first[1] == pytest.approx(again[1])  # loss equal up to float rounding (threads)
    oof = tabular.out_of_fold(name, first[0], data)
    accuracy = ((oof > 0.5) == data.y).mean()
    assert accuracy > 0.8


def test_train_and_save_writes_oof_and_metadata(isolated_data_dir):
    data = _synthetic(150)
    info = tabular.train_and_save(
        "lightgbm", data, modality="email", feature_set="no_header", n_trials=1,
        split_sha256={"split.parquet": "abc"},
    )  # fmt: skip
    folder = tabular.run_dir("email", "no_header", "lightgbm")
    saved = json.loads((folder / "run.json").read_text())
    assert saved["feature_code_hash"] == feature_code_hash() == info.feature_code_hash
    assert saved["seed"] == 42 and saved["n_samples"] == 150
    oof = pq.read_table(folder / "oof.parquet").to_pylist()
    assert len(oof) == 150 and {"sample_id", "fold", "label", "source", "p_phishing"} <= set(oof[0])
