"""The final evaluation on synthetic data. Never touches real data (see conftest)."""

import json
import re
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

import phishguard_ml
from phishguard.services.features.extractor import FEATURE_NAMES, feature_code_hash
from phishguard_ml.__main__ import main
from phishguard_ml.data import split
from phishguard_ml.data.records import SampleRecord, Source
from phishguard_ml.evaluation import final, latency
from phishguard_ml.features import matrix
from phishguard_ml.training import devdata, registry
from phishguard_ml.training.devdata import LockedTestNotConfirmedError

PACKAGE = Path(phishguard_ml.__file__).parent
T = "2026-11-02T00:00Z"


@pytest.fixture
def trained(isolated_data_dir):
    records = []
    for i in range(120):
        phishing = i % 2 == 1
        records.append(
            SampleRecord.create(
                source=Source.NAZARIO if phishing else Source.SPAMASSASSIN,
                raw_content=f"Subject: s{i}\n\nbody {i}",
                collected_at=T,
                group_key=f"sender:{i}@x-test.com",
            )
        )
    split.write_split(records, split.make_split(records), {})
    rng = np.random.default_rng(0)
    phishing = np.array([r.source is Source.NAZARIO for r in records], dtype=float)
    columns = {"sample_id": [str(r.sample_id) for r in records]}
    for name in FEATURE_NAMES:
        columns[name] = rng.normal(size=len(records))
    columns["num_credential_terms"] = phishing * 2 + rng.normal(scale=0.5, size=len(records))
    table = pa.table(columns).replace_schema_metadata({"feature_code_hash": feature_code_hash()})
    matrix.features_path().parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(table, matrix.features_path())
    assert (
        main(["train", "--modality", "email", "--feature-set", "no_header", "--trials", "1"]) == 0
    )
    return records


def test_only_final_may_open_the_locked_test_set():
    offenders = [
        str(p.relative_to(PACKAGE))
        for p in PACKAGE.rglob("*.py")
        if p.name not in ("final.py", "devdata.py")
        and re.search("load_locked_test", p.read_text(encoding="utf-8"))
    ]
    assert offenders == []


def test_nothing_opens_without_confirmation(trained, capsys):
    with pytest.raises(LockedTestNotConfirmedError):
        final.run()
    assert not final.access_log_path().exists() and not final.predictions_path().exists()
    assert main(["final-eval"]) == 2
    assert "Refusing" in capsys.readouterr().err
    from phishguard.models.enums import Modality

    with pytest.raises(LockedTestNotConfirmedError):
        devdata.load_locked_test(Modality.EMAIL, "no_header", None)


def test_a_model_sees_the_locked_test_set_once_and_the_access_is_logged(trained):
    results = final.run(confirmed=True)
    rows = results["email/no_header"]
    assert {r["model"] for r in rows} == {
        "random_forest", "xgboost", "lightgbm", "soft_vote", "stacker",
    }  # fmt: skip

    lines = final.access_log_path().read_text().splitlines()
    assert len(lines) == 1
    assert set(json.loads(lines[0])["versions"]) == {e["version"] for e in registry.load_registry()}
    with pytest.raises(final.AlreadyEvaluatedError):
        final.run(confirmed=True)
    assert len(final.access_log_path().read_text().splitlines()) == 1


def test_only_locked_rows_are_predicted(trained):
    final.run(confirmed=True)
    locked = {r["sample_id"] for r in split.load_split()[1] if r["set"] != "dev"}
    predicted = set(pq.read_table(final.predictions_path())["sample_id"].to_pylist())
    assert predicted == locked and locked


def test_the_report_reproduces_the_numbers_without_the_test_set(trained, monkeypatch):
    first = final.run(confirmed=True)

    def forbidden(*args, **kwargs):
        raise AssertionError("the report must not open the locked test set")

    monkeypatch.setattr(devdata, "load_locked_test", forbidden)
    monkeypatch.setattr(devdata, "load_split", forbidden)
    assert final.report() == first
    table = (final.access_log_path().parent / "final_results.md").read_text(encoding="utf-8")
    assert table.startswith("# Final results on the locked test set")
    assert all(f"## {key}" in table for key in first)


def test_stale_models_are_refused_before_anything_is_opened(trained):
    entries = [{**e, "feature_code_hash": "0" * 64} for e in registry.load_registry()]
    with pytest.raises(ValueError, match="other feature code"):
        final.run(confirmed=True, entries=entries)
    assert not final.access_log_path().exists()


def test_recent_email_check_is_empty_until_your_emails_exist(trained):
    assert final.recent_email_check() == {}


def test_recent_email_check_gives_an_fpr_for_each_email_model(trained, isolated_data_dir):
    from phishguard_ml import paths
    from phishguard_ml.data.records import write_records

    emails = [
        SampleRecord.create(
            source=Source.OWN_MAILBOX, raw_content=f"Subject: lunch {i}\n\nsee you", collected_at=T
        )
        for i in range(4)
    ]
    write_records(emails, paths.processed_dir() / "own_mailbox.parquet")
    result = final.recent_email_check()
    assert set(result) == {f"no_header/{m}" for m in ("random_forest", "xgboost", "lightgbm")}
    assert all(row["n"] == 4 and 0 <= row["fpr"] <= 1 for row in result.values())


def test_latency_asks_the_text_model_only_inside_the_band():
    asked = []
    X = np.zeros((3, 1))
    scores = iter([0.1, 0.5, 0.95])
    result = latency.measure(lambda row: next(scores), asked.append, X, ["a", "b", "c"])
    assert asked == ["b"] and result["n"] == 3
    assert result["share_sent_to_text_model"] == pytest.approx(1 / 3)
    assert result["p95_ms"] >= result["median_ms"] >= 0
