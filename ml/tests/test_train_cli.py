"""End to end on synthetic data: split -> features -> train (3 models) -> report."""

import json

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

from phishguard.services.features.extractor import FEATURE_NAMES, feature_code_hash
from phishguard_ml.__main__ import main
from phishguard_ml.data import split
from phishguard_ml.data.records import SampleRecord, Source
from phishguard_ml.evaluation import report
from phishguard_ml.features import matrix
from phishguard_ml.training import registry

T = "2026-11-02T00:00Z"


def _dataset(n=150):
    records = []
    for i in range(n):
        source = Source.NAZARIO if i % 2 else (Source.ENRON if i % 4 == 0 else Source.SPAMASSASSIN)
        records.append(
            SampleRecord.create(
                source=source,
                raw_content=f"Subject: s{i}\n\nbody {i}",
                collected_at=T,
                group_key=f"sender:{i}@x-test.com",
            )  # fmt: skip
        )
    return records


def test_train_and_report_end_to_end(isolated_data_dir, capsys):
    records = _dataset()
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
    entries = registry.load_registry()
    assert sorted(e["model"] for e in entries) == ["lightgbm", "random_forest", "xgboost"]
    assert all(e["feature_code_hash"] == feature_code_hash() for e in entries)
    folder = isolated_data_dir / "models" / "email" / "no_header" / "xgboost"
    assert (folder / "model.joblib").exists() and (folder / "calibrator.joblib").exists()
    shap_rows = json.loads((folder / "shap.json").read_text())
    assert len(shap_rows) == 25 and shap_rows[0]["feature"] == "num_credential_terms"

    # SpamAssassin baseline (D2): pretend it flagged every Nazario email
    from phishguard.models.enums import Modality
    from phishguard_ml.evaluation import baseline
    from phishguard_ml.training.devdata import development_records

    emails = development_records(Modality.EMAIL)
    baseline.work_dir().mkdir(parents=True)
    with (baseline.work_dir() / "scored.mbox").open("w") as out:
        for r in emails:
            score = 9.0 if r.source is Source.NAZARIO else 0.0
            out.write("From x Thu Jan  1 00:00:00 1970\n")
            out.write(f"X-Spam-Status: No, score={score} required=5.0\n")
            out.write(f"{baseline.ID_HEADER}: {r.sample_id}\n\nx\n\n")
    assert main(["baseline-import"]) == 0

    assert main(["report", "--n-boot", "20"]) == 0
    results = json.loads((isolated_data_dir / "models" / "results.json").read_text())
    rows = {r["model"]: r for r in results["email/no_header"]}
    assert set(rows) == {
        "random_forest", "xgboost", "lightgbm", "soft_vote", "stacker", "spamassassin_baseline",
    }  # fmt: skip
    sa = rows["spamassassin_baseline"]
    assert sa["recall"] == 1 and sa["fpr"] == 0
    assert rows["spamassassin_baseline"]["ece"] is None  # decisions, not probabilities
    assert rows["soft_vote"]["accuracy"] > 0.8  # the one informative feature is learned
    assert "mcnemar_vs_soft_vote" in rows["xgboost"]
    assert set(rows["xgboost"]["fpr_by_legitimate_source"]) == {"enron", "spamassassin"}
    assert "| soft_vote |" in report.results_path().read_text(encoding="utf-8")
