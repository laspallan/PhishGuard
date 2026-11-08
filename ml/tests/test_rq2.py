"""RQ2 recording and experiment, offline: fake VirusTotal and OTX clients, synthetic data."""

import json
from datetime import UTC, datetime

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from phishguard.services.features.extractor import FEATURE_NAMES, feature_code_hash
from phishguard_ml import paths
from phishguard_ml.data import split
from phishguard_ml.data.records import SampleRecord, Source, write_records
from phishguard_ml.features import matrix
from phishguard_ml.training import rq2, tabular


class FakeVT:
    api_key = "vt"

    async def get_url_report(self, url):
        if "phish" in url:
            return {"data": {"attributes": {"last_analysis_stats": {"malicious": 4}}}}
        return {"status": "not_found"}


class FakeOTX:
    api_key = "otx"

    async def get_url_general(self, url):
        return {"pulse_info": {"count": 1 if "phish" in url else 0}}


def _url(source, i, when):
    host = f"phish{i}-test.com" if source is not Source.TRANCO else f"site{i}-test.com"
    return SampleRecord.create(
        source=source, raw_content=f"https://{host}/login", collected_at=when,
        group_key=f"domain:{host}",
    )  # fmt: skip


def _setup(n_legitimate=120, n_fresh=130):
    now = datetime.now(UTC)
    legitimate = [_url(Source.TRANCO, i, "2026-11-02T00:00Z") for i in range(n_legitimate)]
    dev_phishing = [_url(Source.PHISHTANK, 1000 + i, "2026-11-02T00:00Z") for i in range(40)]
    dataset = [*legitimate, *dev_phishing]
    split.write_split(dataset, split.make_split(dataset), {})
    rng = np.random.default_rng(0)
    columns = {"sample_id": [str(r.sample_id) for r in dataset]}
    columns.update({name: rng.normal(size=len(dataset)) for name in FEATURE_NAMES})
    table = pa.table(columns).replace_schema_metadata({"feature_code_hash": feature_code_hash()})
    matrix.features_path().parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(table, matrix.features_path())
    fresh = [_url(Source.PHISHTANK, i, now) for i in range(n_fresh)]
    day = now.date().isoformat()
    write_records(fresh, paths.processed_dir() / "monthly" / day[:7] / f"{day}.parquet")
    for model in tabular.MODELS:
        folder = tabular.run_dir("url", "live", model)
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "run.json").write_text(json.dumps({"params": {"n_estimators": 20}}))
    return legitimate, fresh


def test_a_day_is_balanced_capped_and_never_repeated(isolated_data_dir):
    _setup(n_legitimate=120, n_fresh=130)
    first = rq2.record_day(FakeVT(), FakeOTX(), per_class=50)
    assert first["looked_up"] == 100 and first["subset"] == {"phishing": 50, "legitimate": 50}
    again = rq2.record_day(FakeVT(), FakeOTX(), per_class=50)
    assert again["looked_up"] == 0  # today's quota is used
    more = rq2.record_day(FakeVT(), FakeOTX(), per_class=80)
    assert more["subset"] == {"phishing": 80, "legitimate": 80}
    ids = [line["sample_id"] for line in rq2.recordings()]
    assert len(ids) == len(set(ids)) == 160


def test_legitimate_lookups_never_outnumber_the_phishing_ones(isolated_data_dir):
    _setup(n_legitimate=120, n_fresh=10)
    result = rq2.record_day(FakeVT(), FakeOTX(), per_class=50)
    assert result["subset"] == {"phishing": 10, "legitimate": 10}


def test_only_development_urls_are_used_as_legitimate(isolated_data_dir):
    legitimate, _ = _setup()
    rows = split.load_split()[1]
    dev = {r["sample_id"] for r in rows if r["set"] == "dev"}
    rq2.record_day(FakeVT(), FakeOTX(), per_class=200)
    chosen = {line["sample_id"] for line in rq2.recordings() if line["label"] == "legitimate"}
    assert chosen and chosen <= dev


def test_no_keys_means_no_lookups(isolated_data_dir):
    vt = FakeVT()
    vt.api_key = None
    with pytest.raises(RuntimeError, match="PHISHGUARD_VIRUSTOTAL_API_KEY"):
        rq2.record_day(vt, FakeOTX())


def test_experiment_runs_end_to_end_and_changes_only_ti_score(isolated_data_dir):
    _setup(n_legitimate=120, n_fresh=130)
    rq2.record_day(FakeVT(), FakeOTX(), per_class=100)
    result = rq2.run(n_boot=20)
    rows = {r["model"]: r for r in result["rows"]}
    assert set(rows) == {"soft_vote_without_ti", "soft_vote_with_ti", "ti_score_alone"}
    assert result["n"] == 200 and result["n_phishing"] == 100
    assert result["phishing_flagged_by_virustotal_on_the_day"] == 1.0
    assert rows["ti_score_alone"]["fpr"] == 0  # the fake answers flag only phishing
    assert "mcnemar_vs_soft_vote" in rows["soft_vote_with_ti"]
    text = (rq2.results_dir() / "results.md").read_text(encoding="utf-8")
    assert text.startswith("# RQ2") and "Development results" not in text
    assert "McNemar p vs soft vote without ti_score" in text


def test_experiment_needs_the_tuned_live_models(isolated_data_dir):
    _setup()
    rq2.record_day(FakeVT(), FakeOTX(), per_class=100)
    (tabular.run_dir("url", "live", "xgboost") / "run.json").unlink()
    with pytest.raises(FileNotFoundError, match="train url/live first"):
        rq2.run(n_boot=20)
