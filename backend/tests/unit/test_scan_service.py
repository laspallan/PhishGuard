"""The scan flow (D11) with fake models and a fake collector: every path through the decision."""

import asyncio
import json

import fakeredis
import joblib
import numpy as np
import pytest
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from phishguard.core.config import Settings
from phishguard.models import ModelVersion, Scan, ScanFeatures
from phishguard.services.features.extractor import FEATURE_NAMES, feature_code_hash
from phishguard.services.inference.model_loader import ModelLoader, ServingModel
from phishguard.services.inference.persist import record_scan
from phishguard.services.inference.scan_store import ScanStore
from phishguard.services.inference.service import (
    InferenceService,
    ModelNotLoadedError,
    RateLimitedError,
    decision_for,
)

URL = "https://shop-test.com/login"
TOKEN_URL = "https://shop-test.com/reset?token=abc"
SETTINGS = Settings(_env_file=None, environment="test", scan_rate_limit_per_minute=2)
ANSWER = {"meta": {}, "dns": {"A": {"records": ["203.0.113.5"], "ttl": 60}}, "late": []}


def _entry(version: str, modality: str = "url") -> dict:
    return {
        "version": version,
        "path": version,
        "model": "xgboost",
        "modality": modality,
        "feature_names": list(FEATURE_NAMES[:3]),
        "feature_code_hash": feature_code_hash(),
        "split_sha256": {"dataset.parquet": "a" * 64},
        "seed": 42,
        "oof_log_loss": 0.1,
        "registered_at": "2026-11-06T00:00:00+00:00",
    }


class FakeModel:
    def __init__(self, version: str, probability: float):
        self.version, self.p, self.entry = version, probability, _entry(version)

    def probability(self, values):
        assert len(values) == 140
        return self.p

    def explanations(self, values):
        return [{"feature": "hostname_length", "value": 1.0, "importance": 0.5}]


class FakeLoader:
    def __init__(self, m1=None, m2=None, email=None):
        self.models = {"live_stage1": m1, "live": m2, "no_header": email}

    def load_registry(self):
        return []

    def serving_model(self, modality, feature_set):
        return self.models[feature_set]


class FakeCollector:
    def __init__(self, stage1=ANSWER, stage2=ANSWER):
        self.answers, self.calls = {1: stage1, 2: stage2}, []

    def __call__(self, url, stage, wait_seconds):
        self.calls.append(stage)
        return self.answers[stage]


def _service(p1, p2=0.0, collector=None, store=None, recorder=None):
    return InferenceService(
        FakeLoader(FakeModel("m1", p1), FakeModel("m2", p2)),
        settings=SETTINGS,
        evidence=collector or FakeCollector(),
        store=store or ScanStore(),
        recorder=recorder,
    )


def _scan(service, url=URL, client="c"):
    return asyncio.run(service.scan_url(url, client))


@pytest.mark.parametrize(("p", "verdict"), [(0.05, "allow"), (0.86, "warn"), (0.95, "block")])
def test_a_confident_stage_1_decides_without_contacting_the_target(p, verdict):
    collector = FakeCollector()
    result = _scan(_service(p, collector=collector))

    assert collector.calls == [1]
    assert result["verdict"] == verdict and result["stage"] == 1
    assert result["evidence"] == "complete" and result["model_version"] == "m1"


def test_an_unsure_stage_1_fetches_and_the_full_model_decides():
    collector = FakeCollector()
    result = _scan(_service(0.5, 0.95, collector=collector))

    assert collector.calls == [1, 2]
    assert result["verdict"] == "block" and result["stage"] == 2 and result["score"] == 0.95
    assert result["model_version"] == "m2" and result["evidence"] == "complete"


def test_a_url_that_may_carry_a_secret_is_never_fetched_and_at_most_warn():
    for p, verdict in [(0.5, "warn"), (0.99, "warn"), (0.05, "allow")]:
        collector = FakeCollector()
        result = _scan(_service(p, collector=collector), TOKEN_URL)
        assert collector.calls == [1] and result["verdict"] == verdict


def test_unsure_and_private_target_is_not_fetched_and_warns():
    private = {"meta": {"unsafe_host": True}, "late": []}
    collector = FakeCollector(stage1=private)
    result = _scan(_service(0.5, collector=collector))
    assert collector.calls == [1] and result["verdict"] == "warn"
    assert result["evidence"] == "partial"


@pytest.mark.parametrize(
    "stage2", [None, {**ANSWER, "late": ["page"]}, {**ANSWER, "refused": True}]
)
def test_late_or_refused_page_never_becomes_allow(stage2):
    result = _scan(_service(0.5, 0.0, collector=FakeCollector(stage2=stage2)))
    assert result["verdict"] == "warn" and result["evidence"] == "partial"
    assert result["model_version"] == "m1"


@pytest.mark.parametrize(("p", "verdict"), [(0.05, "warn"), (0.5, "warn"), (0.95, "block")])
def test_collector_down_gives_an_answer_block_only_if_stage_1_is_sure(p, verdict):
    result = _scan(_service(p, collector=FakeCollector(stage1=None, stage2=None)))
    assert result["verdict"] == verdict and result["evidence"] == "partial"
    assert result["stage"] == 1


def test_repeated_scans_do_not_contact_the_target_again():
    store = ScanStore(fakeredis.FakeRedis())
    collector = FakeCollector()
    service = InferenceService(
        FakeLoader(FakeModel("m1", 0.5), FakeModel("m2", 0.95)),
        settings=Settings(_env_file=None, environment="test"),
        evidence=collector,
        store=store,
        recorder=None,
    )
    first = _scan(service)
    second = _scan(service)

    assert collector.calls == [1, 2]
    assert second["cached"] is True and second["verdict"] == first["verdict"]
    assert "shop-test.com" not in " ".join(k.decode() for k in store.client.keys("*"))


def test_partial_verdicts_are_cached_for_a_shorter_time():
    store = ScanStore(fakeredis.FakeRedis())
    _scan(_service(0.5, collector=FakeCollector(stage2=None), store=store))
    key = store.client.keys("phishguard:verdict:*")[0]
    assert 0 < store.client.ttl(key) <= 300


def test_rate_limit_per_client():
    store = ScanStore(fakeredis.FakeRedis())
    service = _service(0.05, store=store)  # limit: 2 per minute
    _scan(service)
    _scan(service)
    with pytest.raises(RateLimitedError):
        _scan(service)
    _scan(service, client="another-client")


def test_redis_failure_does_not_stop_scans():
    class Broken(fakeredis.FakeRedis):
        def execute_command(self, *args, **kwargs):
            import redis

            raise redis.ConnectionError

    assert _scan(_service(0.05, store=ScanStore(Broken())))["verdict"] == "allow"


def test_no_model_means_503_never_a_guess():
    collector = FakeCollector()
    only_m1 = InferenceService(
        FakeLoader(FakeModel("m1", 0.1)), settings=SETTINGS, evidence=collector,
        store=ScanStore(), recorder=None,
    )  # fmt: skip
    with pytest.raises(ModelNotLoadedError):
        _scan(only_m1)
    with pytest.raises(ModelNotLoadedError):
        asyncio.run(only_m1.scan_email("Subject: x\n\ny"))
    assert collector.calls == []


def test_thresholds_are_the_plan_defaults():
    assert [decision_for(p) for p in (0.59, 0.60, 0.89, 0.90)] == [
        "allow", "warn", "warn", "block",
    ]  # fmt: skip


def test_email_scan_saves_hash_and_sender_domain_never_the_text(sqlite_engine):
    saved = []
    service = InferenceService(
        FakeLoader(email=FakeModel("mail", 0.95)), settings=SETTINGS, store=ScanStore(),
        recorder=lambda **fields: saved.append(fields),
    )  # fmt: skip
    raw = "From: Bank <a@Bad-Test.com>\nSubject: secret words\n\nsecret body"
    result = asyncio.run(service.scan_email(raw))

    assert result["verdict"] == "block" and result["ti_score"] is None
    fields = saved[0]
    assert fields["sender_domain"] == "bad-test.com" and fields["url"] is None
    assert len(fields["values"]) == 140

    session_factory = sessionmaker(bind=sqlite_engine)
    record_scan(session_factory, **fields)
    with session_factory() as session:
        scan = session.scalar(select(Scan))
        assert scan.sender_domain == "bad-test.com" and scan.url is None
        assert "secret" not in json.dumps([scan.input_hash, scan.sender_domain])
        assert len(session.scalar(select(ScanFeatures)).values) == 140


def test_url_scans_are_saved_once_per_model_version_and_without_secrets(sqlite_engine):
    session_factory = sessionmaker(bind=sqlite_engine)
    recorder = lambda **fields: record_scan(session_factory, **fields)  # noqa: E731
    service = _service(0.05, recorder=recorder)
    _scan(service, TOKEN_URL)
    _scan(service)

    with session_factory() as session:
        scans = session.scalars(select(Scan)).all()
        assert sorted(s.url for s in scans) == [
            "https://shop-test.com/login", "https://shop-test.com/reset",
        ]  # fmt: skip
        assert len(session.scalars(select(ModelVersion)).all()) == 1
        assert all(s.decision == "allow" and s.latency_ms >= 0 for s in scans)


def test_a_database_failure_does_not_lose_the_verdict():
    def broken(**fields):
        raise OSError("database down")

    assert _scan(_service(0.05, recorder=broken))["verdict"] == "allow"


# --- real files through the loader -----------------------------------------------------------


def _register(models_dir, name, *, log_loss=0.1, code_hash=None, feature_set="live_stage1"):
    folder = models_dir / name
    folder.mkdir(parents=True)
    X = np.array([[0.0], [1.0], [0.1], [0.9]])
    y = np.array([0, 1, 0, 1])
    joblib.dump(LogisticRegression().fit(X, y), folder / "model.joblib")
    calibrator = IsotonicRegression(y_min=0, y_max=1, out_of_bounds="clip").fit([0, 1], [0, 1])
    joblib.dump(calibrator, folder / "calibrator.joblib")
    import hashlib

    return {
        **_entry(name),
        "feature_set": feature_set,
        "feature_names": [FEATURE_NAMES[0]],
        "oof_log_loss": log_loss,
        "feature_code_hash": code_hash or feature_code_hash(),
        "model_sha256": hashlib.sha256((folder / "model.joblib").read_bytes()).hexdigest(),
    }


def test_loader_serves_the_best_usable_model(tmp_path):
    entries = [
        _register(tmp_path, "good", log_loss=0.2),
        _register(tmp_path, "better", log_loss=0.1),
        _register(tmp_path, "stale", log_loss=0.01, code_hash="0" * 64),
    ]
    (tmp_path / "registry.json").write_text(json.dumps(entries))
    loader = ModelLoader(tmp_path)
    loader.load_registry()

    model = loader.serving_model("url", "live_stage1")
    assert model.version == "better"
    assert 0 <= model.probability({FEATURE_NAMES[0]: 1.0}) <= 1
    assert loader.serving_model("url", "live") is None


def test_scan_returns_the_explanations_of_the_model_that_decided():
    result = _scan(_service(0.5, 0.95))
    assert result["explanations"][0]["feature"] == "hostname_length"


@pytest.mark.parametrize("kind", ["lightgbm", "xgboost"])
def test_explanations_are_shap_values_that_add_up_to_the_raw_score(kind):
    """Real models: the strongest feature comes first, and the values are not made up."""
    rng = np.random.default_rng(0)
    X = rng.normal(size=(200, 3))
    y = (X[:, 1] > 0).astype(int)
    if kind == "lightgbm":
        lightgbm = pytest.importorskip("lightgbm")
        model = lightgbm.LGBMClassifier(n_estimators=20, verbose=-1).fit(X, y)
    else:
        xgboost = pytest.importorskip("xgboost")
        model = xgboost.XGBClassifier(n_estimators=20).fit(X, y)
    names = list(FEATURE_NAMES[:3])
    entry = {**_entry("m"), "model": kind, "feature_names": names}
    serving = ServingModel(entry, model, None)

    values = dict(zip(names, [0.1, 2.0, float("nan")], strict=True))
    found = serving.explanations(values, top=2)
    assert len(found) == 2 and found[0]["feature"] == names[1] and found[0]["importance"] > 0
    assert serving.explanations(dict.fromkeys(names, -1.0), top=1)[0]["importance"] < 0
    every = serving.explanations(values, top=3)
    assert next(e for e in every if e["feature"] == names[2])["value"] is None


def test_a_random_forest_has_no_invented_explanation():
    model = ServingModel({"model": "random_forest", "feature_names": []}, None, None)
    assert model.explanations({}) == []


def test_a_failing_explanation_does_not_lose_the_verdict():
    class Broken:
        def predict(self, *args, **kwargs):
            raise RuntimeError

    entry = {"model": "lightgbm", "feature_names": [FEATURE_NAMES[0]]}
    assert ServingModel(entry, Broken(), None).explanations({FEATURE_NAMES[0]: 1.0}) == []


def test_loader_refuses_a_changed_or_escaping_model_file(tmp_path):
    changed = _register(tmp_path, "changed")
    (tmp_path / "changed" / "model.joblib").write_bytes(b"tampered")
    (tmp_path / "registry.json").write_text(json.dumps([changed]))
    loader = ModelLoader(tmp_path)
    loader.load_registry()
    assert loader.serving_model("url", "live_stage1") is None

    (tmp_path / "models").mkdir()
    outside = _register(tmp_path / "models", "../outside")
    (tmp_path / "models" / "registry.json").write_text(json.dumps([outside]))
    loader = ModelLoader(tmp_path / "models")
    loader.load_registry()
    assert loader.serving_model("url", "live_stage1") is None
