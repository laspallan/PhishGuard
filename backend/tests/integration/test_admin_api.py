"""The dashboard's read-only endpoints, on SQLite."""

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from phishguard.core.config import Settings, get_settings
from phishguard.db.session import get_db
from phishguard.main import create_app
from phishguard.models import (
    Campaign,
    ExperimentRun,
    ModelVersion,
    Participant,
    Scan,
    SimulationEvent,
    Template,
)
from phishguard.models.enums import (
    AttackCategory,
    Decision,
    EvalSet,
    EventType,
    Experiment,
    Modality,
    ModelKind,
    TemplateSplit,
)

NOW = datetime(2026, 11, 6, tzinfo=UTC)
KEY = {"X-API-Key": "k"}


@pytest.fixture
def api(sqlite_engine, crypto_keys, tmp_path):
    settings = Settings(_env_file=None, environment="test", api_key="k", data_dir=tmp_path)
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: settings

    def session():
        with Session(sqlite_engine) as db:
            yield db

    app.dependency_overrides[get_db] = session
    return TestClient(app)


@pytest.fixture
def filled(db):
    version = ModelVersion(
        name="m", modality=Modality.URL, kind=ModelKind.XGBOOST, artifact_path="x",
        data_hash="a" * 64, feature_set_hash="b" * 64, seed=42, warn_threshold=0.6,
        block_threshold=0.9, cv_metrics={}, trained_at=NOW,
    )  # fmt: skip
    db.add(version)
    db.flush()
    for decision, latency in [(Decision.BLOCK, 10), (Decision.BLOCK, 30), (Decision.ALLOW, 20)]:
        db.add(
            Scan(
                model_version_id=version.id,
                sample_type=Modality.URL,
                input_hash="h" * 64,
                url="https://a-test.com/",
                score=0.5,
                decision=decision,
                latency_ms=latency,
            )  # fmt: skip
        )
    template = Template(
        name="t", attack_category=AttackCategory.CREDENTIAL_HARVEST,
        fictional_org="Northwind", split=TemplateSplit.TRAIN,
    )  # fmt: skip
    db.add(template)
    db.flush()
    campaign = Campaign(name="c", template_id=template.id)
    participant = Participant(
        email="private@test.example", participant_code="P1", consent_form_version="v1",
        consent_given_at=NOW,
    )  # fmt: skip
    db.add_all([campaign, participant])
    db.flush()
    db.add(
        SimulationEvent(
            campaign_id=campaign.id,
            participant_id=participant.id,
            event_type=EventType.CLICKED,
            occurred_at=NOW,
        )  # fmt: skip
    )
    db.add(
        ExperimentRun(
            experiment=Experiment.RQ3,
            round=1,
            seed=42,
            arm="C",
            eval_set=EvalSet.FRESH_FEED,
            k=5,
            metrics={"f1": 0.9},
        )  # fmt: skip
    )
    db.commit()


@pytest.mark.parametrize(
    "path",
    [
        "/admin/status", "/admin/overview", "/admin/scans", "/admin/campaigns", "/admin/results",
        "/admin/experiments",
    ],
)  # fmt: skip
def test_every_admin_endpoint_needs_the_key(api, path):
    assert api.get(path).status_code == 401
    assert api.get(path, headers=KEY).status_code == 200


def test_overview_counts_and_latency(api, filled):
    data = api.get("/admin/overview", headers=KEY).json()
    assert data["total_scans"] == 3
    assert data["by_decision"] == {"block": 2, "warn": 0, "allow": 1}
    assert data["by_modality"] == {"url": 3}
    assert data["median_latency_ms"] == 20 and data["p95_latency_ms"] == 30


def test_empty_database_has_no_invented_numbers(api):
    data = api.get("/admin/overview", headers=KEY).json()
    assert data["total_scans"] == 0 and data["p95_latency_ms"] is None


def test_campaigns_show_totals_and_never_who(api, filled):
    response = api.get("/admin/campaigns", headers=KEY)
    assert response.json()[0]["participants_by_event"] == {"clicked": 1}
    assert "private@" not in response.text and "P1" not in response.text


def test_status_says_simulations_are_not_allowed_without_approval(api):
    data = api.get("/admin/status", headers=KEY).json()
    assert data["simulations_allowed"] is False
    assert data["warn_threshold"] == 0.6 and data["block_threshold"] == 0.9


def test_results_and_experiments(api, filled, tmp_path):
    assert api.get("/admin/results", headers=KEY).json() == {}
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "results.json").write_text('{"url/all": []}')
    assert api.get("/admin/results", headers=KEY).json() == {"url/all": []}
    assert api.get("/admin/experiments", headers=KEY).json()[0]["metrics"] == {"f1": 0.9}


def test_recent_scans_limit_is_checked(api, filled):
    assert len(api.get("/admin/scans?limit=2", headers=KEY).json()) == 2
    assert api.get("/admin/scans?limit=0", headers=KEY).status_code == 422
