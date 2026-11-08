"""Hosts the extension blocks before they load: host names only, and never a shared domain."""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from phishguard.core.config import Settings, get_settings
from phishguard.db.session import get_db
from phishguard.main import create_app
from phishguard.models import ModelVersion, Scan
from phishguard.models.enums import Decision, Modality, ModelKind
from phishguard.services.blocklist import blocked_hosts, host_of

NOW = datetime(2026, 11, 8, 12, tzinfo=UTC)
KEY = {"X-API-Key": "k"}


def test_hosts_are_shared_only_without_a_safe_page_on_the_same_domain():
    rows = [
        ("https://login.evil-bank.test/x?email=victim@mail.test", Decision.BLOCK, NOW),
        # a shared host: example.org is a real (reserved) registered domain under the PSL
        ("https://phish.example.org/a", Decision.BLOCK, NOW),
        ("https://shop.example.org/", Decision.ALLOW, NOW - timedelta(days=20)),
        ("https://old.test/", Decision.BLOCK, NOW - timedelta(days=8)),  # older than 7 days
        ("http://192.0.2.7/login", Decision.BLOCK, NOW - timedelta(hours=1)),
        ("https://unsure.test/", Decision.WARN, NOW),
        ("ftp://files.test/", Decision.BLOCK, NOW),
        (None, Decision.BLOCK, NOW),
    ]
    assert blocked_hosts(rows, NOW) == ["login.evil-bank.test", "192.0.2.7"]


def test_naive_times_count_as_utc_and_newest_come_first():
    rows = [
        ("https://a.test/", Decision.BLOCK, datetime(2026, 11, 7)),
        ("https://b.test/", Decision.BLOCK, datetime(2026, 11, 8)),
    ]
    assert blocked_hosts(rows, NOW) == ["b.test", "a.test"]
    assert host_of("https://EXAMPLE.test./p") == "example.test"
    assert host_of("not a url") is None


@pytest.fixture
def api(sqlite_engine, tmp_path):
    settings = Settings(_env_file=None, environment="test", api_key="k", data_dir=tmp_path)
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: settings

    def session():
        with Session(sqlite_engine) as db:
            yield db

    app.dependency_overrides[get_db] = session
    with Session(sqlite_engine) as db:
        version = ModelVersion(
            name="m", modality=Modality.URL, kind=ModelKind.XGBOOST, artifact_path="x",
            data_hash="a" * 64, feature_set_hash="b" * 64, seed=42, cv_metrics={},
        )  # fmt: skip
        db.add(version)
        db.flush()
        db.add(
            Scan(
                model_version_id=version.id,
                sample_type=Modality.URL,
                input_hash="h" * 64,
                url="https://login.evil-bank.test/x",
                score=0.99,
                decision=Decision.BLOCK,
            )  # fmt: skip
        )
        db.commit()
    return TestClient(app)


def test_the_endpoint_needs_the_key_and_gives_hosts_only(api):
    assert api.get("/extension/blocked-hosts").status_code == 401
    answer = api.get("/extension/blocked-hosts", headers=KEY)
    assert answer.status_code == 200
    assert answer.json()["hosts"] == ["login.evil-bank.test"]
    assert "/x" not in answer.text
