"""Saving a scan on real PostgreSQL (`make test-db`); the unit tests use SQLite only.

A throwaway database is created for the test and dropped afterwards, so dev data is safe.
"""

import math

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker

from phishguard.core.config import Settings
from phishguard.models import Base, ModelVersion, Scan, ScanFeatures
from phishguard.models.enums import Modality
from phishguard.services.features.extractor import feature_code_hash
from phishguard.services.inference.persist import record_scan

pytestmark = pytest.mark.postgres
TEST_DB = "phishguard_persistence_test"
ENTRY = {
    "version": "url-live-xgboost-abc",
    "path": "url/live/xgboost",
    "model": "xgboost",
    "modality": "url",
    "feature_code_hash": feature_code_hash(),
    "split_sha256": {"dataset.parquet": "a" * 64},
    "seed": 42,
    "oof_log_loss": 0.1,
    "registered_at": "2026-11-06T00:00:00+00:00",
}


@pytest.fixture
def session_factory():
    base_url = Settings().database_url
    if not base_url:
        pytest.fail("PHISHGUARD_DATABASE_URL is not set (copy .env.example to .env)")
    url = make_url(base_url)
    admin = create_engine(url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{TEST_DB}" WITH (FORCE)'))
        conn.execute(text(f'CREATE DATABASE "{TEST_DB}"'))
    engine = create_engine(url.set(database=TEST_DB))
    Base.metadata.create_all(engine)
    yield sessionmaker(bind=engine)
    engine.dispose()
    with admin.connect() as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{TEST_DB}" WITH (FORCE)'))
    admin.dispose()


def test_scans_are_saved_with_one_model_version_and_nan_features(session_factory):
    """Missing features are NaN (P2-a) and must survive the real database column unchanged."""
    values = [float("nan"), 1.5] + [0.0] * 138
    for i in range(2):
        record_scan(
            session_factory,
            entry=ENTRY,
            modality=Modality.URL,
            input_text=f"https://a-test.com/{i}",
            url=f"https://a-test.com/{i}",
            sender_domain=None,
            score=0.7,
            decision="warn",
            latency_ms=12.6,
            values=values,
            warn=0.6,
            block=0.9,
        )
    with session_factory() as session:
        assert len(session.scalars(select(Scan)).all()) == 2
        assert len(session.scalars(select(ModelVersion)).all()) == 1
        saved = session.scalars(select(ScanFeatures)).first().values
        assert math.isnan(saved[0]) and saved[1] == 1.5 and len(saved) == 140
