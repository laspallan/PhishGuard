import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from phishguard.core import crypto
from phishguard.core.config import Settings, get_settings
from phishguard.main import create_app
from phishguard.models import Base


@pytest.fixture
def test_settings() -> Settings:
    # Built explicitly so tests never depend on a developer's .env file.
    return Settings(_env_file=None, environment="test")


@pytest.fixture
def client(test_settings: Settings) -> TestClient:
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: test_settings
    return TestClient(app)


@pytest.fixture
def crypto_keys(monkeypatch: pytest.MonkeyPatch) -> Settings:
    """Fresh, throwaway encryption keys for one test."""
    settings = Settings(
        _env_file=None,
        encryption_key=SecretStr(Fernet.generate_key().decode()),
        email_hash_key=SecretStr("test-hash-key"),
    )
    monkeypatch.setattr(crypto, "get_settings", lambda: settings)
    crypto.clear_key_cache()
    yield settings
    crypto.clear_key_cache()


@pytest.fixture
def sqlite_engine() -> Engine:
    """In-memory SQLite with all tables and foreign keys enforced."""
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection, _record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def db(sqlite_engine: Engine, crypto_keys: Settings) -> Session:
    with Session(sqlite_engine) as session:
        yield session
