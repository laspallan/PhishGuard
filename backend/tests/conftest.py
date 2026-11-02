import pytest
from fastapi.testclient import TestClient

from phishguard.core.config import Settings, get_settings
from phishguard.main import create_app


@pytest.fixture
def test_settings() -> Settings:
    # Built explicitly so tests never depend on a developer's .env file.
    return Settings(_env_file=None, environment="test")


@pytest.fixture
def client(test_settings: Settings) -> TestClient:
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: test_settings
    return TestClient(app)
