"""API key protection, and the 503 answer while no model is trained."""

from fastapi.testclient import TestClient
from pydantic import SecretStr

from phishguard.core.config import Settings, get_settings
from phishguard.main import create_app


def _client(settings: Settings) -> TestClient:
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: settings
    return TestClient(app)


def test_protected_endpoints_need_the_key():
    client = _client(Settings(_env_file=None, environment="test", api_key=SecretStr("s3cret")))
    assert client.get("/admin/status").status_code == 401
    assert client.get("/admin/status", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/admin/status", headers={"X-API-Key": "s3cret"}).status_code == 200
    assert client.get("/health").status_code == 200  # health stays public


def test_missing_key_outside_development_fails_closed():
    client = _client(Settings(_env_file=None, environment="production", api_key=None))
    assert client.get("/models").status_code == 503


def test_scan_answers_503_until_a_model_is_trained():
    client = _client(Settings(_env_file=None, environment="development"))
    response = client.post("/scan/url", json={"url": "http://paypal-login-verify.xyz/"})
    assert response.status_code == 503
