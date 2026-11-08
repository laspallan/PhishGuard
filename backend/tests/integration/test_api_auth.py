"""API key protection, and the 503 answer while no model is trained."""

from fastapi.testclient import TestClient
from pydantic import SecretStr

from phishguard.core.config import Settings, get_settings
from phishguard.main import create_app
from phishguard.services.inference.model_loader import ModelLoader
from phishguard.services.inference.scan_store import ScanStore
from phishguard.services.inference.service import InferenceService, RateLimitedError
from phishguard.views import scan as scan_view


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


def _scanning_with(monkeypatch, tmp_path, **service):
    """The scan view with a real service reading an empty model folder (not the real data/)."""
    inference = InferenceService(ModelLoader(tmp_path), store=ScanStore(), recorder=None, **service)
    monkeypatch.setattr(scan_view.controller, "inference", inference)
    return _client(Settings(_env_file=None, environment="development"))


def test_scan_answers_503_until_a_model_is_trained(monkeypatch, tmp_path):
    client = _scanning_with(monkeypatch, tmp_path)
    response = client.post("/scan/url", json={"url": "http://paypal-login-verify.xyz/"})
    assert response.status_code == 503
    assert client.post("/scan/email", json={"raw_email": "Subject: x\n\ny"}).status_code == 503


def test_scan_url_refuses_what_is_not_a_web_address(monkeypatch, tmp_path):
    client = _scanning_with(monkeypatch, tmp_path)
    for bad in ("file:///etc/passwd", "ftp://a-test.com/", "not a url", "http://[broken"):
        assert client.post("/scan/url", json={"url": bad}).status_code == 422


def test_rate_limit_answers_429(monkeypatch):
    class Limited:
        async def scan_url(self, url, client_id):
            raise RateLimitedError("too many URL scans this minute")

    monkeypatch.setattr(scan_view.controller, "inference", Limited())
    client = _client(Settings(_env_file=None, environment="development"))
    assert client.post("/scan/url", json={"url": "https://a-test.com/"}).status_code == 429


def test_verdict_response_shape(monkeypatch):
    class Fine:
        async def scan_url(self, url, client_id):
            return {
                "verdict": "warn", "score": 0.7, "ti_score": None, "model_version": "m1",
                "stage": 1, "evidence": "partial", "latency_ms": 12.0,
            }  # fmt: skip

    monkeypatch.setattr(scan_view.controller, "inference", Fine())
    client = _client(Settings(_env_file=None, environment="development"))
    body = client.post("/scan/url", json={"url": "https://a-test.com/"}).json()
    assert body["verdict"] == "warn" and body["ti_score"] is None
    assert body["evidence"] == "partial" and body["stage"] == 1 and body["cached"] is False
