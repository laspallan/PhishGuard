"""The dashboard runs on another origin and sends X-API-Key, so browsers ask first (preflight)."""

from fastapi.testclient import TestClient

from phishguard.main import create_app


def _preflight(origin: str):
    return TestClient(create_app()).options(
        "/admin/status",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "x-api-key",
        },
    )


def test_the_dashboard_origin_may_send_the_key():
    response = _preflight("http://localhost:5173")
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "x-api-key" in response.headers["access-control-allow-headers"].lower()
    assert "access-control-allow-credentials" not in response.headers


def test_any_other_origin_is_refused():
    response = _preflight("https://evil.example")
    assert "access-control-allow-origin" not in response.headers
