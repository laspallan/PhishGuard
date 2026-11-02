from phishguard import __version__


def test_health_endpoint_returns_200_and_schema(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "app_name": "PhishGuard API",
        "version": __version__,
        "environment": "test",
    }
