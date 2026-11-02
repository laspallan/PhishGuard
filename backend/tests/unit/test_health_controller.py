from phishguard import __version__
from phishguard.controllers.health_controller import get_health


def test_get_health_reports_ok_and_settings(test_settings):
    result = get_health(test_settings)

    assert result.status == "ok"
    assert result.app_name == "PhishGuard API"
    assert result.version == __version__
    assert result.environment == "test"
