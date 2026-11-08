"""Application settings, read from environment variables (see .env.example).

Every variable uses the PHISHGUARD_ prefix, e.g. PHISHGUARD_ENVIRONMENT.
A .env file is read from the repo root (../.env) or from backend/ (.env).
"""

from functools import lru_cache
from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PHISHGUARD_",
        env_file=("../.env", ".env"),
        extra="ignore",
    )

    app_name: str = "PhishGuard API"
    environment: str = "development"
    database_url: str | None = None
    redis_url: str | None = None
    # Fernet key that encrypts email addresses at rest.
    encryption_key: SecretStr | None = None
    # Separate secret for the email blind index (HMAC-SHA256), so lookups work on encrypted data.
    email_hash_key: SecretStr | None = None
    # Shared secret sent by the extension, gateway and dashboard in the X-API-Key header.
    # Required outside development; without it the protected endpoints answer 503.
    api_key: SecretStr | None = None
    # Browser origins the dashboard is served from (CORS). JSON list in .env.
    dashboard_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    # Data folder shared with ml/ (models/, ti_responses/). Same variable as the pipeline uses.
    data_dir: Path = Path(__file__).resolve().parents[3] / "data"
    # Threat intelligence (Phase 4)
    virustotal_api_key: SecretStr | None = None
    alienvault_otx_api_key: SecretStr | None = None
    ti_offline: bool = False
    # Live URL scans (decision D11). Stage 1 probabilities inside the band count as unsure, so the
    # page is fetched. Provisional: to be chosen on development OOF predictions once M1 is trained.
    stage1_band_low: float = 0.15
    stage1_band_high: float = 0.85
    # URL scans per API key per minute (0 = no limit); keeps the service from hammering a site.
    scan_rate_limit_per_minute: int = 60
    # Simulations (Phase 6). No campaign can launch until the university's approval reference is
    # set here: consenting participants only, after approval.
    gophish_url: str | None = None
    gophish_api_key: SecretStr | None = None
    # GoPhish's own admin certificate is self-signed with no host name, so it cannot be checked.
    # Give GoPhish our certificate (`make gophish-cert`) and trust exactly that file here.
    gophish_ca_file: Path | None = None
    ethics_approval_ref: str | None = None
    # Shown on the explanation page: where participants ask questions or withdraw.
    simulation_contact_email: str | None = None


@lru_cache
def get_settings() -> Settings:
    return Settings()
