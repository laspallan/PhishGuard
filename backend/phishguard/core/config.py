"""Application settings, read from environment variables (see .env.example).

Every variable uses the PHISHGUARD_ prefix, e.g. PHISHGUARD_ENVIRONMENT.
A .env file is read from the repo root (../.env) or from backend/ (.env).
"""

from functools import lru_cache

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


@lru_cache
def get_settings() -> Settings:
    return Settings()
