"""IMAP email gateway configuration (environment variables PHISHGUARD_GATEWAY_*)."""

from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class GatewaySettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PHISHGUARD_GATEWAY_", env_file=".env")

    imap_host: str = "localhost"
    imap_port: int = 993
    imap_use_ssl: bool = True
    imap_user: str = ""
    imap_password: SecretStr = SecretStr("")
    mailbox: str = "INBOX"
    api_base_url: str = "http://127.0.0.1:8000"
    api_key: SecretStr = SecretStr("")
    quarantine_folder: str = "PhishGuard/Quarantine"
    check_interval_seconds: int = 60
    # Remembers the last scanned UID per mailbox, so every email is scanned exactly once.
    state_file: Path = Path("gateway_state.json")
