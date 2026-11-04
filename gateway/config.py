"""IMAP email gateway configuration."""
from pydantic_settings import BaseSettings


class GatewaySettings(BaseSettings):
    imap_host: str = "localhost"
    imap_port: int = 993
    imap_use_ssl: bool = True
    imap_user: str = ""
    imap_password: str = ""
    api_base_url: str = "http://localhost:8000"
    api_key: str = ""
    quarantine_folder: str = "PhishGuard/Quarantine"
    check_interval_seconds: int = 60

    class Config:
        env_prefix = "PHISHGUARD_GATEWAY_"
        env_file = ".env"
