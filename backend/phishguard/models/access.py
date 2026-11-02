"""Who may use the system: dashboard administrators and API clients (extension, gateway)."""

from datetime import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from phishguard.models.base import (
    Base,
    CreatedAtMixin,
    EncryptedEmailMixin,
    UUIDPrimaryKeyMixin,
    str_enum,
)
from phishguard.models.enums import AdminRole, ClientType


class AdminUser(UUIDPrimaryKeyMixin, EncryptedEmailMixin, CreatedAtMixin, Base):
    __tablename__ = "admin_users"

    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[AdminRole] = mapped_column(str_enum(AdminRole), default=AdminRole.VIEWER)
    is_active: Mapped[bool] = mapped_column(default=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ApiClient(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """Only a hash of the API key is stored; key_prefix lets an admin recognise a key."""

    __tablename__ = "api_clients"

    name: Mapped[str] = mapped_column(String(100))
    client_type: Mapped[ClientType] = mapped_column(str_enum(ClientType))
    key_prefix: Mapped[str] = mapped_column(String(12))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    is_active: Mapped[bool] = mapped_column(default=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
