"""Declarative base, shared column types and mixins for every table."""

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import JSON, DateTime, Enum, Float, MetaData, String, Text, Uuid
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, validates
from sqlalchemy.types import TypeDecorator

from phishguard.core import crypto

# Stable constraint names, so Alembic migrations are predictable.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


# JSONB on PostgreSQL, plain JSON elsewhere (SQLite in unit tests).
JSONDoc = JSON().with_variant(JSONB(), "postgresql")
# float[] on PostgreSQL, a JSON list elsewhere.
FloatArray = JSON().with_variant(ARRAY(Float), "postgresql")


def utcnow() -> datetime:
    return datetime.now(UTC)


def str_enum(enum_cls: type[StrEnum]) -> Enum:
    """Store a StrEnum as VARCHAR plus a CHECK constraint (portable and easy to migrate)."""
    return Enum(
        enum_cls,
        name=enum_cls.__name__.lower(),
        native_enum=False,
        create_constraint=True,
        length=32,
        values_callable=lambda members: [m.value for m in members],
    )


class EncryptedString(TypeDecorator[str]):
    """Text column that is encrypted on write and decrypted on read (see core/crypto.py)."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value: str | None, dialect) -> str | None:
        return None if value is None else crypto.encrypt(value)

    def process_result_value(self, value: str | None, dialect) -> str | None:
        return None if value is None else crypto.decrypt(value)


class UUIDPrimaryKeyMixin:
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)


class CreatedAtMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EncryptedEmailMixin:
    """An encrypted email plus its blind index; setting `email` always updates `email_hash`."""

    email: Mapped[str] = mapped_column(EncryptedString)
    email_hash: Mapped[str] = mapped_column(String(64), unique=True)

    @validates("email")
    def _set_email_hash(self, _key: str, value: str) -> str:
        self.email_hash = crypto.email_blind_index(value)
        return crypto.normalise_email(value)
