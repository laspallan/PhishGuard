"""Database engine and sessions. Views get a session through the get_db dependency."""

from collections.abc import Iterator
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from phishguard.core.config import get_settings


class DatabaseNotConfiguredError(RuntimeError):
    """Raised when PHISHGUARD_DATABASE_URL is missing."""


@lru_cache
def get_engine() -> Engine:
    url = get_settings().database_url
    if not url:
        raise DatabaseNotConfiguredError("PHISHGUARD_DATABASE_URL is not set")
    return create_engine(url, pool_pre_ping=True)


@lru_cache
def get_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False)


def get_db() -> Iterator[Session]:
    with get_sessionmaker()() as session:
        yield session
