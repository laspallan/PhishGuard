"""Alembic environment: runs migrations against PHISHGUARD_DATABASE_URL.

A caller (e.g. a test) can override the URL with config.set_main_option("sqlalchemy.url", ...).
"""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine

from phishguard.core.config import get_settings
from phishguard.models import Base
from phishguard.models.base import EncryptedString

config = context.config
if config.config_file_name is not None and config.attributes.get("configure_logger", True):
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def database_url() -> str:
    url = config.get_main_option("sqlalchemy.url") or get_settings().database_url
    if not url:
        raise RuntimeError("PHISHGUARD_DATABASE_URL is not set")
    return url


def render_item(type_: str, obj, autogen_context):
    # Encrypted columns are plain TEXT in the database; encryption happens in Python.
    if type_ == "type" and isinstance(obj, EncryptedString):
        return "sa.Text()"
    return False


def run_migrations_offline() -> None:
    context.configure(
        url=database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        render_item=render_item,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(database_url())
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_item=render_item,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
