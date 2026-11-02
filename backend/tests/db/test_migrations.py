"""Migrations against real PostgreSQL. Run with `make test-db` (needs docker compose postgres).

A throwaway database is created for the test and dropped afterwards, so dev data is safe.
"""

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url

from phishguard.core.config import Settings
from phishguard.models import Base

pytestmark = pytest.mark.postgres
TEST_DB = "phishguard_migration_test"


@pytest.fixture(scope="module")
def pg_url() -> str:
    base_url = Settings().database_url
    if not base_url:
        pytest.fail("PHISHGUARD_DATABASE_URL is not set (copy .env.example to .env)")
    url = make_url(base_url)
    admin = create_engine(url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{TEST_DB}" WITH (FORCE)'))
        conn.execute(text(f'CREATE DATABASE "{TEST_DB}"'))
    test_url = url.set(database=TEST_DB).render_as_string(hide_password=False)
    yield test_url
    with admin.connect() as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{TEST_DB}" WITH (FORCE)'))
    admin.dispose()


def alembic_config(url: str) -> Config:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", url)
    config.attributes["configure_logger"] = False
    return config


def test_upgrade_matches_models_and_downgrade_removes_everything(pg_url):
    config = alembic_config(pg_url)
    engine = create_engine(pg_url)

    command.upgrade(config, "head")
    with engine.connect() as conn:
        assert set(inspect(conn).get_table_names()) >= set(Base.metadata.tables)
        diff = compare_metadata(
            MigrationContext.configure(conn, opts={"compare_type": True}), Base.metadata
        )
    assert diff == [], f"models and migrations differ: {diff}"

    command.downgrade(config, "base")
    with engine.connect() as conn:
        assert set(inspect(conn).get_table_names()) == {"alembic_version"}
    engine.dispose()
