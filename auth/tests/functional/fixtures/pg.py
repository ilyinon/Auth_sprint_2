from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Column, Integer, MetaData, String, Table, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.sql import text
from tests.models.base import Base
from tests.models.user import User

from tests.functional.settings import test_settings


@pytest.fixture(scope="session")
@pytest.mark.alembic_auto_upsgrade  # Добавляем маркер Alembic
def engine():
    engine = create_engine(test_settings.database_dsn_not_async)
    Base.metadata.create_all(bind=engine)

    yield engine

    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="session")
def tables(engine):
    alembic_cfg = Config()
    alembic_cfg.set_main_option("script_location", "/opt/alembic")
    alembic_cfg.set_main_option("sqlalchemy.url", str(engine.url))

    command.upgrade(alembic_cfg, "head")
    try:
        command.upgrade(alembic_cfg, "head")
    except Exception as e:
        print(e)
    import traceback

    traceback.print_exc()

    yield
    command.downgrade(alembic_cfg, "base")


@pytest.fixture(scope="session")
def get_db(engine):
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
