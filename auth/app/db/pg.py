from core.config import auth_settings
from sqlalchemy.orm import declarative_base

from sqlalchemy.ext.asyncio import create_async_engine  # isort: skip
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker  # isort: skip

Base = declarative_base()

engine = create_async_engine(
    auth_settings.database_dsn, echo=auth_settings.pg_echo, future=True
)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_session() -> AsyncSession:
    async with async_session() as session:
        yield session
