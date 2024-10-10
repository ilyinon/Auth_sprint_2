import pytest
from redis.asyncio import Redis

from tests.functional.settings import test_settings


@pytest.fixture(scope="session")
async def redis_client():
    client = Redis.from_url(test_settings.redis_dsn)
    await client.flushdb()
    yield client
    await client.close()
