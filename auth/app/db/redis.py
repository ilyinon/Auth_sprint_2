from core.config import auth_settings
from core.logger import logger
from redis.asyncio import Redis, from_url

redis: Redis | None = None


async def get_redis() -> Redis:
    return redis


JTI_EXPIRY = 3600

token_blocklist = from_url(auth_settings.redis_dsn)


async def add_jti_to_blocklist(jti: str) -> None:
    logger.info(f"Will add token {jti} to blacklist")
    await token_blocklist.set(
        name=jti, value="", ex=auth_settings.jwt_access_token_expires_in_seconds
    )


async def token_in_blocklist(jti: str) -> bool:
    logger.info(f"check if token {jti} in blacklist")
    jti = await token_blocklist.get(jti)

    return jti is not None
