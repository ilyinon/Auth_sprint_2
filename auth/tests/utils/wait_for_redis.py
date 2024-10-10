from functional.settings import test_settings
from redis.client import Redis
from utils.backoff import backoff
from utils.logger import logger


@backoff()
def wait_for_redis():
    redis_client = Redis(
        host=test_settings.redis_host, port=test_settings.redis_port, db=0
    )
    ping = redis_client.ping()

    if ping:
        return ping
    logger.info(f"redis ping: {ping}")


if __name__ == "__main__":

    wait_for_redis()
