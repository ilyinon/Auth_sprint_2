import psycopg2
from functional.settings import test_settings
from utils.backoff import backoff
from utils.logger import logger


@backoff()
def wait_for_pg():
    pg = psycopg2.connect(
        dbname=test_settings.pg_db,
        user=test_settings.pg_user,
        host=test_settings.pg_host,
        password=test_settings.pg_password,
        connect_timeout=1,
    )
    with pg as conn:
        psycopg2.connect

        return True


if __name__ == "__main__":

    wait_for_pg()
