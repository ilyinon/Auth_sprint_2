import os

from async_fastapi_jwt_auth import AuthJWT
from pydantic_settings import BaseSettings, SettingsConfigDict

DOTENV = os.path.abspath(os.path.join(os.path.dirname(__file__), "../..", ".env_test"))


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=DOTENV)

    project_name: str

    redis_host: str
    redis_port: int

    pg_user: str
    pg_password: str
    pg_host: str
    pg_port: int
    pg_db: str

    authjwt_secret_key: str
    authjwt_algorithm: str = "HS256"

    jwt_access_token_expires_in_seconds: int = 1800
    jwt_refresh_token_expires_in_days: int = 30

    app_dsn: str = "http://app:8000"

    @property
    def redis_dsn(self):
        return f"redis://{self.redis_host}:{self.redis_port}"

    @property
    def database_dsn(self):
        return f"postgresql+asyncpg://{self.pg_user}:{self.pg_password}@{self.pg_host}:{self.pg_port}/{self.pg_db}"

    @property
    def database_dsn_not_async(self):
        return f"postgresql://{self.pg_user}:{self.pg_password}@{self.pg_host}:{self.pg_port}/{self.pg_db}"


test_settings = TestSettings()


@AuthJWT.load_config
def get_config():
    return TestSettings()
