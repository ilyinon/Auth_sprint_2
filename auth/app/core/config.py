import os
from logging import config as logging_config

from async_fastapi_jwt_auth import AuthJWT
from core.logger import LOGGING
from pydantic_settings import BaseSettings, SettingsConfigDict

DOTENV = os.path.abspath(os.path.join(os.path.dirname(__file__), "../..", ".env"))

# Применяем настройки логирования
logging_config.dictConfig(LOGGING)


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class AuthSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=DOTENV)

    project_name: str = "auth"

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

    google_client_id: str
    google_client_secret: str
    google_redirect_uri: str = "http://localhost/api/v1/auth/login/google/callback"
    google_auth_uri: str = "https://accounts.google.com/o/oauth2/auth"
    google_scope: str = "email"

    yandex_client_id: str
    yandex_client_secret: str
    yandex_redirect_uri: str = "http://localhost/api/v1/auth/login/yandex/callback"
    yandex_auth_uri: str = "https://oauth.yandex.ru/authorize"
    yandex_token_uri: str = "https://oauth.yandex.ru/token"
    yandex_scope: str = "login:email login:info"

    vk_client_id: str
    vk_client_secret: str
    vk_redirect_uri: str = "http://localhost/api/v1/auth/login/vk/callback"
    vk_auth_uri: str = "https://oauth.vk.com/authorize"
    vk_token_uri: str = "https://oauth.vk.com/access_token"
    vk_user_info_url: str = "https://api.vk.com/method/users.get"
    vk_scope: str = "email"

    pg_echo: bool = False

    log_level: bool = False

    enable_tracer: bool = True
    jaeger_agent_host: str = "jaeger"
    jaeger_agent_port: int = 6831

    @property
    def redis_dsn(self):
        return f"redis://{self.redis_host}:{self.redis_port}"

    @property
    def database_dsn(self):
        return f"postgresql+asyncpg://{self.pg_user}:{self.pg_password}@{self.pg_host}:{self.pg_port}/{self.pg_db}"

    @property
    def database_dsn_not_async(self):
        return f"postgresql://{self.pg_user}:{self.pg_password}@{self.pg_host}:{self.pg_port}/{self.pg_db}"


auth_settings = AuthSettings()


@AuthJWT.load_config
def get_config():
    return AuthSettings()
