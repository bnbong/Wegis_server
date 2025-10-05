# --------------------------------------------------------------------------
# Configuration module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import os
import secrets
import warnings

from typing import Any, Annotated, Literal
from typing_extensions import Self

from pydantic import (
    AnyUrl,
    BeforeValidator,
    computed_field,
    model_validator,
    PostgresDsn,
)
from pydantic_core import MultiHostUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


def parse_cors(v: Any) -> list[str] | str:
    if isinstance(v, str) and not v.startswith("["):
        return [i.strip() for i in v.split(",")]
    elif isinstance(v, list | str):
        return v
    raise ValueError(v)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_ignore_empty=True,
        extra="ignore",
    )
    SECRET_KEY: str = secrets.token_urlsafe(32)
    ENVIRONMENT: Literal["development", "production", "test"] = "development"

    CLIENT_ORIGIN: str = ""
    BACKEND_CORS_ORIGINS: Annotated[
        list[AnyUrl] | str, BeforeValidator(parse_cors)
    ] = []

    @computed_field  # type: ignore[prop-decorator]
    @property
    def all_cors_origins(self) -> list[str]:
        return [str(origin).rstrip("/") for origin in self.BACKEND_CORS_ORIGINS] + [
            self.CLIENT_ORIGIN
        ]

    PROJECT_NAME: str = "Wegis Server"
    MODEL_NAME: str = "best_acc_model.pt"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def MODEL_PATH(self) -> str:
        current_dir = os.path.dirname(os.path.abspath(__file__))

        search_paths = [
            os.path.join(current_dir, "..", "..", "models", self.MODEL_NAME),
            os.path.join(current_dir, "..", self.MODEL_NAME),
            os.path.join(current_dir, "..", "..", self.MODEL_NAME),
        ]

        for path in search_paths:
            normalized_path = os.path.normpath(path)
            if os.path.exists(normalized_path) and os.path.isfile(normalized_path):
                return normalized_path

        searched_locations = "\n".join(
            [f"  - {os.path.normpath(p)}" for p in search_paths]
        )
        raise FileNotFoundError(
            f"AI model checkpoint file '{self.MODEL_NAME}' not found.\n"
            f"Searched locations:\n{searched_locations}\n"
            f"Please ensure the model file exists in the 'models/' directory."
        )

    HTML_LOAD_TIMEOUT: int = int(os.getenv("HTML_LOAD_TIMEOUT", "20"))
    HTML_LOAD_RETRIES: int = int(os.getenv("HTML_LOAD_RETRIES", "2"))

    CHROME_BIN: str = "/usr/bin/chromium"
    CHROMEDRIVER_PATH: str = "/usr/bin/chromedriver"

    DOMAIN_ENABLE_PATTERNS: bool = True

    # Redis
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_CACHE_TTL: int = int(os.getenv("REDIS_CACHE_TTL", "43200"))
    REDIS_NAMESPACE: str = "wegis"
    REDIS_MAX_CONNECTIONS: int = 10
    REDIS_RETRY_ON_TIMEOUT: bool = True
    REDIS_SOCKET_TIMEOUT: int = 5

    # PostgreSQL
    POSTGRES_USER: str = "admin"
    POSTGRES_PASSWORD: str = "password"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "phishing_data"
    POSTGRES_POOL_SIZE: int = 5
    POSTGRES_MAX_OVERFLOW: int = 10

    @computed_field  # type: ignore[prop-decorator]
    @property
    def POSTGRES_URI(self) -> PostgresDsn:
        return MultiHostUrl.build(  # type: ignore
            scheme="postgresql+psycopg2",
            username=self.POSTGRES_USER,
            password=self.POSTGRES_PASSWORD,
            host=self.POSTGRES_HOST,
            port=self.POSTGRES_PORT,
            path=self.POSTGRES_DB,
        )

    # MongoDB
    MONGODB_USER: str = "admin"
    MONGODB_PASSWORD: str = "password"
    MONGODB_HOST: str = "localhost"
    MONGODB_PORT: int = 27017
    MONGODB_NAME: str = "phishing_feedback"
    MONGODB_MAX_POOL_SIZE: int = 10
    MONGODB_MIN_POOL_SIZE: int = 1
    MONGODB_SERVER_SELECTION_TIMEOUT: int = 5000

    @computed_field  # type: ignore[prop-decorator]
    @property
    def MONGODB_URI(self) -> str:
        return f"mongodb://{self.MONGODB_USER}:{self.MONGODB_PASSWORD}@{self.MONGODB_HOST}:{self.MONGODB_PORT}/{self.MONGODB_NAME}?authSource=admin&maxPoolSize={self.MONGODB_MAX_POOL_SIZE}&minPoolSize={self.MONGODB_MIN_POOL_SIZE}&serverSelectionTimeoutMS={self.MONGODB_SERVER_SELECTION_TIMEOUT}"

    MAX_CONCURRENT_REQUESTS: int = 5
    MODEL_CACHE_SIZE: int = 1

    CHROME_PROCESS_TIMEOUT: int = 30
    CHROME_MAX_INSTANCES: int = 2

    def _check_default_secret(self, var_name: str, value: str | None) -> None:
        if value == "changethis":
            message = (
                f'The value of {var_name} is "changethis", '
                "for security, please change it, at least for deployments."
            )
            if self.ENVIRONMENT == "development":
                warnings.warn(message, stacklevel=1)
            else:
                raise ValueError(message)

    @model_validator(mode="after")
    def _enforce_non_default_secrets(self) -> Self:
        self._check_default_secret("SECRET_KEY", self.SECRET_KEY)
        return self


settings = Settings()
