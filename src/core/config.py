# --------------------------------------------------------------------------
# Configuration module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
from __future__ import annotations

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

    HTML_LOAD_TIMEOUT: int = 20
    HTML_LOAD_RETRIES: int = 2

    CHROMEDRIVER_PATH: str = "/usr/bin/chromedriver"

    DOMAIN_ENABLE_PATTERNS: bool = True

    # Redis
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_CACHE_TTL_PHISHING: int = 86400
    REDIS_CACHE_TTL_BENIGN: int = 1800
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

    MAX_BROWSER_CONCURRENCY: int = 2
    MAX_INFER_CONCURRENCY: int = 4

    BENCHMARK_OUTPUT_DIR: str = "./log/benchmarks"
    ENABLE_PERF_RECORDS: bool | None = None

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
        if self.ENABLE_PERF_RECORDS is None:
            self.ENABLE_PERF_RECORDS = self.ENVIRONMENT != "production"
        self._check_default_secret("SECRET_KEY", self.SECRET_KEY)
        return self


settings = Settings()
