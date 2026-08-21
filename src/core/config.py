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
        # ENV_FILE lets tests load env.test instead of the production .env, so the
        # suite is hermetic (no production keys/hosts leak in). Defaults to .env.
        env_file=os.getenv("ENV_FILE", ".env"),
        env_ignore_empty=True,
        extra="ignore",
    )
    SECRET_KEY: str = secrets.token_urlsafe(32)
    ENVIRONMENT: Literal["development", "production", "test"] = "development"

    CLIENT_ORIGIN: str = ""
    BACKEND_CORS_ORIGINS: Annotated[
        list[AnyUrl] | str, BeforeValidator(parse_cors)
    ] = []
    # Matched (fullmatch) against the request Origin in addition to the explicit
    # list above. The extension calls from chrome-extension://<id>, and the id
    # differs per build/store listing, so it cannot be enumerated. Set to "" to
    # allow only the explicit origins.
    CORS_ORIGIN_REGEX: str = "^chrome-extension://.*$"

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
    # Max bytes read from an HTTP response body when fetching HTML. Non-HTML
    # responses are not read at all (connection closed after headers).
    HTTP_FETCH_MAX_BYTES: int = 3_000_000

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

    # URL reputation (threat intelligence) stage.
    # Each provider is auto-disabled when its API key is empty.
    REPUTATION_ENABLED: bool = True
    REPUTATION_TIMEOUT: float = 4.0
    REPUTATION_MAX_CONCURRENCY: int = 8
    REPUTATION_CACHE_TTL_MALICIOUS: int = 21600  # 6h
    REPUTATION_CACHE_TTL_CLEAN: int = 1800  # 30m
    GOOGLE_SAFE_BROWSING_API_KEY: str = ""
    URLHAUS_AUTH_KEY: str = ""

    # External malware scanner (VirusTotal) — only queried for high-risk download
    # URLs (Phase 2). Lookup-first to conserve quota; set SUBMIT_UNKNOWN to seed a
    # scan when VT has no existing report (costs extra quota).
    VIRUSTOTAL_API_KEY: str = ""
    VIRUSTOTAL_MALICIOUS_THRESHOLD: int = 2
    VIRUSTOTAL_SUBMIT_UNKNOWN: bool = False

    # --- Block-signal policy (design 02) ---
    # Model confidence (= P(phishing)) thresholds. Calibrate with data.
    MODEL_BLOCK_THRESHOLD: float = 0.90
    MODEL_WARN_THRESHOLD: float = 0.70

    # Persist benign model verdicts to PostgreSQL. Off by default: every analyzed
    # URL is benign-by-majority, so persisting them all causes write amplification
    # and unbounded table growth. Benign results are still cached in Redis.
    PERSIST_BENIGN: bool = False

    # --- Analysis trigger policy (design 01) ---
    # Links (page-discovered URLs) are reputation-only + cache-first by default.
    # When enabled, a cache-miss link schedules a bounded background model run.
    LINK_BACKGROUND_MODEL: bool = False
    LINK_BG_CONCURRENCY: int = 4
    LINK_BG_MAX_INFLIGHT: int = 256

    # --- Operational safety (design 03) ---
    # Batch guards
    MAX_BATCH_URLS: int = 50
    BATCH_CONCURRENCY: int = 8
    BATCH_PER_URL_TIMEOUT: float = 6.0
    # Global in-flight request cap (429 beyond this)
    MAX_CONCURRENT_REQUESTS: int = 32
    # SSRF guard for outbound fetches
    SSRF_GUARD_ENABLED: bool = True
    FETCH_MAX_REDIRECTS: int = 3
    # Browser (Selenium) fallback. The HTTP path pins each hop to the address
    # the SSRF guard inspected, but Chrome resolves DNS itself, so a rebinding
    # window remains on this path only. Turn it off where no egress firewall
    # backstops that residual risk.
    BROWSER_FETCH_ENABLED: bool = True
    # Rate limiting (Redis-backed, fail-open)
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_CHECK_PER_MIN: int = 120
    RATE_LIMIT_BATCH_PER_MIN: int = 12
    # Feedback is user-initiated (one report per click), so it is low-volume.
    RATE_LIMIT_FEEDBACK_PER_MIN: int = 30
    # Trusted-proxy header carrying the real client IP (e.g. "cf-connecting-ip"
    # behind Cloudflare). Empty = use the socket peer (request.client.host).
    # ONLY set this when the origin accepts traffic only from the trusted proxy;
    # otherwise the header is client-spoofable.
    CLIENT_IP_HEADER: str = ""

    # --- Auth (design 05) ---
    # off         : no auth (default; dev / unpacked testing)
    # static      : X-Wegis-Token must be in WEGIS_API_TOKENS (closed beta)
    # registration: X-Wegis-Token must be a live per-install token issued by
    #               POST /auth/register (public launch)
    AUTH_MODE: Literal["off", "static", "registration"] = "off"
    WEGIS_API_TOKENS: str = ""  # static mode only
    # registration mode:
    REGISTRATION_BOOTSTRAP_SECRET: str = ""  # gates POST /auth/register
    REGISTRATION_RATE_LIMIT_PER_HOUR: int = 5  # per client IP
    AUTH_TOKEN_CACHE_TTL: int = 300  # seconds; Redis cache for token validation
    # Failed auth attempts allowed per client IP per minute. Rejected requests
    # never reach the rate limiter (auth runs first), so this bounds token
    # brute-force and the token lookups it would otherwise trigger.
    AUTH_FAIL_LIMIT_PER_MIN: int = 30

    @computed_field  # type: ignore[prop-decorator]
    @property
    def api_tokens(self) -> set[str]:
        return {t.strip() for t in self.WEGIS_API_TOKENS.split(",") if t.strip()}

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

    def _promote_auth_mode_for_static_tokens(self) -> None:
        """Turn auth on when only WEGIS_API_TOKENS was configured.

        The client integration contract documents setting WEGIS_API_TOKENS as the
        way to require a token, so leaving AUTH_MODE at its "off" default would
        serve /analyze/* unauthenticated against the operator's intent.
        """
        # api_tokens (not the raw string) so a blank/whitespace value cannot
        # promote the server into static mode with an empty allowlist.
        if self.api_tokens and self.AUTH_MODE == "off":
            self.AUTH_MODE = "static"
            warnings.warn(
                'WEGIS_API_TOKENS is set while AUTH_MODE is "off"; promoting '
                'AUTH_MODE to "static". Set AUTH_MODE explicitly to silence this.',
                stacklevel=1,
            )

    @model_validator(mode="after")
    def _enforce_non_default_secrets(self) -> Self:
        if self.ENABLE_PERF_RECORDS is None:
            self.ENABLE_PERF_RECORDS = self.ENVIRONMENT != "production"
        self._check_default_secret("SECRET_KEY", self.SECRET_KEY)
        self._promote_auth_mode_for_static_tokens()
        return self


settings = Settings()
