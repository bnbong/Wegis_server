# --------------------------------------------------------------------------
# HTTP middleware: global concurrency cap, rate limiting, optional auth (design 03C)
#
# All controls are fail-open and apply only to the /analyze surface. The rate
# limiter self-disables briefly after a Redis failure so a missing/slow Redis
# cannot add latency to every request.
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import asyncio
import logging
import time

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from src.core.config import settings
from src.clients.redis import get_redis
from src.api.deps import get_client_ip
from src.services.auth_tokens import hash_token, is_token_valid

logger = logging.getLogger("main")

_PROTECTED_PREFIX = "/analyze"
_REDIS_OP_TIMEOUT = 0.5

# Global in-flight counter. The event loop is single-threaded, so the
# check-then-increment below runs without an intervening await (atomic).
_inflight = 0

# Rate-limiter circuit breaker: after a Redis failure, skip limiting until this
# monotonic timestamp to avoid paying the timeout on every request.
_limiter_disabled_until = 0.0


def _client_key(request) -> str:
    token = request.headers.get("x-wegis-token")
    # Key on the token only when auth is active (the token is then already
    # validated by the auth middleware) and store its HASH, never the plaintext.
    # In off mode an arbitrary token must NOT let a caller dodge the per-IP limit.
    if token and settings.AUTH_MODE != "off":
        return f"tok:{hash_token(token)}"
    return f"ip:{get_client_ip(request)}"


def _too_many(detail: str, retry_after: str) -> JSONResponse:
    return JSONResponse(
        status_code=429,
        content={"detail": detail},
        headers={"Retry-After": retry_after},
    )


def register_middleware(app: FastAPI) -> None:
    # Registered inner-to-outer; the LAST registered runs first. Order at runtime:
    # auth -> rate-limit -> concurrency -> handler.

    @app.middleware("http")
    async def concurrency_mw(request, call_next):
        global _inflight
        if not request.url.path.startswith(_PROTECTED_PREFIX):
            return await call_next(request)
        if _inflight >= settings.MAX_CONCURRENT_REQUESTS:
            return _too_many("Server busy, retry shortly", "1")
        _inflight += 1
        try:
            return await call_next(request)
        finally:
            _inflight -= 1

    @app.middleware("http")
    async def ratelimit_mw(request, call_next):
        global _limiter_disabled_until
        path = request.url.path
        if not settings.RATE_LIMIT_ENABLED or not path.startswith(_PROTECTED_PREFIX):
            return await call_next(request)
        if time.monotonic() < _limiter_disabled_until:
            return await call_next(request)  # circuit open: fail-open

        limit = (
            settings.RATE_LIMIT_BATCH_PER_MIN
            if path.startswith("/analyze/batch")
            else settings.RATE_LIMIT_CHECK_PER_MIN
        )
        try:
            redis = await asyncio.wait_for(get_redis(), timeout=_REDIS_OP_TIMEOUT)
            window = int(time.time() // 60)
            key = (
                f"{settings.REDIS_NAMESPACE}:ratelimit:"
                f"{path}:{_client_key(request)}:{window}"
            )
            count = await asyncio.wait_for(redis.incr(key), timeout=_REDIS_OP_TIMEOUT)
            if count == 1:
                await asyncio.wait_for(redis.expire(key, 60), timeout=_REDIS_OP_TIMEOUT)
            if count > limit:
                return _too_many("Rate limit exceeded", "60")
        except Exception as exc:
            logger.warning("Rate limiter failed open: %s", exc)
            _limiter_disabled_until = time.monotonic() + 60
        return await call_next(request)

    @app.middleware("http")
    async def auth_mw(request, call_next):
        mode = settings.AUTH_MODE
        if mode == "off" or not request.url.path.startswith(_PROTECTED_PREFIX):
            return await call_next(request)

        token = request.headers.get("x-wegis-token", "")
        if mode == "static":
            ok = token in settings.api_tokens
        elif mode == "registration":
            ok = await is_token_valid(token)
        else:
            ok = True

        if not ok:
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
        return await call_next(request)
