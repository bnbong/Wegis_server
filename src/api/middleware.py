# --------------------------------------------------------------------------
# HTTP middleware: global concurrency cap, rate limiting, optional auth (design 03C)
#
# All controls are fail-open and apply only to the /analyze and /feedback
# surfaces. The rate limiter self-disables briefly after a Redis failure so a
# missing/slow Redis cannot add latency to every request. Rejected requests
# never reach the rate limiter, so auth carries its own per-IP failure limiter.
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import asyncio
import hmac
import logging
import time

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from src.core.config import settings
from src.clients.redis import get_redis
from src.api.deps import get_client_ip
from src.services.auth_tokens import hash_token, is_token_valid

logger = logging.getLogger("main")

# str.startswith() takes a tuple, so every guard below covers both surfaces.
_PROTECTED_PREFIXES = ("/analyze", "/feedback")
_REDIS_OP_TIMEOUT = 0.5

# Global in-flight counter. The event loop is single-threaded, so the
# check-then-increment below runs without an intervening await (atomic).
_inflight = 0

# Rate-limiter circuit breaker: after a Redis failure, skip limiting until this
# monotonic timestamp to avoid paying the timeout on every request.
_limiter_disabled_until = 0.0

# The auth-failure limiter keeps its OWN breaker: it is an abuse control on
# unauthenticated traffic, so a blip on its keys must not also switch off the
# per-client rate limit (and vice versa). Cost of not sharing is at most one
# extra Redis timeout per minute.
_authfail_disabled_until = 0.0


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


def _authfail_key(client_ip: str) -> str:
    return f"{settings.REDIS_NAMESPACE}:authfail:{client_ip}:{int(time.time() // 60)}"


async def _charge_auth_attempt(client_ip: str) -> bool:
    """Charge one attempt to this IP's budget; True when it blew the limit.

    The charge is taken BEFORE the token is validated, and the verdict is INCR's
    own return value, so a burst of concurrent attempts cannot all observe the
    same low count and slip through together — at most AUTH_FAIL_LIMIT_PER_MIN
    of them reach is_token_valid() and its Redis/PostgreSQL lookups. Successful
    requests hand the charge back via _refund_auth_attempt().

    Trade-off: an IP with more than the limit in flight AT ONCE can see a 429 on
    the margin even with a valid token, because every attempt is charged until it
    is refunded. Fail-open like the rate limiter.
    """
    global _authfail_disabled_until
    if time.monotonic() < _authfail_disabled_until:
        return False  # circuit open: fail-open
    try:
        redis = await asyncio.wait_for(get_redis(), timeout=_REDIS_OP_TIMEOUT)
        key = _authfail_key(client_ip)
        count = await asyncio.wait_for(redis.incr(key), timeout=_REDIS_OP_TIMEOUT)
        if count == 1:
            await asyncio.wait_for(redis.expire(key, 60), timeout=_REDIS_OP_TIMEOUT)
        return count > settings.AUTH_FAIL_LIMIT_PER_MIN
    except Exception as exc:
        logger.warning("Auth-failure limiter failed open: %s", exc)
        _authfail_disabled_until = time.monotonic() + 60
        return False


async def _refund_auth_attempt(client_ip: str) -> None:
    """Return the charge taken by _charge_auth_attempt() after a valid token.

    Only failures should consume the budget. A window rollover between the two
    calls makes this DECR land on the NEXT window's key: harmless, but Redis
    creates a missing key WITHOUT a TTL, so give any non-positive counter an
    expiry rather than leaving it behind forever. A counter sitting at 0/-1 just
    grants that window one extra attempt.
    """
    global _authfail_disabled_until
    if time.monotonic() < _authfail_disabled_until:
        return
    try:
        redis = await asyncio.wait_for(get_redis(), timeout=_REDIS_OP_TIMEOUT)
        key = _authfail_key(client_ip)
        count = await asyncio.wait_for(redis.decr(key), timeout=_REDIS_OP_TIMEOUT)
        if count <= 0:
            await asyncio.wait_for(redis.expire(key, 60), timeout=_REDIS_OP_TIMEOUT)
    except Exception as exc:
        logger.warning("Auth-failure limiter failed open: %s", exc)
        _authfail_disabled_until = time.monotonic() + 60


def register_middleware(app: FastAPI) -> None:
    # Registered inner-to-outer; the LAST registered runs first. Order at runtime:
    # auth -> rate-limit -> concurrency -> handler.

    @app.middleware("http")
    async def concurrency_mw(request, call_next):
        global _inflight
        if not request.url.path.startswith(_PROTECTED_PREFIXES):
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
        if not settings.RATE_LIMIT_ENABLED or not path.startswith(_PROTECTED_PREFIXES):
            return await call_next(request)
        if time.monotonic() < _limiter_disabled_until:
            return await call_next(request)  # circuit open: fail-open

        if path.startswith("/analyze/batch"):
            limit = settings.RATE_LIMIT_BATCH_PER_MIN
        elif path.startswith("/feedback"):
            # User-initiated (one report per click), so a lenient cap is enough.
            limit = settings.RATE_LIMIT_FEEDBACK_PER_MIN
        else:
            limit = settings.RATE_LIMIT_CHECK_PER_MIN
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
        if mode == "off" or not request.url.path.startswith(_PROTECTED_PREFIXES):
            return await call_next(request)

        # Auth runs before the rate limiter, so a rejected request never reaches
        # it. Bound failed attempts per IP here instead: charge the attempt up
        # front (atomically) and refund it below once the token proves valid, so
        # an over-limit caller cannot keep driving is_token_valid() lookups.
        # (Moving the rate limiter ahead of auth is not an option: _client_key
        # would then key on an unvalidated token and dodge the per-IP limit.)
        client_ip = get_client_ip(request)
        if await _charge_auth_attempt(client_ip):
            return _too_many("Too many failed authentication attempts", "60")

        token = request.headers.get("x-wegis-token", "")
        if mode == "static":
            # Constant-time per candidate; `token in set` is not. Compare BYTES:
            # header values may be non-ASCII, which compare_digest rejects for str.
            raw = token.encode()
            ok = any(hmac.compare_digest(raw, t.encode()) for t in settings.api_tokens)
        elif mode == "registration":
            ok = await is_token_valid(token)
        else:
            ok = True

        if not ok:
            # The attempt is already counted; leave the charge in place.
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

        await _refund_auth_attempt(client_ip)
        return await call_next(request)
