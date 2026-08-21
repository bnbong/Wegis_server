# --------------------------------------------------------------------------
# Per-install API token service (design 05)
#
# Tokens are issued by POST /auth/register and validated on /analyze/*. Only the
# SHA-256 hash is stored. Validation is Redis-cache-fronted with a PostgreSQL
# fallback. Infra errors fail OPEN (consistent with the rate limiter): auth here
# is abuse control + per-install revocation, not a strong secret. Brute-force is
# additionally mitigated by the per-IP auth-failure limiter in the middleware.
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import asyncio
import hashlib
import hmac
import logging
import secrets
import time
from uuid import uuid4

from src.core.config import settings
from src.clients.redis import get_redis
from src.database import DBManager

logger = logging.getLogger("main")


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _cache_key(token_hash: str) -> str:
    return f"{settings.REDIS_NAMESPACE}:authtoken:{token_hash}"


def bootstrap_ok(provided: str | None) -> bool:
    """Constant-time check of the registration bootstrap secret."""
    secret = settings.REGISTRATION_BOOTSTRAP_SECRET
    if not secret:
        # Registration must not be open without a configured bootstrap secret.
        return False
    # Compare BYTES: the value comes from a header and may be non-ASCII, which
    # compare_digest rejects for str (a TypeError here would 500 the endpoint).
    return hmac.compare_digest((provided or "").encode(), secret.encode())


async def is_token_valid(token: str) -> bool:
    """Validate a per-install token. Redis cache -> PostgreSQL. Fail-open on
    infra errors; reject empty/unknown/revoked tokens."""
    if not token:
        return False
    token_hash = hash_token(token)
    key = _cache_key(token_hash)

    redis = None
    try:
        redis = await get_redis()
        cached = await redis.get(key)
        if cached == "active":
            return True
        if cached in ("revoked", "invalid"):
            return False
    except Exception as exc:
        logger.warning("Auth token cache read failed: %s", exc)

    try:
        status = await asyncio.to_thread(DBManager().get_client_status, token_hash)
    except Exception as exc:
        # Datastore unreachable -> fail open (availability over strict auth).
        logger.warning("Auth token DB lookup failed (fail-open): %s", exc)
        return True

    if redis is not None:
        try:
            await redis.setex(key, settings.AUTH_TOKEN_CACHE_TTL, status or "invalid")
        except Exception:
            pass
    return status == "active"


async def register_client(ext_version: str | None = None) -> tuple[str, str]:
    """Issue a new per-install token; returns (token, install_id)."""
    token = secrets.token_urlsafe(32)
    install_id = str(uuid4())
    await asyncio.to_thread(
        DBManager().register_client, hash_token(token), install_id, ext_version
    )
    try:
        redis = await get_redis()
        await redis.setex(
            _cache_key(hash_token(token)), settings.AUTH_TOKEN_CACHE_TTL, "active"
        )
    except Exception:
        pass
    return token, install_id


async def registration_allowed(client_ip: str) -> bool:
    """Per-IP fixed-window rate limit for registration. Fail-open."""
    try:
        redis = await get_redis()
        window = int(time.time() // 3600)
        key = f"{settings.REDIS_NAMESPACE}:reg_rate:{client_ip}:{window}"
        count = await redis.incr(key)
        if count == 1:
            await redis.expire(key, 3600)
        return count <= settings.REGISTRATION_RATE_LIMIT_PER_HOUR
    except Exception as exc:
        logger.warning("Registration rate-limit failed open: %s", exc)
        return True
