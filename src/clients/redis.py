# --------------------------------------------------------------------------
# Redis client module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import logging
from typing import Optional

import redis.asyncio as aioredis
from src.core.config import settings

logger = logging.getLogger("main")


class RedisClient:
    """Redis client management class"""

    def __init__(self):
        self._client: Optional[aioredis.Redis] = None
        self._pool: Optional[aioredis.ConnectionPool] = None

    async def connect(self) -> aioredis.Redis:
        """Initialize Redis connection"""
        if self._client is None:
            try:
                self._pool = aioredis.ConnectionPool(
                    host=settings.REDIS_HOST,
                    port=settings.REDIS_PORT,
                    db=settings.REDIS_DB,
                    decode_responses=True,
                    socket_timeout=settings.REDIS_SOCKET_TIMEOUT,
                    retry_on_timeout=settings.REDIS_RETRY_ON_TIMEOUT,
                    max_connections=settings.REDIS_MAX_CONNECTIONS,
                )
                self._client = aioredis.Redis(connection_pool=self._pool)

                # Test connection
                await self._client.ping()
                logger.info("Redis connection established successfully")
            except Exception as e:
                logger.error(f"Failed to connect to Redis: {e}")
                raise

        return self._client

    async def disconnect(self) -> None:
        """Disconnect Redis connection"""
        if self._client:
            await self._client.aclose()
            logger.info("Redis connection closed")

        if self._pool:
            await self._pool.aclose()
            logger.info("Redis connection pool closed")

        self._client = None
        self._pool = None

    async def get_client(self) -> aioredis.Redis:
        """Return Redis client (connect if not connected)"""
        if self._client is None:
            await self.connect()
        if self._client is None:
            raise ConnectionError("Failed to initialize Redis client")
        return self._client


# Global Redis client instance
_redis_client = RedisClient()


async def get_redis() -> aioredis.Redis:
    """Return Redis client instance"""
    return await _redis_client.get_client()


async def init_redis() -> None:
    """Initialize Redis client"""
    await _redis_client.connect()


async def close_redis() -> None:
    """Close Redis client"""
    await _redis_client.disconnect()
