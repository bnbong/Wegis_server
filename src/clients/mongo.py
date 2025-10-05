# --------------------------------------------------------------------------
# MongoDB client module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import logging
from typing import Optional, List, Any

import motor.motor_asyncio
from beanie import init_beanie
from src.core.config import settings

logger = logging.getLogger("main")


class MongoClient:
    """MongoDB client management class"""

    def __init__(self):
        self._client: Optional[motor.motor_asyncio.AsyncIOMotorClient] = None
        self._database = None

    async def connect(self) -> motor.motor_asyncio.AsyncIOMotorClient:
        """Initialize MongoDB connection"""
        if self._client is None:
            try:
                mongo_uri = str(settings.MONGODB_URI)
                self._client = motor.motor_asyncio.AsyncIOMotorClient(
                    mongo_uri,
                    maxPoolSize=settings.MONGODB_MAX_POOL_SIZE,
                    minPoolSize=settings.MONGODB_MIN_POOL_SIZE,
                    serverSelectionTimeoutMS=settings.MONGODB_SERVER_SELECTION_TIMEOUT,
                )

                # Test connection
                await self._client.admin.command("ping")
                self._database = self._client[settings.MONGODB_NAME]

                logger.info("MongoDB connection established successfully")
            except Exception as e:
                logger.error(f"Failed to connect to MongoDB: {e}")
                raise

        return self._client

    async def disconnect(self) -> None:
        """Disconnect MongoDB connection"""
        if self._client:
            self._client.close()
            logger.info("MongoDB connection closed")

        self._client = None
        self._database = None

    async def get_client(self) -> Optional[motor.motor_asyncio.AsyncIOMotorClient]:
        """Return MongoDB client (connect if not connected)"""
        if self._client is None:
            await self.connect()
        return self._client

    async def get_database(self):
        """Return MongoDB database"""
        if self._database is None:
            await self.connect()
        return self._database

    async def init_beanie(self, document_models: List[Any]) -> None:
        """Initialize Beanie ODM"""
        if self._database is None:
            await self.connect()

        if self._database is not None:
            await init_beanie(database=self._database, document_models=document_models)
            logger.info("Beanie ODM initialized successfully")


# Global MongoDB client instance
_mongo_client = MongoClient()


async def get_mongo() -> Optional[motor.motor_asyncio.AsyncIOMotorClient]:
    """Return MongoDB client instance"""
    return await _mongo_client.get_client()


async def get_mongo_database():
    """Return MongoDB database instance"""
    return await _mongo_client.get_database()


async def init_mongo(document_models: Optional[List[Any]] = None) -> None:
    """Initialize MongoDB client and Beanie"""
    await _mongo_client.connect()
    if document_models is not None:
        await _mongo_client.init_beanie(document_models)


async def close_mongo() -> None:
    """Close MongoDB client"""
    await _mongo_client.disconnect()
