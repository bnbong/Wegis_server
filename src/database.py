# --------------------------------------------------------------------------
# Database connection management module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence

from sqlalchemy import desc
from sqlalchemy.orm import sessionmaker
from sqlmodel import Session, SQLModel, create_engine, select

from src.core.config import settings
from src.exceptions import BackendExceptions
from src.orm_models import PhishingURL, UserFeedback
from src.clients.redis import get_redis
from src.clients.mongo import get_mongo_database

logger = logging.getLogger("main")


class DBManager:
    _instance = None

    @classmethod
    def _reset_instance(cls):
        """Initialize instance for test purposes (only used in test environment)"""
        cls._instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DBManager, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        # PostgreSQL connection setup
        self.postgres_engine = create_engine(str(settings.POSTGRES_URI))
        SQLModel.metadata.create_all(bind=self.postgres_engine)
        self.SessionLocal = sessionmaker(
            autocommit=False, autoflush=False, bind=self.postgres_engine, class_=Session
        )

    def get_postgres_session(self) -> Session:
        """Get PostgreSQL session"""
        return self.SessionLocal()

    def close(self):
        """Close PostgreSQL database connections"""
        logger.info("PostgreSQL database connections closed")

    # Redis operations
    async def cache_phishing_result(
        self, url: str, is_phishing: bool, confidence: float, ttl: int = 86400
    ) -> None:
        """Cache phishing URL result in Redis"""
        cache_data = {
            "is_phishing": is_phishing,
            "confidence": confidence,
            "last_updated": datetime.now().isoformat(),
        }
        redis_client = await get_redis()
        await redis_client.setex(f"phishing:{url}", ttl, json.dumps(cache_data))  # type: ignore
        logger.info(f"Cached result for URL: {url}")

    async def get_cached_result(self, url: str) -> Optional[Dict[str, Any]]:
        """Get cached phishing URL result from Redis"""
        redis_client = await get_redis()
        result = await redis_client.get(f"phishing:{url}")  # type: ignore
        if result:
            logger.info(f"Cache hit for URL: {url}")
            return json.loads(result)
        logger.info(f"Cache miss for URL: {url}")
        return None

    async def update_cache_from_db(self, limit: int = 1000) -> int:
        """Update PostgreSQL phishing URL to Redis cache"""
        session = self.get_postgres_session()
        try:
            urls = session.exec(
                select(PhishingURL)
                .where(PhishingURL.is_phishing)
                .order_by(desc("detection_time"))
                .limit(limit)
            ).all()

            count = 0
            for url_obj in urls:
                await self.cache_phishing_result(
                    url_obj.url,
                    url_obj.is_phishing,
                    url_obj.confidence,
                )
                count += 1

            logger.info(f"Updated {count} URLs in cache from database")
            return count
        finally:
            session.close()

    def save_phishing_url(
        self,
        url: str,
        is_phishing: bool,
        confidence: float,
        html_content: Optional[str] = None,
        features: Optional[Dict[str, Any]] = None,
    ) -> PhishingURL:
        """Save phishing URL information to PostgreSQL"""
        session = self.get_postgres_session()
        try:
            existing = session.exec(
                select(PhishingURL).where(PhishingURL.url == url)
            ).first()

            if existing:
                # Update existing data
                existing.is_phishing = is_phishing
                existing.confidence = confidence
                existing.detection_time = datetime.now()
                if html_content:
                    existing.html_content = html_content
                if features:
                    existing.features = json.dumps(features)
                url_obj = existing
            else:
                # Add new data
                url_obj = PhishingURL(
                    url=url,
                    is_phishing=is_phishing,
                    confidence=confidence,
                    html_content=html_content,
                    features=json.dumps(features) if features else None,
                )
                session.add(url_obj)

            session.commit()
            session.refresh(url_obj)
            logger.info(f"Saved phishing URL data: {url}")

            return url_obj
        except Exception as e:
            session.rollback()
            logger.error(f"Error saving URL to database: {e}")
            raise
        finally:
            session.close()

    def get_phishing_urls(
        self, limit: int = 100, offset: int = 0
    ) -> Sequence[PhishingURL]:
        """Get phishing URL list from PostgreSQL"""
        session = self.get_postgres_session()
        try:
            return session.exec(
                select(PhishingURL)
                .order_by(desc("detection_time"))
                .limit(limit)
                .offset(offset)
            ).all()
        finally:
            session.close()

    # MongoDB operations
    async def save_user_feedback(self, feedback: UserFeedback) -> str:
        """Save user feedback to MongoDB"""
        try:
            mongo_db = await get_mongo_database()
            if mongo_db is None:
                raise BackendExceptions("MongoDB connection not available")

            feedback_collection = mongo_db["user_feedback"]
            result = await feedback_collection.insert_one(feedback.model_dump())
            logger.info(f"Saved user feedback for URL: {feedback.url}")
            return str(result.inserted_id)
        except Exception as e:
            logger.error(f"Error saving feedback to MongoDB: {e}")
            raise BackendExceptions(f"Error saving feedback to MongoDB: {e}")

    async def get_user_feedbacks(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get user feedback list from MongoDB"""
        try:
            mongo_db = await get_mongo_database()
            if mongo_db is None:
                raise BackendExceptions("MongoDB connection not available")

            feedback_collection = mongo_db["user_feedback"]
            cursor = feedback_collection.find().sort("feedback_time", -1).limit(limit)
            return await cursor.to_list(length=limit)
        except Exception as e:
            logger.error(f"Error getting feedback from MongoDB: {e}")
            raise BackendExceptions(f"Error getting feedback from MongoDB: {e}")
