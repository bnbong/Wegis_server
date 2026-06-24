# --------------------------------------------------------------------------
# Database connection management module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import json
import logging
from datetime import datetime
from typing import Any, Dict, Optional, Sequence

from sqlalchemy import desc
from sqlalchemy.orm import sessionmaker
from sqlmodel import Session, SQLModel, create_engine, select

from src.core.config import settings
from src.orm_models import PhishingURL, APIClient
from src.clients.redis import get_redis
from src.services.url_utils import canonicalize_url

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

    def _cache_key(self, url: str) -> str:
        canonical = canonicalize_url(url)
        # NOTE: prefix changed from "<ns>:phishing:" to "<ns>:analysis:" so that
        # benign results are no longer indistinguishable from phishing ones. Legacy
        # "<ns>:phishing:*" keys expire naturally or are removed by
        # scripts/cleanup-redis-falsepos.sh.
        return f"{settings.REDIS_NAMESPACE}:analysis:{canonical}"

    # Redis operations
    async def cache_result(
        self, url: str, is_phishing: bool, confidence: float, ttl: Optional[int] = None
    ) -> None:
        """Cache URL analysis result in Redis"""
        resolved_ttl = ttl
        if resolved_ttl is None:
            resolved_ttl = (
                settings.REDIS_CACHE_TTL_PHISHING
                if is_phishing
                else settings.REDIS_CACHE_TTL_BENIGN
            )

        cache_data = {
            "is_phishing": is_phishing,
            "confidence": confidence,
            "canonical_url": canonicalize_url(url),
            "last_updated": datetime.now().isoformat(),
        }
        redis_client = await get_redis()
        await redis_client.setex(
            self._cache_key(url), resolved_ttl, json.dumps(cache_data)
        )  # type: ignore
        logger.info(f"Cached result for URL: {url}")

    async def get_cached_result(self, url: str) -> Optional[Dict[str, Any]]:
        """Get cached phishing URL result from Redis"""
        redis_client = await get_redis()
        result = await redis_client.get(self._cache_key(url))  # type: ignore
        if result:
            logger.info(f"Cache hit for URL: {url}")
            return json.loads(result)
        logger.info(f"Cache miss for URL: {url}")
        return None

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
        self, limit: int = 100, offset: int = 0, include_benign: bool = False
    ) -> Sequence[PhishingURL]:
        """Get phishing URL list from PostgreSQL.

        By default returns only phishing (blocked) rows so the "recent" feed
        cannot be diluted by benign rows (e.g. legacy data or PERSIST_BENIGN=true).
        """
        session = self.get_postgres_session()
        try:
            statement = select(PhishingURL)
            if not include_benign:
                statement = statement.where(PhishingURL.is_phishing.is_(True))
            return session.exec(
                statement.order_by(desc("detection_time")).limit(limit).offset(offset)
            ).all()
        finally:
            session.close()

    # API client (per-install auth) operations
    def register_client(
        self, token_hash: str, install_id: str, ext_version: Optional[str] = None
    ) -> None:
        """Persist a newly issued per-install API client (token hash only)."""
        session = self.get_postgres_session()
        try:
            session.add(
                APIClient(
                    token_hash=token_hash,
                    install_id=install_id,
                    status="active",
                    ext_version=ext_version,
                )
            )
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Error registering API client: {e}")
            raise
        finally:
            session.close()

    def get_client_status(self, token_hash: str) -> Optional[str]:
        """Return the client status (active|revoked) or None if unknown."""
        session = self.get_postgres_session()
        try:
            client = session.get(APIClient, token_hash)
            return client.status if client else None
        finally:
            session.close()

    def revoke_client(self, token_hash: str) -> bool:
        """Revoke a client token. Returns True if a client was found."""
        session = self.get_postgres_session()
        try:
            client = session.get(APIClient, token_hash)
            if client is None:
                return False
            client.status = "revoked"
            session.add(client)
            session.commit()
            return True
        finally:
            session.close()
