# --------------------------------------------------------------------------
# Analyzer service module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import logging

from fastapi import Request
from typing import Optional, Type

from src.database import DBManager
from src.core.config import settings
from src.services.html.loader import HTMLLoader
from src.services.model.manager import PhishingDetector
from src.services.domain_checker import DomainChecker
from src.schemas.analyze import PhishingDetectionResponse
from src.clients.redis import get_redis

logger = logging.getLogger("main")


class AnalyzerService:
    def __init__(self):
        self.loader = HTMLLoader()
        self.detector = PhishingDetector(settings.MODEL_PATH)

    async def analyze(
        self,
        url: str,
        request: Request,
        response_model: Type[PhishingDetectionResponse] = PhishingDetectionResponse,
        db_manager: Optional[DBManager] = None,
    ) -> PhishingDetectionResponse:
        logger.info(f"Analyzing URL: {url}")

        # Redis-based whitelist/blacklist check
        redis_client = await get_redis()
        domain_checker = DomainChecker(redis_client)

        # Check whitelist
        if await domain_checker.is_whitelisted(url):
            logger.info(f"URL {url} is in whitelist")
            return response_model.model_validate(
                {
                    "result": False,
                    "confidence": 0.01,
                    "source": "whitelist",
                }
            )

        # Check blacklist
        if await domain_checker.is_blacklisted(url):
            logger.info(f"URL {url} is in blacklist")
            return response_model.model_validate(
                {
                    "result": True,
                    "confidence": 0.99,
                    "source": "blacklist",
                }
            )

        # If DB manager is not provided, create a new one
        if db_manager is None:
            db_manager = DBManager()

        # 1. Check cached result in Redis
        cached_result = await db_manager.get_cached_result(url)
        if cached_result:
            logger.info(
                f"Using cached result for URL: {url} - Is phishing site: {cached_result['is_phishing']}, Confidence: {cached_result['confidence']}"
            )
            return response_model.model_validate(
                {
                    "result": cached_result["is_phishing"],
                    "confidence": cached_result["confidence"],
                    "source": "cache",
                }
            )

        # 2. If cached result is not found, analyze with AI model
        detector = request.app.state.model
        result = detector.predict(url)

        if result["confidence"] is not None:
            logger.info(
                f"AI analysis result: {url} - Phishing: {result['result']}, Confidence: {result['confidence']:.4f}"
            )

            # Get HTML content
            html_content = None
            if hasattr(detector, "html_loader") and detector.html_loader:
                try:
                    html_content = detector.html_loader.load(url)
                except Exception as e:
                    logger.warning(f"Failed to get HTML for storage: {e}")

            # Save data to PostgreSQL
            db_manager.save_phishing_url(
                url=url,
                is_phishing=result["result"],
                confidence=result["confidence"],
                html_content=html_content,
            )

            # If the URL is phishing, cache the result in Redis
            if result["result"]:
                await db_manager.cache_phishing_result(
                    url=url,
                    is_phishing=result["result"],
                    confidence=result["confidence"],
                )

            return response_model.model_validate(
                {
                    "result": result["result"],
                    "confidence": result["confidence"],
                    "source": "model",
                }
            )
        else:
            logger.error(f"Failed to analyze URL: {url}")
            return response_model.model_validate(
                {"result": False, "confidence": 0.0, "source": "error"}
            )
