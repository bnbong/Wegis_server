# --------------------------------------------------------------------------
# Integration test module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import pytest
import pytest_asyncio
from unittest.mock import patch, MagicMock
from datetime import datetime

from src.core.config import settings
from src.database import DBManager
from src.orm_models import UserFeedback


@pytest.mark.integration
class TestDomainCheckerIntegration:
    """DomainChecker integration test (actual Redis connection)"""

    @pytest.mark.asyncio
    async def test_full_workflow_whitelist(
        self, integration_domain_checker, redis_client
    ):
        """Whitelist full workflow test"""
        # Set test data
        test_domain = "google.com"
        test_url = f"https://{test_domain}"

        # Add domain to whitelist
        await redis_client.sadd(
            f"{settings.REDIS_NAMESPACE}:whitelist:domains", test_domain
        )

        # Check whitelist
        is_whitelisted = await integration_domain_checker.is_whitelisted(test_url)
        assert is_whitelisted is True

        # Check domain status
        status = await integration_domain_checker.get_domain_status(test_url)
        assert status == "whitelist"

        # Clean up
        await redis_client.srem(
            f"{settings.REDIS_NAMESPACE}:whitelist:domains", test_domain
        )

    @pytest.mark.asyncio
    async def test_full_workflow_blacklist(
        self, integration_domain_checker, redis_client
    ):
        """Blacklist full workflow test"""
        # Set test data
        test_domain = "malicious-site.com"
        test_url = f"https://{test_domain}"

        # Add domain to blacklist
        await redis_client.sadd(
            f"{settings.REDIS_NAMESPACE}:blacklist:domains", test_domain
        )

        # Check blacklist
        is_blacklisted = await integration_domain_checker.is_blacklisted(test_url)
        assert is_blacklisted is True

        # Check domain status
        status = await integration_domain_checker.get_domain_status(test_url)
        assert status == "blacklist"

        # Clean up
        await redis_client.srem(
            f"{settings.REDIS_NAMESPACE}:blacklist:domains", test_domain
        )

    @pytest.mark.asyncio
    async def test_pattern_matching_workflow(
        self, integration_domain_checker, redis_client
    ):
        """Pattern matching full workflow test"""
        # Set test data
        pattern = "*.google.com"
        test_url = "https://mail.google.com"

        # Add whitelist pattern
        await redis_client.sadd(
            f"{settings.REDIS_NAMESPACE}:whitelist:patterns", pattern
        )

        # Check pattern matching
        is_whitelisted = await integration_domain_checker.is_whitelisted(test_url)
        assert is_whitelisted is True

        # Check domain status
        status = await integration_domain_checker.get_domain_status(test_url)
        assert status == "whitelist"

        # Clean up
        await redis_client.srem(
            f"{settings.REDIS_NAMESPACE}:whitelist:patterns", pattern
        )

    @pytest.mark.asyncio
    async def test_unknown_domain_workflow(
        self, integration_domain_checker, redis_client
    ):
        """Unknown domain full workflow test"""
        test_url = "https://unknown-domain.com"

        # Check whitelist/blacklist
        is_whitelisted = await integration_domain_checker.is_whitelisted(test_url)
        is_blacklisted = await integration_domain_checker.is_blacklisted(test_url)

        assert is_whitelisted is False
        assert is_blacklisted is False

        # Check domain status
        status = await integration_domain_checker.get_domain_status(test_url)
        assert status == "unknown"


@pytest.mark.integration
class TestDatabaseIntegration:
    """Database integration test (PostgreSQL, Redis, MongoDB)"""

    @pytest_asyncio.fixture
    async def init_beanie(self):
        """Initialize Beanie ODM for MongoDB tests"""
        import motor.motor_asyncio
        from beanie import init_beanie as beanie_init
        from src.core.config import settings

        # Reset MongoDB client singleton to avoid event loop issues
        from src.clients.mongo import _mongo_client

        if _mongo_client._client is not None:
            _mongo_client._client.close()
        _mongo_client._client = None
        _mongo_client._database = None

        # Create a new MongoDB client for each test
        mongo_uri = str(settings.MONGODB_URI)
        client = motor.motor_asyncio.AsyncIOMotorClient(mongo_uri)
        database = client[settings.MONGODB_NAME]

        # Initialize Beanie
        await beanie_init(database=database, document_models=[UserFeedback])

        yield

        # Clean up
        client.close()

        # Reset MongoDB client after test
        if _mongo_client._client is not None:
            _mongo_client._client.close()
        _mongo_client._client = None
        _mongo_client._database = None

    @pytest_asyncio.fixture
    async def db_manager(self, init_beanie):
        """DBManager fixture for integration test"""
        # Reset both DBManager and Redis client singleton for each test
        DBManager._reset_instance()

        # Reset Redis client singleton to avoid event loop issues
        from src.clients.redis import _redis_client

        if _redis_client._client is not None:
            try:
                await _redis_client.disconnect()
            except Exception:
                pass
        _redis_client._client = None
        _redis_client._pool = None

        db_manager = DBManager()
        yield db_manager

        # Cleanup
        db_manager.close()

        # Reset Redis client after test
        if _redis_client._client is not None:
            try:
                await _redis_client.disconnect()
            except Exception:
                pass
        _redis_client._client = None
        _redis_client._pool = None

    @pytest.mark.asyncio
    async def test_aaa_full_database_workflow(self, db_manager):
        """Full database workflow integration test

        Note: Named with 'aaa_' prefix to run first and avoid Redis client conflicts
        """
        test_url = "https://full-workflow-test.com"

        # 1. Save to PostgreSQL
        saved_url = db_manager.save_phishing_url(
            url=test_url,
            is_phishing=True,
            confidence=0.88,
            html_content="<html>Test</html>",
        )
        assert saved_url.url == test_url

        # 2. Cache to Redis
        await db_manager.cache_phishing_result(
            url=test_url, is_phishing=True, confidence=0.88
        )

        # 3. Retrieve from cache
        cached = await db_manager.get_cached_result(test_url)
        assert cached is not None
        assert cached["is_phishing"] is True

        # 4. Save user feedback to MongoDB
        feedback = UserFeedback(
            url=test_url,
            is_correct=True,  # User confirms it's phishing
            detected_result=True,  # Model detected as phishing
            confidence=0.88,
            user_comment="Confirmed phishing site",
            feedback_time=datetime.now(),
        )
        feedback_id = await db_manager.save_user_feedback(feedback)
        assert feedback_id is not None

    @pytest.mark.asyncio
    async def test_postgresql_phishing_url_workflow(self, db_manager):
        """PostgreSQL phishing URL save and retrieve test"""
        # Test data
        test_url = "https://test-phishing-site.com"
        test_confidence = 0.95
        test_html = "<html><body>Phishing site</body></html>"

        # Save phishing URL
        saved_url = db_manager.save_phishing_url(
            url=test_url,
            is_phishing=True,
            confidence=test_confidence,
            html_content=test_html,
        )

        assert saved_url.url == test_url
        assert saved_url.is_phishing is True
        assert saved_url.confidence == test_confidence
        assert saved_url.html_content == test_html

        # Retrieve phishing URLs
        urls = db_manager.get_phishing_urls(limit=10)
        assert len(urls) > 0

        # Check if saved URL is in the list
        url_strings = [url_obj.url for url_obj in urls]
        assert test_url in url_strings

    @pytest.mark.asyncio
    async def test_redis_cache_workflow(self, db_manager):
        """Redis cache save and retrieve test"""
        # Test data
        test_url = "https://cached-phishing-site.com"
        test_confidence = 0.85

        # Cache phishing result
        await db_manager.cache_phishing_result(
            url=test_url,
            is_phishing=True,
            confidence=test_confidence,
            ttl=300,  # 5 minutes
        )

        # Retrieve cached result
        cached_result = await db_manager.get_cached_result(test_url)

        assert cached_result is not None
        assert cached_result["is_phishing"] is True
        assert cached_result["confidence"] == test_confidence
        assert "last_updated" in cached_result

    @pytest.mark.asyncio
    async def test_mongodb_feedback_workflow(self, db_manager):
        """MongoDB user feedback save and retrieve test"""
        # Test data
        test_feedback = UserFeedback(
            url="https://feedback-test-site.com",
            is_correct=False,  # User says it's not phishing
            detected_result=True,  # Model detected as phishing
            confidence=0.90,
            user_comment="This is actually a safe site, false positive",
            feedback_time=datetime.now(),
        )

        # Save user feedback
        feedback_id = await db_manager.save_user_feedback(test_feedback)
        assert feedback_id is not None

        # Retrieve user feedbacks
        feedbacks = await db_manager.get_user_feedbacks(limit=10)
        assert len(feedbacks) > 0

        # Check if saved feedback is in the list
        feedback_urls = [feedback["url"] for feedback in feedbacks]
        assert test_feedback.url in feedback_urls


@pytest.mark.integration
class TestAnalyzerWorkflow:
    """Analyzer workflow integration test"""

    @pytest.mark.asyncio
    async def test_analyzer_with_domain_checker_integration(self):
        """Analyzer and DomainChecker integration test"""
        from src.services.analyzer import AnalyzerService
        from unittest.mock import AsyncMock

        with (
            patch("src.services.analyzer.get_redis") as mock_get_redis,
            patch("src.services.analyzer.DomainChecker") as mock_domain_checker_class,
            patch("src.services.analyzer.HTMLLoader"),
            patch("src.services.analyzer.PhishingDetector"),
        ):
            # Redis client mocking
            mock_redis = AsyncMock()
            mock_get_redis.return_value = mock_redis

            # DomainChecker mocking
            mock_domain_checker = AsyncMock()
            mock_domain_checker.is_whitelisted.return_value = True
            mock_domain_checker.is_blacklisted.return_value = False
            mock_domain_checker_class.return_value = mock_domain_checker

            # Mock request
            mock_request = MagicMock()
            mock_request.app.state.model = MagicMock()

            # Mock DB manager
            mock_db_manager = MagicMock()

            # Analyzer test
            analyzer = AnalyzerService()
            result = await analyzer.analyze(
                url="https://google.com",
                request=mock_request,
                db_manager=mock_db_manager,
            )

            # Check if whitelisted
            assert result.result is False
            assert result.source == "whitelist"

            # Check if DomainChecker is called
            mock_domain_checker.is_whitelisted.assert_called_once_with(
                "https://google.com"
            )
