# --------------------------------------------------------------------------
# Pytest configuration and shared fixtures
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import pytest
import pytest_asyncio
import redis.asyncio as aioredis
from unittest.mock import MagicMock, AsyncMock, patch
from fastapi import Request
from fastapi.testclient import TestClient

# Load test environment variables before importing settings
from dotenv import load_dotenv

from src.server import app
from src.services.domain_checker import DomainChecker
from src.services.analyzer import AnalyzerService
from src.schemas.analyze import PhishingDetectionResponse

load_dotenv("env.test", override=True)

# ============================================================================
# Pytest configuration
# ============================================================================


def pytest_configure(config):
    """Pytest configuration"""
    config.addinivalue_line(
        "markers", "integration: mark test as integration test (uses actual services)"
    )
    config.addinivalue_line("markers", "unit: mark test as unit test (uses mocks)")


# ============================================================================
# Common fixtures
# ============================================================================


@pytest.fixture
def client():
    """FastAPI TestClient fixture

    Used for API endpoint test.
    """
    return TestClient(app)


@pytest.fixture
def mock_request():
    """Mock FastAPI Request fixture

    Mock FastAPI Request object.
    Default to AI model predicting phishing site.
    """
    request = MagicMock(spec=Request)
    request.app.state.model = MagicMock()
    request.app.state.model.predict.return_value = {"result": True, "confidence": 0.85}
    return request


@pytest.fixture
def mock_db_manager():
    """Mock DBManager fixture

    Mock database operations.
    Default to no cached result and successful save operation.
    """
    db_manager = MagicMock()
    # Set asynchronous methods to AsyncMock
    db_manager.get_cached_result = AsyncMock(return_value=None)
    db_manager.save_phishing_url = MagicMock(return_value=MagicMock())
    db_manager.cache_phishing_result = AsyncMock(return_value=None)
    db_manager.get_phishing_urls = MagicMock(return_value=[])
    return db_manager


@pytest_asyncio.fixture
async def mock_redis():
    """Mock Redis client fixture

    Mock Redis asynchronous operations.
    """
    redis_mock = AsyncMock(spec=aioredis.Redis)
    # Set Redis methods to AsyncMock
    redis_mock.sismember = AsyncMock(return_value=False)
    redis_mock.smembers = AsyncMock(return_value=set())
    redis_mock.sadd = AsyncMock(return_value=1)
    redis_mock.srem = AsyncMock(return_value=1)
    redis_mock.get = AsyncMock(return_value=None)
    redis_mock.setex = AsyncMock(return_value=True)
    return redis_mock


@pytest.fixture
def mock_redis_sync():
    """Mock Redis client fixture (sync)

    Mock synchronous Redis operations.
    """
    return MagicMock()


@pytest_asyncio.fixture
async def domain_checker(mock_redis):
    """DomainChecker instance fixture

    Create DomainChecker with mock Redis client.
    """
    return DomainChecker(mock_redis)


@pytest.fixture
def analyzer_service():
    """AnalyzerService instance fixture

    Create AnalyzerService with mocked HTMLLoader and PhishingDetector.
    """
    with (
        patch("src.services.analyzer.HTMLLoader"),
        patch("src.services.analyzer.PhishingDetector"),
    ):
        return AnalyzerService()


@pytest.fixture
def mock_analyzer_service():
    """Mock AnalyzerService fixture

    Mock AnalyzerService's analyze method.
    Default to AI model predicting phishing site.
    """
    analyzer = AsyncMock()
    analyzer.analyze.return_value = PhishingDetectionResponse(
        result=True, confidence=0.85, source="model"
    )
    return analyzer


# ============================================================================
# Integration test fixtures
# ============================================================================


@pytest_asyncio.fixture
async def redis_client():
    """Actual Redis client fixture (integration test)

    Connect to actual Redis server running in Docker Compose.
    Should only be used for tests with integration marker.
    """
    import redis.asyncio as aioredis
    from src.core.config import settings

    # Create a new connection pool for each test
    pool = aioredis.ConnectionPool(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        db=settings.REDIS_DB,
        decode_responses=True,
    )
    client = aioredis.Redis(connection_pool=pool)

    yield client

    # Clean up
    await client.aclose()
    await pool.aclose()


@pytest_asyncio.fixture
async def integration_domain_checker(redis_client):
    """Actual Redis using DomainChecker fixture (integration test)

    Should only be used for tests with integration marker.
    """
    return DomainChecker(redis_client)


# ============================================================================
# Test data fixtures
# ============================================================================


@pytest.fixture
def sample_phishing_response():
    """Sample phishing detection response fixture"""
    return PhishingDetectionResponse(result=True, confidence=0.85, source="model")


@pytest.fixture
def sample_safe_response():
    """Sample safe site response fixture"""
    return PhishingDetectionResponse(result=False, confidence=0.15, source="whitelist")


@pytest.fixture
def test_urls():
    """Test URL list fixture"""
    return {
        "phishing": "https://suspicious-phishing-site.com",
        "safe": "https://google.com",
        "whitelist": "https://github.com",
        "blacklist": "https://known-malicious-site.com",
        "unknown": "https://unknown-domain-12345.com",
    }
