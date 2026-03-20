# --------------------------------------------------------------------------
# Analyzer service test module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from src.schemas.analyze import PhishingDetectionResponse


class TestAnalyzerService:
    """AnalyzerService class test"""

    @pytest.mark.asyncio
    async def test_analyze_whitelist_url(
        self, analyzer_service, mock_request, mock_db_manager
    ):
        """Whitelist URL analysis test"""
        with (
            patch("src.services.analyzer.get_redis") as mock_get_redis,
            patch("src.services.analyzer.DomainChecker") as mock_domain_checker_class,
        ):
            # Redis client mocking
            mock_redis = AsyncMock()
            mock_get_redis.return_value = mock_redis

            # DomainChecker mocking
            mock_domain_checker = AsyncMock()
            mock_domain_checker.is_whitelisted.return_value = True
            mock_domain_checker_class.return_value = mock_domain_checker

            result = await analyzer_service.analyze(
                url="https://google.com",
                request=mock_request,
                db_manager=mock_db_manager,
            )

            assert isinstance(result, PhishingDetectionResponse)
            assert result.result is False
            assert result.confidence == 0.01
            assert result.source == "whitelist"

    @pytest.mark.asyncio
    async def test_analyze_blacklist_url(
        self, analyzer_service, mock_request, mock_db_manager
    ):
        """Blacklist URL analysis test"""
        with (
            patch("src.services.analyzer.get_redis") as mock_get_redis,
            patch("src.services.analyzer.DomainChecker") as mock_domain_checker_class,
        ):
            # Redis client mocking
            mock_redis = AsyncMock()
            mock_get_redis.return_value = mock_redis

            # DomainChecker mocking
            mock_domain_checker = AsyncMock()
            mock_domain_checker.is_whitelisted.return_value = False
            mock_domain_checker.is_blacklisted.return_value = True
            mock_domain_checker_class.return_value = mock_domain_checker

            result = await analyzer_service.analyze(
                url="https://malicious-site.com",
                request=mock_request,
                db_manager=mock_db_manager,
            )

            assert isinstance(result, PhishingDetectionResponse)
            assert result.result is True
            assert result.confidence == 0.99
            assert result.source == "blacklist"

    @pytest.mark.asyncio
    async def test_analyze_cached_result(
        self, analyzer_service, mock_request, mock_db_manager
    ):
        """Cached result analysis test"""
        # Set cached result
        mock_db_manager.get_cached_result.return_value = {
            "is_phishing": True,
            "confidence": 0.75,
        }

        with (
            patch("src.services.analyzer.get_redis") as mock_get_redis,
            patch("src.services.analyzer.DomainChecker") as mock_domain_checker_class,
        ):
            # Redis client mocking
            mock_redis = AsyncMock()
            mock_get_redis.return_value = mock_redis

            # DomainChecker mocking (whitelist/blacklist both False)
            mock_domain_checker = AsyncMock()
            mock_domain_checker.is_whitelisted.return_value = False
            mock_domain_checker.is_blacklisted.return_value = False
            mock_domain_checker_class.return_value = mock_domain_checker

            result = await analyzer_service.analyze(
                url="https://cached-site.com",
                request=mock_request,
                db_manager=mock_db_manager,
            )

            assert isinstance(result, PhishingDetectionResponse)
            assert result.result is True
            assert result.confidence == 0.75
            assert result.source == "cache"

    @pytest.mark.asyncio
    async def test_analyze_ai_model_prediction(
        self, analyzer_service, mock_request, mock_db_manager
    ):
        """AI model prediction analysis test"""
        with (
            patch("src.services.analyzer.get_redis") as mock_get_redis,
            patch("src.services.analyzer.DomainChecker") as mock_domain_checker_class,
        ):
            # Redis client mocking
            mock_redis = AsyncMock()
            mock_get_redis.return_value = mock_redis

            # DomainChecker mocking (whitelist/blacklist both False)
            mock_domain_checker = AsyncMock()
            mock_domain_checker.is_whitelisted.return_value = False
            mock_domain_checker.is_blacklisted.return_value = False
            mock_domain_checker_class.return_value = mock_domain_checker

            # AI model prediction result setting
            mock_request.app.state.model.predict.return_value = {
                "result": True,
                "confidence": 0.85,
            }
            mock_request.app.state.model.html_loader = None

            result = await analyzer_service.analyze(
                url="https://unknown-site.com",
                request=mock_request,
                db_manager=mock_db_manager,
            )

            assert isinstance(result, PhishingDetectionResponse)
            assert result.result is True
            assert result.confidence == 0.85
            assert result.source == "model"

            # Check if DB save and cache save are called
            mock_db_manager.save_phishing_url.assert_called_once()
            mock_db_manager.cache_result.assert_called_once()

    @pytest.mark.asyncio
    async def test_analyze_ai_model_failure(
        self, analyzer_service, mock_request, mock_db_manager
    ):
        """AI model prediction failure test"""
        with (
            patch("src.services.analyzer.get_redis") as mock_get_redis,
            patch("src.services.analyzer.DomainChecker") as mock_domain_checker_class,
        ):
            # Redis client mocking
            mock_redis = AsyncMock()
            mock_get_redis.return_value = mock_redis

            # DomainChecker mocking (whitelist/blacklist both False)
            mock_domain_checker = AsyncMock()
            mock_domain_checker.is_whitelisted.return_value = False
            mock_domain_checker.is_blacklisted.return_value = False
            mock_domain_checker_class.return_value = mock_domain_checker

            # AI model prediction failure
            mock_request.app.state.model.predict.return_value = {
                "result": None,
                "confidence": None,
            }

            result = await analyzer_service.analyze(
                url="https://error-site.com",
                request=mock_request,
                db_manager=mock_db_manager,
            )

            assert isinstance(result, PhishingDetectionResponse)
            assert result.result is False
            assert result.confidence == 0.0
            assert result.source == "error"

    @pytest.mark.asyncio
    async def test_analyze_predict_from_html_path(
        self, analyzer_service, mock_request, mock_db_manager
    ):
        """Optimized HTML pipeline analysis test"""

        class OptimizedDetector:
            def predict_from_html(self, url: str, html: str) -> dict:
                return {
                    "result": True,
                    "confidence": 0.91,
                    "preprocess_ms": 12.5,
                    "infer_ms": 8.2,
                }

        detector = OptimizedDetector()
        mock_request.app.state.model = detector

        analyzer_service.fetcher.http_fetcher.fetch = MagicMock(
            return_value=MagicMock(html="<html>ok</html>")
        )
        analyzer_service.fetcher._is_low_quality_html = MagicMock(return_value=False)
        analyzer_service.fetcher.browser_fetcher.fetch = MagicMock()

        with (
            patch("src.services.analyzer.get_redis") as mock_get_redis,
            patch("src.services.analyzer.DomainChecker") as mock_domain_checker_class,
            patch("src.services.analyzer.log_perf_record") as mock_log_perf_record,
        ):
            mock_redis = AsyncMock()
            mock_get_redis.return_value = mock_redis

            mock_domain_checker = AsyncMock()
            mock_domain_checker.is_whitelisted.return_value = False
            mock_domain_checker.is_blacklisted.return_value = False
            mock_domain_checker_class.return_value = mock_domain_checker

            result = await analyzer_service.analyze(
                url="https://optimized-path.com",
                request=mock_request,
                db_manager=mock_db_manager,
            )

            assert isinstance(result, PhishingDetectionResponse)
            assert result.result is True
            assert result.confidence == 0.91
            assert result.source == "model"
            assert result.fetch_mode == "http"

            analyzer_service.fetcher.http_fetcher.fetch.assert_called_once()
            analyzer_service.fetcher.browser_fetcher.fetch.assert_not_called()
            mock_db_manager.save_phishing_url.assert_called_once_with(
                "https://optimized-path.com/",
                True,
                0.91,
                "<html>ok</html>",
            )
            mock_db_manager.cache_result.assert_called_once_with(
                url="https://optimized-path.com/",
                is_phishing=True,
                confidence=0.91,
            )

            perf_record = mock_log_perf_record.call_args.args[0]
            assert perf_record["fetch_mode"] == "http"
            assert perf_record["stages"]["preprocess"] == 12.5
            assert perf_record["stages"]["inference"] == 8.2
