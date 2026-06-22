# --------------------------------------------------------------------------
# Analyzer service test module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import asyncio

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from src.exceptions import BackendExceptions
from src.schemas.analyze import PhishingDetectionResponse
from src.services.fetchers.http_fetcher import FetchResult
from src.services.net_guard import SSRFBlockedError
from src.services.reputation import ReputationResult
import src.services.analyzer as analyzer_mod


@pytest.fixture(autouse=True)
def _pin_model_thresholds():
    """Pin severity thresholds so analyzer tests don't depend on ambient .env
    values (e.g. a deployment that raised MODEL_BLOCK_THRESHOLD)."""
    with (
        patch.object(analyzer_mod.settings, "MODEL_BLOCK_THRESHOLD", 0.90),
        patch.object(analyzer_mod.settings, "MODEL_WARN_THRESHOLD", 0.70),
    ):
        yield


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
        # Set cached result (high confidence -> block under threshold policy)
        mock_db_manager.get_cached_result.return_value = {
            "is_phishing": True,
            "confidence": 0.95,
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
            assert result.confidence == 0.95
            assert result.source == "cache"
            assert result.severity == "block"

    @pytest.mark.asyncio
    async def test_analyze_ai_model_prediction(
        self, analyzer_service, mock_request, mock_db_manager
    ):
        """AI model prediction analysis test"""
        # AI model prediction result setting (HTML pipeline). High confidence so
        # the navigation severity policy yields a block.
        mock_request.app.state.model.predict_from_html.return_value = {
            "result": True,
            "confidence": 0.95,
            "preprocess_ms": 1.0,
            "infer_ms": 1.0,
        }
        analyzer_service.fetcher.http_fetcher.fetch = MagicMock(
            return_value=FetchResult(
                html="<html>ok</html>", fetch_mode="http", content_type="text/html"
            )
        )
        analyzer_service.fetcher._is_low_quality_html = MagicMock(return_value=False)
        analyzer_service.fetcher.browser_fetcher.fetch = MagicMock()

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
                url="https://unknown-site.com",
                request=mock_request,
                db_manager=mock_db_manager,
            )

            assert isinstance(result, PhishingDetectionResponse)
            assert result.result is True
            assert result.confidence == 0.95
            assert result.source == "model"
            assert result.severity == "block"

            # Check if DB save and cache save are called
            mock_db_manager.save_phishing_url.assert_called_once()
            mock_db_manager.cache_result.assert_called_once()

    @pytest.mark.asyncio
    async def test_analyze_rejects_blank_url(
        self, analyzer_service, mock_request, mock_db_manager
    ):
        """Blank URL should be rejected before cache lookup or model execution"""
        with pytest.raises(BackendExceptions, match="URL must not be empty"):
            await analyzer_service.analyze(
                url="   ",
                request=mock_request,
                db_manager=mock_db_manager,
            )

        mock_db_manager.get_cached_result.assert_not_called()
        mock_request.app.state.model.predict_from_html.assert_not_called()

    @pytest.mark.asyncio
    async def test_analyze_uses_input_url_for_inference_and_persists_canonical_url(
        self, analyzer_service, mock_request, mock_db_manager
    ):
        """Model path should keep raw input for inference and canonical URL for persistence"""
        raw_input = "www.legacy-site.com/login?b=2&a=1"

        mock_request.app.state.model.predict_from_html.return_value = {
            "result": True,
            "confidence": 0.85,
            "preprocess_ms": 1.0,
            "infer_ms": 1.0,
        }
        analyzer_service.fetcher.http_fetcher.fetch = MagicMock(
            return_value=FetchResult(
                html="<html>ok</html>", fetch_mode="http", content_type="text/html"
            )
        )
        analyzer_service.fetcher._is_low_quality_html = MagicMock(return_value=False)
        analyzer_service.fetcher.browser_fetcher.fetch = MagicMock()

        with (
            patch("src.services.analyzer.get_redis") as mock_get_redis,
            patch("src.services.analyzer.DomainChecker") as mock_domain_checker_class,
        ):
            mock_redis = AsyncMock()
            mock_get_redis.return_value = mock_redis

            mock_domain_checker = AsyncMock()
            mock_domain_checker.is_whitelisted.return_value = False
            mock_domain_checker.is_blacklisted.return_value = False
            mock_domain_checker_class.return_value = mock_domain_checker

            result = await analyzer_service.analyze(
                url=raw_input,
                request=mock_request,
                db_manager=mock_db_manager,
            )

            assert result.url == "https://legacy-site.com/login?a=1&b=2"
            mock_domain_checker.is_whitelisted.assert_awaited_once_with(raw_input)
            mock_domain_checker.is_blacklisted.assert_awaited_once_with(raw_input)
            mock_request.app.state.model.predict_from_html.assert_called_once_with(
                raw_input, "<html>ok</html>"
            )
            mock_db_manager.save_phishing_url.assert_called_once_with(
                "https://legacy-site.com/login?a=1&b=2",
                True,
                0.85,
                "<html>ok</html>",
            )
            mock_db_manager.cache_result.assert_called_once_with(
                url="https://legacy-site.com/login?a=1&b=2",
                is_phishing=True,
                confidence=0.85,
            )

    @pytest.mark.asyncio
    async def test_analyze_ai_model_failure(
        self, analyzer_service, mock_request, mock_db_manager
    ):
        """AI model prediction failure test"""
        # AI model prediction failure (HTML pipeline)
        mock_request.app.state.model.predict_from_html.return_value = {
            "result": None,
            "confidence": None,
        }
        analyzer_service.fetcher.http_fetcher.fetch = MagicMock(
            return_value=FetchResult(
                html="<html>ok</html>", fetch_mode="http", content_type="text/html"
            )
        )
        analyzer_service.fetcher._is_low_quality_html = MagicMock(return_value=False)
        analyzer_service.fetcher.browser_fetcher.fetch = MagicMock()

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
                url="https://error-site.com",
                request=mock_request,
                db_manager=mock_db_manager,
            )

            assert isinstance(result, PhishingDetectionResponse)
            assert result.result is False
            assert result.confidence == 0.0
            assert result.source == "error"

    @pytest.mark.asyncio
    async def test_reputation_malicious_blocks_download_url(
        self, analyzer_service, mock_request, mock_db_manager
    ):
        """A reputation-flagged URL is blocked before fetch/model, even for downloads."""
        analyzer_service.reputation_service.check = AsyncMock(
            return_value=ReputationResult(
                verdict="malicious",
                confidence=0.95,
                source="reputation:gsb",
                provider="gsb",
                reason_codes=["MALWARE"],
            )
        )
        analyzer_service.fetcher.http_fetcher.fetch = MagicMock()
        analyzer_service.fetcher.browser_fetcher.fetch = MagicMock()

        with (
            patch("src.services.analyzer.get_redis") as mock_get_redis,
            patch("src.services.analyzer.DomainChecker") as mock_domain_checker_class,
        ):
            mock_get_redis.return_value = AsyncMock()
            mock_domain_checker = AsyncMock()
            mock_domain_checker.is_whitelisted.return_value = False
            mock_domain_checker.is_blacklisted.return_value = False
            mock_domain_checker_class.return_value = mock_domain_checker

            result = await analyzer_service.analyze(
                url="https://evil.example.com/installer.exe",
                request=mock_request,
                db_manager=mock_db_manager,
            )

        assert result.result is True
        assert result.source == "reputation:gsb"
        assert result.reason_codes == ["MALWARE"]
        # Reputation runs before the analysis cache, fetch and model.
        mock_db_manager.get_cached_result.assert_not_called()
        analyzer_service.fetcher.http_fetcher.fetch.assert_not_called()
        analyzer_service.fetcher.browser_fetcher.fetch.assert_not_called()
        mock_request.app.state.model.predict_from_html.assert_not_called()

    @pytest.mark.asyncio
    async def test_reputation_failure_is_fail_open(
        self, analyzer_service, mock_request, mock_db_manager
    ):
        """If the reputation stage errors, analysis continues to the model."""
        analyzer_service.reputation_service.check = AsyncMock(
            side_effect=RuntimeError("provider down")
        )
        mock_request.app.state.model.predict_from_html.return_value = {
            "result": True,
            "confidence": 0.95,
            "preprocess_ms": 1.0,
            "infer_ms": 1.0,
        }
        analyzer_service.fetcher.http_fetcher.fetch = MagicMock(
            return_value=FetchResult(
                html="<html>ok</html>", fetch_mode="http", content_type="text/html"
            )
        )
        analyzer_service.fetcher._is_low_quality_html = MagicMock(return_value=False)
        analyzer_service.fetcher.browser_fetcher.fetch = MagicMock()

        with (
            patch("src.services.analyzer.get_redis") as mock_get_redis,
            patch("src.services.analyzer.DomainChecker") as mock_domain_checker_class,
        ):
            mock_get_redis.return_value = AsyncMock()
            mock_domain_checker = AsyncMock()
            mock_domain_checker.is_whitelisted.return_value = False
            mock_domain_checker.is_blacklisted.return_value = False
            mock_domain_checker_class.return_value = mock_domain_checker

            result = await analyzer_service.analyze(
                url="https://unknown-site.com",
                request=mock_request,
                db_manager=mock_db_manager,
            )

        assert result.source == "model"
        assert result.result is True

    @pytest.mark.asyncio
    async def test_reputation_clean_continues_to_model(
        self, analyzer_service, mock_request, mock_db_manager
    ):
        """A clean reputation verdict does not short-circuit; the model still runs."""
        analyzer_service.reputation_service.check = AsyncMock(
            return_value=ReputationResult(
                verdict="clean",
                confidence=0.0,
                source="reputation",
                provider="reputation",
            )
        )
        mock_request.app.state.model.predict_from_html.return_value = {
            "result": False,
            "confidence": 0.2,
            "preprocess_ms": 1.0,
            "infer_ms": 1.0,
        }
        analyzer_service.fetcher.http_fetcher.fetch = MagicMock(
            return_value=FetchResult(
                html="<html>ok</html>", fetch_mode="http", content_type="text/html"
            )
        )
        analyzer_service.fetcher._is_low_quality_html = MagicMock(return_value=False)
        analyzer_service.fetcher.browser_fetcher.fetch = MagicMock()

        with (
            patch("src.services.analyzer.get_redis") as mock_get_redis,
            patch("src.services.analyzer.DomainChecker") as mock_domain_checker_class,
        ):
            mock_get_redis.return_value = AsyncMock()
            mock_domain_checker = AsyncMock()
            mock_domain_checker.is_whitelisted.return_value = False
            mock_domain_checker.is_blacklisted.return_value = False
            mock_domain_checker_class.return_value = mock_domain_checker

            result = await analyzer_service.analyze(
                url="https://unknown-site.com",
                request=mock_request,
                db_manager=mock_db_manager,
            )

        assert result.source == "model"
        mock_request.app.state.model.predict_from_html.assert_called_once()

    @pytest.mark.asyncio
    async def test_blacklist_takes_precedence_over_non_html(
        self, analyzer_service, mock_request, mock_db_manager
    ):
        """Blacklisted domains stay phishing even for non-HTML download URLs.

        The non-HTML skip guards model input quality; it must not disable domain
        reputation. Blacklist is checked before any fetch, so the resource is
        never fetched.
        """
        analyzer_service.fetcher.http_fetcher.fetch = MagicMock()
        analyzer_service.fetcher.browser_fetcher.fetch = MagicMock()

        with (
            patch("src.services.analyzer.get_redis") as mock_get_redis,
            patch("src.services.analyzer.DomainChecker") as mock_domain_checker_class,
        ):
            mock_redis = AsyncMock()
            mock_get_redis.return_value = mock_redis

            mock_domain_checker = AsyncMock()
            mock_domain_checker.is_whitelisted.return_value = False
            mock_domain_checker.is_blacklisted.return_value = True
            mock_domain_checker_class.return_value = mock_domain_checker

            result = await analyzer_service.analyze(
                url="https://malicious-host.com/payload.pdf",
                request=mock_request,
                db_manager=mock_db_manager,
            )

        assert result.result is True
        assert result.source == "blacklist"
        # Blacklist short-circuits before fetch; non-HTML skip never runs.
        analyzer_service.fetcher.http_fetcher.fetch.assert_not_called()
        analyzer_service.fetcher.browser_fetcher.fetch.assert_not_called()

    @pytest.mark.asyncio
    async def test_analyze_skips_non_html_resource(
        self, analyzer_service, mock_request, mock_db_manager
    ):
        """Non-HTML resources (SVG/PDF/...) must not run the model or browser fallback."""
        # http fetch returns a non-HTML resource (e.g. GitHub camo SVG badge)
        analyzer_service.fetcher.http_fetcher.fetch = MagicMock(
            return_value=FetchResult(
                html="", fetch_mode="http", content_type="image/svg+xml"
            )
        )
        analyzer_service.fetcher.browser_fetcher.fetch = MagicMock()

        with (
            patch("src.services.analyzer.get_redis") as mock_get_redis,
            patch("src.services.analyzer.DomainChecker") as mock_domain_checker_class,
            patch("src.services.analyzer.log_perf_record"),
        ):
            mock_redis = AsyncMock()
            mock_get_redis.return_value = mock_redis

            mock_domain_checker = AsyncMock()
            mock_domain_checker.is_whitelisted.return_value = False
            mock_domain_checker.is_blacklisted.return_value = False
            mock_domain_checker_class.return_value = mock_domain_checker

            result = await analyzer_service.analyze(
                url="https://camo.githubusercontent.com/abc/badge.svg",
                request=mock_request,
                db_manager=mock_db_manager,
            )

        assert isinstance(result, PhishingDetectionResponse)
        assert result.result is False
        assert result.confidence == 0.0
        assert result.source == "non_html"

        # No browser escalation, no model inference, no persistence/cache.
        analyzer_service.fetcher.browser_fetcher.fetch.assert_not_called()
        mock_request.app.state.model.predict_from_html.assert_not_called()
        mock_db_manager.save_phishing_url.assert_not_called()
        mock_db_manager.cache_result.assert_not_called()

    @pytest.mark.asyncio
    async def test_analyze_predict_from_html_path(
        self, analyzer_service, mock_request, mock_db_manager
    ):
        """Optimized HTML pipeline analysis test"""
        raw_input = "www.optimized-path.com/login?b=2&a=1"

        class OptimizedDetector:
            def __init__(self):
                self.calls: list[tuple[str, str]] = []

            def predict_from_html(self, url: str, html: str) -> dict:
                self.calls.append((url, html))
                return {
                    "result": True,
                    "confidence": 0.91,
                    "preprocess_ms": 12.5,
                    "infer_ms": 8.2,
                }

        detector = OptimizedDetector()
        mock_request.app.state.model = detector

        analyzer_service.fetcher.http_fetcher.fetch = MagicMock(
            return_value=FetchResult(
                html="<html>ok</html>", fetch_mode="http", content_type="text/html"
            )
        )
        analyzer_service.fetcher._is_low_quality_html = MagicMock(return_value=False)
        analyzer_service.fetcher.browser_fetcher.fetch = MagicMock()

        with (
            patch("src.services.analyzer.settings.ENABLE_PERF_RECORDS", True),
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
                url=raw_input,
                request=mock_request,
                db_manager=mock_db_manager,
            )

            assert isinstance(result, PhishingDetectionResponse)
            assert result.url == "https://optimized-path.com/login?a=1&b=2"
            assert result.result is True
            assert result.confidence == 0.91
            assert result.source == "model"
            assert result.fetch_mode == "http"

            mock_domain_checker.is_whitelisted.assert_awaited_once_with(raw_input)
            mock_domain_checker.is_blacklisted.assert_awaited_once_with(raw_input)
            analyzer_service.fetcher.http_fetcher.fetch.assert_called_once_with(
                raw_input
            )
            analyzer_service.fetcher.browser_fetcher.fetch.assert_not_called()
            assert detector.calls == [(raw_input, "<html>ok</html>")]
            mock_db_manager.save_phishing_url.assert_called_once_with(
                "https://optimized-path.com/login?a=1&b=2",
                True,
                0.91,
                "<html>ok</html>",
            )
            mock_db_manager.cache_result.assert_called_once_with(
                url="https://optimized-path.com/login?a=1&b=2",
                is_phishing=True,
                confidence=0.91,
            )

            perf_record = mock_log_perf_record.call_args.args[0]
            assert perf_record["url"] == "https://optimized-path.com/login?a=1&b=2"
            assert perf_record["fetch_mode"] == "http"
            assert perf_record["stages"]["preprocess"] == 12.5
            assert perf_record["stages"]["inference"] == 8.2

    @pytest.mark.asyncio
    async def test_navigation_model_warn_threshold(
        self, analyzer_service, mock_request, mock_db_manager
    ):
        """Navigation: model confidence between WARN and BLOCK -> warn (not block)."""
        mock_request.app.state.model.predict_from_html.return_value = {
            "result": True,
            "confidence": 0.75,
            "preprocess_ms": 1.0,
            "infer_ms": 1.0,
        }
        analyzer_service.fetcher.http_fetcher.fetch = MagicMock(
            return_value=FetchResult(
                html="<html>ok</html>", fetch_mode="http", content_type="text/html"
            )
        )
        analyzer_service.fetcher._is_low_quality_html = MagicMock(return_value=False)
        analyzer_service.fetcher.browser_fetcher.fetch = MagicMock()

        with (
            patch("src.services.analyzer.get_redis") as mock_get_redis,
            patch("src.services.analyzer.DomainChecker") as mock_domain_checker_class,
        ):
            mock_get_redis.return_value = AsyncMock()
            mock_domain_checker = AsyncMock()
            mock_domain_checker.is_whitelisted.return_value = False
            mock_domain_checker.is_blacklisted.return_value = False
            mock_domain_checker_class.return_value = mock_domain_checker

            result = await analyzer_service.analyze(
                url="https://unknown-site.com/page",
                request=mock_request,
                db_manager=mock_db_manager,
            )

        assert result.source == "model"
        assert result.severity == "warn"
        assert result.result is False

    @pytest.mark.asyncio
    async def test_link_context_does_not_block_on_model(
        self, analyzer_service, mock_request, mock_db_manager
    ):
        """A link is never hard-blocked by the model/cache (warn at most)."""
        mock_db_manager.get_cached_result.return_value = {
            "is_phishing": True,
            "confidence": 0.99,
        }

        with (
            patch("src.services.analyzer.get_redis") as mock_get_redis,
            patch("src.services.analyzer.DomainChecker") as mock_domain_checker_class,
        ):
            mock_get_redis.return_value = AsyncMock()
            mock_domain_checker = AsyncMock()
            mock_domain_checker.is_whitelisted.return_value = False
            mock_domain_checker.is_blacklisted.return_value = False
            mock_domain_checker_class.return_value = mock_domain_checker

            result = await analyzer_service.analyze(
                url="https://unknown-site.com/link",
                request=mock_request,
                db_manager=mock_db_manager,
                context="link",
            )

        assert result.source == "cache"
        assert result.severity == "warn"
        assert result.result is False
        mock_request.app.state.model.predict_from_html.assert_not_called()

    @pytest.mark.asyncio
    async def test_link_context_cache_miss_returns_pending(
        self, analyzer_service, mock_request, mock_db_manager
    ):
        """Link cache-miss returns pending without fetch/model (bg off by default)."""
        mock_db_manager.get_cached_result.return_value = None
        analyzer_service.fetcher.http_fetcher.fetch = MagicMock()

        with (
            patch("src.services.analyzer.get_redis") as mock_get_redis,
            patch("src.services.analyzer.DomainChecker") as mock_domain_checker_class,
        ):
            mock_get_redis.return_value = AsyncMock()
            mock_domain_checker = AsyncMock()
            mock_domain_checker.is_whitelisted.return_value = False
            mock_domain_checker.is_blacklisted.return_value = False
            mock_domain_checker_class.return_value = mock_domain_checker

            result = await analyzer_service.analyze(
                url="https://unknown-site.com/link",
                request=mock_request,
                db_manager=mock_db_manager,
                context="link",
            )

        assert result.status == "pending"
        assert result.source == "pending"
        assert result.severity == "allow"
        assert result.result is False
        mock_request.app.state.model.predict_from_html.assert_not_called()
        analyzer_service.fetcher.http_fetcher.fetch.assert_not_called()

    @pytest.mark.asyncio
    async def test_ssrf_blocked_returns_blocked_private(
        self, analyzer_service, mock_request, mock_db_manager
    ):
        """An SSRF-blocked fetch is reported as a distinct, observable source."""
        mock_db_manager.get_cached_result.return_value = None
        analyzer_service.fetcher.http_fetcher.fetch = MagicMock(
            side_effect=SSRFBlockedError("blocked")
        )
        analyzer_service.fetcher.browser_fetcher.fetch = MagicMock()

        with (
            patch("src.services.analyzer.get_redis") as mock_get_redis,
            patch("src.services.analyzer.DomainChecker") as mock_domain_checker_class,
        ):
            mock_get_redis.return_value = AsyncMock()
            mock_domain_checker = AsyncMock()
            mock_domain_checker.is_whitelisted.return_value = False
            mock_domain_checker.is_blacklisted.return_value = False
            mock_domain_checker_class.return_value = mock_domain_checker

            result = await analyzer_service.analyze(
                url="http://169.254.169.254/latest/meta-data/",
                request=mock_request,
                db_manager=mock_db_manager,
            )

        assert result.source == "blocked_private"
        assert result.result is False
        assert result.severity == "allow"
        mock_request.app.state.model.predict_from_html.assert_not_called()

    @pytest.mark.asyncio
    async def test_background_schedule_dedups_by_key(self, analyzer_service):
        """Duplicate link schedules for the same URL spawn only one task."""
        analyzer_service._bg_tasks.clear()
        analyzer_service._bg_inflight_keys.clear()
        analyzer_service._background_model = MagicMock(return_value=asyncio.sleep(0.02))

        with patch.object(analyzer_mod.settings, "LINK_BACKGROUND_MODEL", True):
            analyzer_service._maybe_schedule_background(
                MagicMock(), MagicMock(), "https://x.com/p", "https://x.com/p"
            )
            analyzer_service._maybe_schedule_background(
                MagicMock(), MagicMock(), "https://x.com/p", "https://x.com/p"
            )

        assert len(analyzer_service._bg_tasks) == 1
        assert "https://x.com/p" in analyzer_service._bg_inflight_keys
        analyzer_service._background_model.assert_called_once()

        await asyncio.gather(*list(analyzer_service._bg_tasks), return_exceptions=True)
        assert analyzer_service._bg_inflight_keys == set()

    @pytest.mark.asyncio
    async def test_close_cancels_background_tasks(self, analyzer_service):
        """close() cancels in-flight background tasks and clears tracking state."""
        analyzer_service._bg_tasks.clear()
        analyzer_service._bg_inflight_keys.clear()

        async def _never():
            await asyncio.Event().wait()

        task = asyncio.create_task(_never())
        analyzer_service._bg_tasks.add(task)
        analyzer_service._bg_inflight_keys.add("https://x.com/p")

        analyzer_service.close()

        assert analyzer_service._bg_tasks == set()
        assert analyzer_service._bg_inflight_keys == set()
        await asyncio.gather(task, return_exceptions=True)
        assert task.cancelled()

    @pytest.mark.asyncio
    async def test_inflight_dedup_waiter_does_not_block_other_keys(
        self, analyzer_service
    ):
        """Waiting on an existing in-flight task should not hold the shared lock"""
        first_started = asyncio.Event()
        release_first = asyncio.Event()

        async def first_work() -> PhishingDetectionResponse:
            first_started.set()
            await release_first.wait()
            return PhishingDetectionResponse(
                url="https://first.test/",
                result=False,
                confidence=0.2,
                source="model",
                fetch_mode="none",
            )

        async def duplicate_work() -> PhishingDetectionResponse:
            raise AssertionError("duplicate work should not run")

        async def other_work() -> PhishingDetectionResponse:
            return PhishingDetectionResponse(
                url="https://other.test/",
                result=True,
                confidence=0.7,
                source="model",
                fetch_mode="none",
            )

        first_task = asyncio.create_task(
            analyzer_service._run_inflight_deduplicated("same-key", first_work)
        )
        await first_started.wait()

        duplicate_task = asyncio.create_task(
            analyzer_service._run_inflight_deduplicated("same-key", duplicate_work)
        )

        other_result = await asyncio.wait_for(
            analyzer_service._run_inflight_deduplicated("other-key", other_work),
            timeout=0.2,
        )
        assert other_result.url == "https://other.test/"

        release_first.set()
        first_result = await first_task
        duplicate_result = await duplicate_task

        assert first_result.url == "https://first.test/"
        assert duplicate_result.url == "https://first.test/"

    @pytest.mark.asyncio
    async def test_inflight_dedup_survives_waiter_cancellation(self, analyzer_service):
        """Cancelling one waiter should not cancel the shared in-flight task"""
        started = asyncio.Event()
        release = asyncio.Event()

        async def shared_work() -> PhishingDetectionResponse:
            started.set()
            await release.wait()
            return PhishingDetectionResponse(
                url="https://shared.test/",
                result=True,
                confidence=0.8,
                source="model",
                fetch_mode="none",
            )

        first_waiter = asyncio.create_task(
            analyzer_service._run_inflight_deduplicated("shared-key", shared_work)
        )
        await started.wait()

        second_waiter = asyncio.create_task(
            analyzer_service._run_inflight_deduplicated("shared-key", shared_work)
        )

        first_waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first_waiter

        release.set()
        second_result = await asyncio.wait_for(second_waiter, timeout=0.2)
        assert second_result.url == "https://shared.test/"

    @pytest.mark.asyncio
    async def test_perf_recording_can_be_disabled(
        self, analyzer_service, mock_request, mock_db_manager
    ):
        """Perf record creation should be skipped when the flag is disabled"""
        mock_db_manager.get_cached_result.return_value = {
            "is_phishing": True,
            "confidence": 0.75,
        }

        with (
            patch("src.services.analyzer.settings.ENABLE_PERF_RECORDS", False),
            patch("src.services.analyzer.get_redis") as mock_get_redis,
            patch("src.services.analyzer.DomainChecker") as mock_domain_checker_class,
            patch("src.services.analyzer.build_perf_record") as mock_build_perf_record,
            patch("src.services.analyzer.log_perf_record") as mock_log_perf_record,
        ):
            mock_redis = AsyncMock()
            mock_get_redis.return_value = mock_redis

            mock_domain_checker = AsyncMock()
            mock_domain_checker.is_whitelisted.return_value = False
            mock_domain_checker.is_blacklisted.return_value = False
            mock_domain_checker_class.return_value = mock_domain_checker

            result = await analyzer_service.analyze(
                url="https://cached-site.com",
                request=mock_request,
                db_manager=mock_db_manager,
            )

            assert result.source == "cache"
            mock_build_perf_record.assert_not_called()
            mock_log_perf_record.assert_not_called()
