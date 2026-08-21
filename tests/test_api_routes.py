# --------------------------------------------------------------------------
# API routes test module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
from unittest.mock import MagicMock, patch, AsyncMock

from fastapi import HTTPException

from src.server import app
from src.schemas.analyze import PhishingDetectionResponse
from src.services.analyzer import AnalyzerService
from src.services.fetchers.http_fetcher import FetchResult


class TestHealthEndpoint:
    """Health check endpoint test"""

    def test_health_check_success(self, client):
        """Normal status health check test"""
        # Set model and db_manager attributes in app.state
        app.state.model = MagicMock()
        app.state.db_manager = MagicMock()

        try:
            response = client.get("/health")

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "ready"
            assert data["model"] == "loaded"
            assert data["db"] == "fetched"
        finally:
            # Clean up after test
            if hasattr(app.state, "model"):
                delattr(app.state, "model")
            if hasattr(app.state, "db_manager"):
                delattr(app.state, "db_manager")


class TestAnalyzeEndpoints:
    """Analyze endpoint test"""

    def test_get_perf_records(self, client):
        """Performance record lookup test"""
        records = [
            {
                "url": "https://example.com",
                "source": "model",
                "total_ms": 12.3,
            }
        ]

        with (
            patch("src.api.routes.analyze.settings.ENABLE_PERF_RECORDS", True),
            patch(
                "src.api.routes.analyze.perf_store.list",
                new=AsyncMock(return_value=records),
            ),
        ):
            response = client.get("/analyze/perf/records")

        assert response.status_code == 200
        data = response.json()
        assert data["count"] == 1
        assert data["data"] == records

    def test_clear_perf_records(self, client):
        """Performance record clear test"""
        with (
            patch("src.api.routes.analyze.settings.ENABLE_PERF_RECORDS", True),
            patch(
                "src.api.routes.analyze.perf_store.clear",
                new=AsyncMock(return_value=None),
            ),
        ):
            response = client.delete("/analyze/perf/records")

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "cleared"

    def test_perf_records_forbidden_in_production(self, client):
        """Performance record endpoint should be blocked in production"""
        with patch("src.api.routes.analyze.settings.ENABLE_PERF_RECORDS", False):
            response = client.get("/analyze/perf/records")

        assert response.status_code == 403
        assert response.json()["detail"] == "Performance records unavailable"

    def test_get_recent_phishing(self, client, mock_db_manager):
        """Recent phishing URL lookup test"""
        # Mock phishing URL object
        mock_phishing_url = MagicMock()
        mock_phishing_url.url = "https://phishing-site.com"
        mock_phishing_url.is_phishing = True
        mock_phishing_url.confidence = 0.85
        mock_phishing_url.detection_time = MagicMock()
        mock_phishing_url.detection_time.isoformat.return_value = "2024-01-01T00:00:00"

        mock_db_manager.get_phishing_urls.return_value = [mock_phishing_url]

        with patch("src.api.deps.DBManager", return_value=mock_db_manager):
            response = client.get("/analyze/recent?limit=10&offset=0")

            assert response.status_code == 200
            data = response.json()
            assert data["message"] == "SUCCESS"
            assert "data" in data

    def test_check_single_url(self, client, mock_db_manager):
        """Single URL analysis test"""
        with (
            patch("src.api.routes.analyze.AnalyzerService") as mock_analyzer_class,
            patch("src.api.deps.DBManager", return_value=mock_db_manager),
        ):
            # AnalyzerService mocking
            mock_analyzer = AsyncMock()
            mock_analyzer.analyze.return_value = PhishingDetectionResponse(
                result=True, confidence=0.85, source="model"
            )
            mock_analyzer_class.return_value = mock_analyzer

            response = client.post(
                "/analyze/check", json={"url": "https://suspicious-site.com"}
            )

            assert response.status_code == 200
            data = response.json()
            assert data["message"] == "SUCCESS"
            assert data["data"]["result"] is True
            assert data["data"]["confidence"] == 0.85
            assert data["data"]["source"] == "model"

    def test_check_single_url_analyzer_failure_returns_error_payload(
        self, client, mock_db_manager
    ):
        """An analyzer crash must not become a 500; it becomes source='error'."""
        with (
            patch("src.api.routes.analyze.AnalyzerService") as mock_analyzer_class,
            patch("src.api.deps.DBManager", return_value=mock_db_manager),
        ):
            mock_analyzer = AsyncMock()
            mock_analyzer.analyze.side_effect = RuntimeError("browser startup failed")
            mock_analyzer_class.return_value = mock_analyzer

            response = client.post(
                "/analyze/check", json={"url": "https://boom-site.com"}
            )

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "SUCCESS"
        assert data["data"]["url"] == "https://boom-site.com"
        assert data["data"]["result"] is False
        assert data["data"]["confidence"] == 0.0
        assert data["data"]["source"] == "error"
        assert data["data"]["fetch_mode"] == "none"
        assert data["data"]["severity"] == "allow"
        assert data["data"]["status"] == "final"

    def test_check_single_url_propagates_http_exception(self, client, mock_db_manager):
        """A deliberate HTTPException keeps its own status code."""
        with (
            patch("src.api.routes.analyze.AnalyzerService") as mock_analyzer_class,
            patch("src.api.deps.DBManager", return_value=mock_db_manager),
        ):
            mock_analyzer = AsyncMock()
            mock_analyzer.analyze.side_effect = HTTPException(
                status_code=503, detail="Analyzer unavailable"
            )
            mock_analyzer_class.return_value = mock_analyzer

            response = client.post(
                "/analyze/check", json={"url": "https://unavailable-site.com"}
            )

        assert response.status_code == 503
        assert response.json()["detail"] == "Analyzer unavailable"

    def test_check_single_url_keeps_block_when_persist_fails(
        self, client, mock_db_manager
    ):
        """End-to-end: a persist failure must not flip a block into source='error'.

        The /check catch-all turns any escaping exception into an allow verdict, so
        a Redis/Postgres hiccup right after the model blocked a page would be a
        fail-open if persistence were not handled inside the analyzer.
        """
        mock_db_manager.cache_result = AsyncMock(side_effect=RuntimeError("redis down"))

        app.state.model = MagicMock()
        app.state.model.predict_from_html.return_value = {
            "result": True,
            "confidence": 0.95,
            "preprocess_ms": 1.0,
            "infer_ms": 1.0,
        }

        with (
            patch("src.services.fetchers.browser_fetcher.HTMLLoader"),
            patch("src.api.deps.DBManager", return_value=mock_db_manager),
            patch("src.services.analyzer.get_redis", new=AsyncMock()),
            patch("src.services.analyzer.DomainChecker") as mock_domain_checker_class,
            patch("src.services.analyzer.settings.MODEL_BLOCK_THRESHOLD", 0.90),
        ):
            mock_domain_checker = AsyncMock()
            mock_domain_checker.is_whitelisted.return_value = False
            mock_domain_checker.is_blacklisted.return_value = False
            mock_domain_checker_class.return_value = mock_domain_checker

            analyzer = AnalyzerService()
            analyzer.reputation_service.check = AsyncMock(return_value=None)
            analyzer.fetcher.http_fetcher.fetch = MagicMock(
                return_value=FetchResult(
                    html="<html>ok</html>", fetch_mode="http", content_type="text/html"
                )
            )
            analyzer.fetcher._is_low_quality_html = MagicMock(return_value=False)
            app.state.analyzer_service = analyzer

            try:
                response = client.post(
                    "/analyze/check", json={"url": "https://persist-fail.test/login"}
                )
            finally:
                analyzer.close()
                delattr(app.state, "analyzer_service")
                delattr(app.state, "model")

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["source"] == "model"
        assert data["severity"] == "block"
        assert data["result"] is True
        assert data["confidence"] == 0.95

    def test_check_single_url_rejects_blank_url(self, client, mock_db_manager):
        """Blank URL input should fail validation"""
        with patch("src.api.deps.DBManager", return_value=mock_db_manager):
            response = client.post("/analyze/check", json={"url": "   "})

        assert response.status_code == 422

    def test_check_batch_urls_rejects_blank_item(self, client, mock_db_manager):
        """Blank batch item should fail validation"""
        with patch("src.api.deps.DBManager", return_value=mock_db_manager):
            response = client.post(
                "/analyze/batch",
                json=["https://ok.com", "   ", "https://still-ok.com"],
            )

        assert response.status_code == 422

    def test_check_batch_urls(self, client, mock_db_manager):
        """Batch URL analysis test"""
        with (
            patch("src.api.routes.analyze.AnalyzerService") as mock_analyzer_class,
            patch("src.api.deps.DBManager", return_value=mock_db_manager),
        ):
            # AnalyzerService mocking
            mock_analyzer = AsyncMock()
            mock_analyzer.analyze.side_effect = [
                PhishingDetectionResponse(result=True, confidence=0.85, source="model"),
                PhishingDetectionResponse(
                    result=False, confidence=0.15, source="whitelist"
                ),
                PhishingDetectionResponse(
                    result=True, confidence=0.95, source="blacklist"
                ),
            ]
            mock_analyzer_class.return_value = mock_analyzer

            test_urls = [
                "https://suspicious-site.com",
                "https://google.com",
                "https://known-phishing.com",
            ]

            response = client.post("/analyze/batch", json=test_urls)

            assert response.status_code == 200
            data = response.json()
            assert data["message"] == "SUCCESS"
            assert len(data["data"]) == 3

            # Validate first result
            assert data["data"][0]["result"] is True
            assert data["data"][0]["confidence"] == 0.85
            assert data["data"][0]["source"] == "model"

            # Validate second result (whitelist)
            assert data["data"][1]["result"] is False
            assert data["data"][1]["confidence"] == 0.15
            assert data["data"][1]["source"] == "whitelist"

            # Validate third result (blacklist)
            assert data["data"][2]["result"] is True
            assert data["data"][2]["confidence"] == 0.95
            assert data["data"][2]["source"] == "blacklist"

    def test_batch_uses_link_context(self, client, mock_db_manager):
        """The batch endpoint must analyze every URL with context='link'."""
        with (
            patch("src.api.routes.analyze.AnalyzerService") as mock_analyzer_class,
            patch("src.api.deps.DBManager", return_value=mock_db_manager),
        ):
            mock_analyzer = AsyncMock()
            mock_analyzer.analyze.return_value = PhishingDetectionResponse(
                result=False, confidence=0.0, source="pending", status="pending"
            )
            mock_analyzer_class.return_value = mock_analyzer

            response = client.post(
                "/analyze/batch", json=["https://a.com", "https://b.com"]
            )

        assert response.status_code == 200
        assert mock_analyzer.analyze.call_args_list  # was called
        for call in mock_analyzer.analyze.call_args_list:
            assert call.kwargs["context"] == "link"

    def test_batch_caps_and_marks_trimmed_pending(self, client, mock_db_manager):
        """URLs beyond MAX_BATCH_URLS are returned as pending/skipped, not safe."""
        with (
            patch("src.api.routes.analyze.AnalyzerService") as mock_analyzer_class,
            patch("src.api.deps.DBManager", return_value=mock_db_manager),
            patch("src.api.routes.analyze.settings.MAX_BATCH_URLS", 2),
        ):
            mock_analyzer = AsyncMock()
            mock_analyzer.analyze.return_value = PhishingDetectionResponse(
                result=False, confidence=0.0, source="pending", status="pending"
            )
            mock_analyzer_class.return_value = mock_analyzer

            response = client.post(
                "/analyze/batch",
                json=["https://a.com", "https://b.com", "https://c.com"],
            )

        assert response.status_code == 200
        data = response.json()["data"]
        assert len(data) == 3
        # Only the first 2 were actually analyzed.
        assert mock_analyzer.analyze.await_count == 2
        # The trimmed 3rd is marked not-analyzed, not "final safe".
        assert data[2]["source"] == "skipped"
        assert data[2]["status"] == "pending"
        assert data[2]["result"] is False

    def test_batch_cap_is_positional_for_duplicate_urls(self, client, mock_db_manager):
        """A duplicate sitting past the cap gets the pending placeholder, not the
        analyzed result of its in-cap twin."""
        with (
            patch("src.api.routes.analyze.AnalyzerService") as mock_analyzer_class,
            patch("src.api.deps.DBManager", return_value=mock_db_manager),
            patch("src.api.routes.analyze.settings.MAX_BATCH_URLS", 2),
        ):
            mock_analyzer = AsyncMock()
            mock_analyzer.analyze.return_value = PhishingDetectionResponse(
                result=True, confidence=0.9, source="model", status="final"
            )
            mock_analyzer_class.return_value = mock_analyzer

            response = client.post(
                "/analyze/batch",
                json=["https://a.com", "https://b.com", "https://a.com"],
            )

        assert response.status_code == 200
        data = response.json()["data"]
        assert len(data) == 3
        # Only the 2 in-cap positions were analyzed.
        assert mock_analyzer.analyze.await_count == 2
        assert data[0]["source"] == "model"
        assert data[1]["source"] == "model"
        # The 3rd position is past the cap even though the URL repeats a.com.
        assert data[2]["source"] == "skipped"
        assert data[2]["status"] == "pending"
        assert data[2]["result"] is False
        assert data[2]["confidence"] == 0.0

    def test_batch_deduplicates_within_cap(self, client, mock_db_manager):
        """In-cap duplicates are analyzed once and share the same result."""
        with (
            patch("src.api.routes.analyze.AnalyzerService") as mock_analyzer_class,
            patch("src.api.deps.DBManager", return_value=mock_db_manager),
        ):
            mock_analyzer = AsyncMock()
            mock_analyzer.analyze.side_effect = [
                PhishingDetectionResponse(
                    url="https://dup.com", result=True, confidence=0.85, source="model"
                ),
                PhishingDetectionResponse(
                    url="https://other.com",
                    result=False,
                    confidence=0.15,
                    source="whitelist",
                ),
            ]
            mock_analyzer_class.return_value = mock_analyzer

            response = client.post(
                "/analyze/batch",
                json=["https://dup.com", "https://other.com", "https://dup.com"],
            )

        assert response.status_code == 200
        data = response.json()["data"]
        assert len(data) == 3
        # The repeated URL was analyzed only once.
        assert mock_analyzer.analyze.await_count == 2
        assert data[0] == data[2]
        assert data[0]["source"] == "model"
        assert data[1]["source"] == "whitelist"

    def test_check_batch_urls_with_error(self, client, mock_db_manager):
        """Batch URL analysis with error test"""
        with (
            patch("src.api.routes.analyze.AnalyzerService") as mock_analyzer_class,
            patch("src.api.deps.DBManager", return_value=mock_db_manager),
        ):
            # AnalyzerService mocking (error occurs in second URL)
            mock_analyzer = AsyncMock()
            mock_analyzer.analyze.side_effect = [
                PhishingDetectionResponse(result=True, confidence=0.85, source="model"),
                Exception("Analysis failed"),
                PhishingDetectionResponse(
                    result=False, confidence=0.15, source="whitelist"
                ),
            ]
            mock_analyzer_class.return_value = mock_analyzer

            test_urls = [
                "https://suspicious-site.com",
                "https://error-site.com",
                "https://google.com",
            ]

            response = client.post("/analyze/batch", json=test_urls)

            assert response.status_code == 200
            data = response.json()
            assert data["message"] == "SUCCESS"
            assert len(data["data"]) == 3

            # Validate first result
            assert data["data"][0]["result"] is True
            assert data["data"][0]["confidence"] == 0.85

            # Validate second result (error handling)
            assert data["data"][1]["result"] is False
            assert data["data"][1]["confidence"] == 0.0
            assert data["data"][1]["source"] == "error"

            # Validate third result
            assert data["data"][2]["result"] is False
            assert data["data"][2]["confidence"] == 0.15
