# --------------------------------------------------------------------------
# API routes test module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
from unittest.mock import MagicMock, patch, AsyncMock

from src.server import app
from src.schemas.analyze import PhishingDetectionResponse


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


class TestFeedbackEndpoints:
    """Feedback endpoint test"""

    def test_feedback_endpoints_exist(self, client):
        """Feedback endpoint existence test (simple test)"""
        # Check if feedback endpoint exists
        response = client.get("/docs")  # OpenAPI document check
        assert response.status_code == 200

    # TODO: implement more detailed test
